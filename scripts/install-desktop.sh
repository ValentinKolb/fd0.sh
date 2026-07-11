#!/bin/sh
# fd0 Desktop installer for signed macOS bundles and Linux AppImages.

set -eu

REPO="ValentinKolb/fd0.sh"
RELEASE_BASE="${FD0_RELEASE_BASE:-https://github.com/${REPO}/releases}"
API_BASE="${FD0_API_BASE:-https://api.github.com/repos/${REPO}}"
VERSION="${FD0_DESKTOP_VERSION:-latest}"
SYSTEM="${FD0_DESKTOP_SYSTEM:-0}"
VERIFY="${FD0_DESKTOP_VERIFY:-1}"
ASSUME_YES="${FD0_DESKTOP_ASSUME_YES:-0}"
UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --system)       SYSTEM=1; shift ;;
        --version=*)    VERSION="${1#--version=}"; shift ;;
        --no-verify)    VERIFY=0; shift ;;
        --uninstall)    UNINSTALL=1; shift ;;
        -y|--yes)       ASSUME_YES=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: install-desktop.sh [options]

Installs or upgrades fd0 Desktop.

  --system            install for every user (macOS: /Applications, Linux: /usr/local/bin)
  --version=TAG       install a desktop-vX.Y.Z release (default: latest desktop release)
  --no-verify         skip Cosign verification; SHA-256 is still required
  --uninstall         remove the app and desktop-managed CLI wrappers; keep vault data
  -y, --yes           do not prompt
  -h, --help          show this help
EOF
            exit 0 ;;
        *) printf 'unknown flag: %s\n' "$1" >&2; exit 2 ;;
    esac
done

die() { printf 'fd0 Desktop: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

install_executable() {
    src=$1
    dst=$2
    dir=$(dirname "$dst")
    staged="$dir/.fd0.$(basename "$dst").installing.$$"
    if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
        sudo install -d -m 0755 "$dir"
        sudo install -m 0755 "$src" "$staged"
        sudo mv -f "$staged" "$dst"
    else
        install -d -m 0755 "$dir"
        install -m 0755 "$src" "$staged"
        mv -f "$staged" "$dst"
    fi
}

remove_path() {
    path=$1
    if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
        sudo rm -rf "$path"
    else
        rm -rf "$path"
    fi
}

remove_managed_wrapper() {
    path=$1
    if [ -f "$path" ] && grep -q '^# fd0-desktop-managed-v1$' "$path"; then
        remove_path "$path"
    fi
}

shell_quote() {
    printf "'"
    printf '%s' "$1" | sed "s/'/'\\\\''/g"
    printf "'"
}

confirm() {
    [ "$ASSUME_YES" = "1" ] && return 0
    printf '%s [Y/n] ' "$1"
    if [ -r /dev/tty ]; then
        IFS= read -r reply < /dev/tty || reply=""
    else
        die "not a terminal; pass --yes to confirm non-interactively"
    fi
    case "$reply" in
        ''|y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
    darwin) ASSET_OS="mac" ;;
    linux)  ASSET_OS="linux" ;;
    *) die "unsupported OS: $OS" ;;
esac
case "$ARCH" in
    x86_64|amd64)  ASSET_ARCH="x64" ;;
    aarch64|arm64) ASSET_ARCH="arm64" ;;
    *) die "unsupported architecture: $ARCH" ;;
esac

if [ "$OS" = "darwin" ]; then
    TARGET=$([ "$SYSTEM" = "1" ] && printf '/Applications/fd0.app' || printf '%s/Applications/fd0.app' "$HOME")
else
    TARGET=$([ "$SYSTEM" = "1" ] && printf '/usr/local/bin/fd0-desktop' || printf '%s/.local/bin/fd0-desktop' "$HOME")
fi
CLI_DIR=$([ "$SYSTEM" = "1" ] && printf '/usr/local/bin' || printf '%s/.local/bin' "$HOME")

if [ "$UNINSTALL" = "1" ]; then
    confirm "uninstall fd0 Desktop and its managed CLI? Vault data will be kept." || { printf 'aborted.\n'; exit 1; }
    if [ -f "$CLI_DIR/fd0" ] && grep -q '^# fd0-desktop-managed-v1$' "$CLI_DIR/fd0"; then
        "$CLI_DIR/fd0" agent stop >/dev/null 2>&1 || true
    fi
    remove_managed_wrapper "$CLI_DIR/fd0"
    remove_managed_wrapper "$CLI_DIR/fd0-agent"
    remove_path "$TARGET"
    if [ "$OS" = "linux" ] && [ "$SYSTEM" != "1" ]; then
        remove_path "$HOME/.local/share/applications/sh.fd0.desktop.desktop"
    fi
    printf '✓ fd0 Desktop removed; %s was not changed\n' "${FD0_HOME:-$HOME/.fd0}"
    exit 0
fi

have curl || die "curl is required"
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -fsSL "${API_BASE}/releases?per_page=30" \
        | sed -n 's/.*"tag_name": *"\(desktop-v[^"]*\)".*/\1/p' \
        | head -n1)
    [ -n "$VERSION" ] || die "no desktop release found"
fi
case "$VERSION" in
    desktop-v*) ;;
    v[0-9]*|[0-9]*) VERSION="desktop-v${VERSION#v}" ;;
    *) die "invalid desktop release tag: $VERSION" ;;
esac
printf '%s\n' "$VERSION" | grep -Eq '^desktop-v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' \
    || die "invalid desktop release tag: $VERSION"
VERSION_NUM=${VERSION#desktop-v}

if [ "$OS" = "darwin" ]; then
    ASSET="fd0-desktop_${VERSION_NUM}_${ASSET_OS}_${ASSET_ARCH}.dmg"
else
    ASSET="fd0-desktop_${VERSION_NUM}_${ASSET_OS}_${ASSET_ARCH}.AppImage"
fi

printf '\nfd0 Desktop installer\n'
printf '  release: %s\n' "$VERSION"
printf '  target:  %s\n' "$TARGET"
printf '  asset:   %s\n\n' "$ASSET"
confirm "install fd0 Desktop?" || { printf 'aborted.\n'; exit 1; }

TMP=$(mktemp -d)
MOUNT=""
cleanup() {
    if [ -n "$MOUNT" ]; then hdiutil detach "$MOUNT" -quiet >/dev/null 2>&1 || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM

DL="${RELEASE_BASE}/download/${VERSION}"
curl -fsSL "$DL/$ASSET" -o "$TMP/$ASSET" || die "could not download $ASSET"
curl -fsSL "$DL/checksums.txt" -o "$TMP/checksums.txt" || die "missing checksums.txt"
expected=$(awk -v target="$ASSET" '$2 == target || $2 == "*"target {print $1}' "$TMP/checksums.txt")
[ -n "$expected" ] || die "$ASSET is not listed in checksums.txt"
if have sha256sum; then
    actual=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
elif have shasum; then
    actual=$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')
else
    die "sha256sum or shasum is required"
fi
[ "$actual" = "$expected" ] || die "SHA-256 mismatch; refusing to install"

if [ "$VERIFY" = "1" ] && have cosign; then
    curl -fsSL "$DL/checksums.txt.sig" -o "$TMP/checksums.txt.sig" || die "missing checksums.txt.sig"
    curl -fsSL "$DL/checksums.txt.pem" -o "$TMP/checksums.txt.pem" || die "missing checksums.txt.pem"
    cosign verify-blob \
        --certificate "$TMP/checksums.txt.pem" \
        --signature "$TMP/checksums.txt.sig" \
        --certificate-identity-regexp "^https://github.com/${REPO}/" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$TMP/checksums.txt" >/dev/null 2>&1 || die "Cosign verification failed"
    printf '✓ verified release manifest with Cosign\n'
elif [ "$VERIFY" = "1" ]; then
    printf '! cosign not installed; SHA-256 verified, manifest identity not verified\n' >&2
fi

if [ "$OS" = "darwin" ]; then
    MOUNT="$TMP/mount"
    mkdir "$MOUNT"
    hdiutil attach "$TMP/$ASSET" -nobrowse -readonly -mountpoint "$MOUNT" -quiet || die "could not mount disk image"
    SOURCE=$(find "$MOUNT" -maxdepth 1 -name '*.app' -type d | head -n1)
    [ -n "$SOURCE" ] || die "disk image does not contain an app"
    codesign --verify --deep --strict "$SOURCE" >/dev/null 2>&1 || die "the macOS app signature is invalid"
    spctl --assess --type execute "$SOURCE" >/dev/null 2>&1 || die "macOS Gatekeeper rejected the app"
    PARENT=$(dirname "$TARGET")
    STAGED="$PARENT/.fd0.app.installing.$$"
    BACKUP="$PARENT/.fd0.app.previous.$$"
    if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
        sudo mkdir -p "$PARENT"
        sudo rm -rf "$STAGED" "$BACKUP"
        sudo ditto "$SOURCE" "$STAGED"
        if sudo test -e "$TARGET"; then sudo mv "$TARGET" "$BACKUP"; fi
        if ! sudo mv "$STAGED" "$TARGET"; then
            sudo test ! -e "$BACKUP" || sudo mv "$BACKUP" "$TARGET"
            die "could not replace the installed app"
        fi
        sudo rm -rf "$BACKUP"
    else
        mkdir -p "$PARENT"
        rm -rf "$STAGED" "$BACKUP"
        ditto "$SOURCE" "$STAGED"
        if [ -e "$TARGET" ]; then mv "$TARGET" "$BACKUP"; fi
        if ! mv "$STAGED" "$TARGET"; then
            [ ! -e "$BACKUP" ] || mv "$BACKUP" "$TARGET"
            die "could not replace the installed app"
        fi
        rm -rf "$BACKUP"
    fi
else
    install_executable "$TMP/$ASSET" "$TARGET"
    if [ "$SYSTEM" != "1" ]; then
        DESKTOP_DIR="$HOME/.local/share/applications"
        mkdir -p "$DESKTOP_DIR"
        cat > "$DESKTOP_DIR/sh.fd0.desktop.desktop" <<EOF
[Desktop Entry]
Name=fd0
Comment=Password and infrastructure credential manager
Exec=$TARGET
Terminal=false
Type=Application
Categories=Utility;Security;
StartupWMClass=fd0
EOF
    fi
fi

mkdir -p "$TMP/wrappers"
APP_Q=$(shell_quote "$TARGET")
if [ "$OS" = "darwin" ]; then
    FD0_EXEC="$TARGET/Contents/Resources/bin/fd0"
    AGENT_EXEC="$TARGET/Contents/Resources/bin/fd0-agent"
    FD0_Q=$(shell_quote "$FD0_EXEC")
    AGENT_Q=$(shell_quote "$AGENT_EXEC")
    cat > "$TMP/wrappers/fd0" <<EOF
#!/bin/sh
# fd0-desktop-managed-v1
export FD0_DESKTOP_MANAGED=1
export FD0_DESKTOP_APP=$APP_Q
export FD0_AGENT_BIN=$AGENT_Q
exec $FD0_Q "\$@"
EOF
    cat > "$TMP/wrappers/fd0-agent" <<EOF
#!/bin/sh
# fd0-desktop-managed-v1
export FD0_DESKTOP_MANAGED=1
export FD0_DESKTOP_APP=$APP_Q
exec $AGENT_Q "\$@"
EOF
else
    cat > "$TMP/wrappers/fd0" <<EOF
#!/bin/sh
# fd0-desktop-managed-v1
exec $APP_Q --fd0-cli-relay "\$@"
EOF
    cat > "$TMP/wrappers/fd0-agent" <<EOF
#!/bin/sh
# fd0-desktop-managed-v1
exec $APP_Q --fd0-agent-relay "\$@"
EOF
fi
install_executable "$TMP/wrappers/fd0" "$CLI_DIR/fd0"
install_executable "$TMP/wrappers/fd0-agent" "$CLI_DIR/fd0-agent"

printf '✓ fd0 Desktop %s installed at %s\n' "$VERSION_NUM" "$TARGET"
printf '✓ desktop-managed fd0 and fd0-agent installed at %s\n' "$CLI_DIR"
case ":$PATH:" in
    *":$CLI_DIR:"*) ;;
    *) printf '! add %s to PATH to use the bundled fd0 CLI\n' "$CLI_DIR" >&2 ;;
esac
