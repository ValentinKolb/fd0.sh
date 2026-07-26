#!/bin/sh
# fd0 Desktop installer for signed macOS bundles and Linux AppImages.

set -eu

REPO="k2b-dev/fd0.sh"
RELEASE_BASE="${FD0_RELEASE_BASE:-https://github.com/${REPO}/releases}"
DESKTOP_FEED="${FD0_DESKTOP_FEED_URL:-https://fd0.sh/api/desktop/releases}"
VERSION="${FD0_DESKTOP_VERSION:-latest}"
SYSTEM="${FD0_DESKTOP_SYSTEM:-0}"
ASSUME_YES="${FD0_DESKTOP_ASSUME_YES:-0}"
ALLOW_DOWNGRADE="${FD0_DESKTOP_ALLOW_DOWNGRADE:-0}"
UNINSTALL=0
COSIGN_VERSION="3.0.6"

while [ $# -gt 0 ]; do
    case "$1" in
        --system)       SYSTEM=1; shift ;;
        --version=*)    VERSION="${1#--version=}"; shift ;;
        --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
        --uninstall)    UNINSTALL=1; shift ;;
        -y|--yes)       ASSUME_YES=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: install-desktop.sh [options]

Installs or upgrades fd0 Desktop.

  --system            install for every user (macOS: /Applications, Linux: /usr/local/bin)
  --version=TAG       install a desktop-vX.Y.Z release (default: latest desktop release)
  --allow-downgrade   permit an explicitly selected older release
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
COSIGN="${FD0_COSIGN_BIN:-cosign}"

sha256_file() {
    if have sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "sha256sum or shasum is required"
    fi
}

prepare_cosign() {
    if have "$COSIGN"; then
        COSIGN=$(command -v "$COSIGN")
        return
    fi
    [ -z "${FD0_COSIGN_BIN:-}" ] || die "configured Cosign verifier is not executable: $FD0_COSIGN_BIN"
    case "$OS/$ASSET_ARCH" in
        darwin/x64)   expected="4c3e7af8372d3ca3296e62fa56f23fcbb5721cc6ac1827900d398f110d7cd280"; cosign_os=darwin; cosign_arch=amd64 ;;
        darwin/arm64) expected="5fadd012ae6381a6a29ff86a7d39aa873878852f1073fc90b15995961ecfb084"; cosign_os=darwin; cosign_arch=arm64 ;;
        linux/x64)    expected="c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74"; cosign_os=linux; cosign_arch=amd64 ;;
        linux/arm64)  expected="bedac92e8c3729864e13d4a17048007cfafa79d5deca993a43a90ffe018ef2b8"; cosign_os=linux; cosign_arch=arm64 ;;
        *) die "no release verifier is available for $OS/$ASSET_ARCH" ;;
    esac
    COSIGN="$TMP/cosign"
    curl -fsSL "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-${cosign_os}-${cosign_arch}" \
        -o "$COSIGN" || die "could not download the pinned release verifier"
    actual=$(sha256_file "$COSIGN")
    [ "$actual" = "$expected" ] || die "release verifier SHA-256 mismatch"
    chmod 700 "$COSIGN"
}

version_lt() {
    awk -v left="$1" -v right="$2" '
        function core(version) {
            sub(/\+.*/, "", version)
            sub(/-.*/, "", version)
            return version
        }
        function prerelease(version) {
            sub(/\+.*/, "", version)
            if (version !~ /-/) return ""
            sub(/^[^-]*-/, "", version)
            return version
        }
        BEGIN {
            left_core = core(left)
            right_core = core(right)
            split(left_core, left_parts, ".")
            split(right_core, right_parts, ".")
            for (i = 1; i <= 3; i++) {
                if ((left_parts[i] + 0) < (right_parts[i] + 0)) exit 0
                if ((left_parts[i] + 0) > (right_parts[i] + 0)) exit 1
            }

            left_pre = prerelease(left)
            right_pre = prerelease(right)
            if (left_pre == right_pre || left_pre == "") exit 1
            if (right_pre == "") exit 0

            left_count = split(left_pre, left_ids, ".")
            right_count = split(right_pre, right_ids, ".")
            count = left_count < right_count ? left_count : right_count
            for (i = 1; i <= count; i++) {
                left_numeric = left_ids[i] ~ /^[0-9]+$/
                right_numeric = right_ids[i] ~ /^[0-9]+$/
                if (left_numeric && right_numeric) {
                    if ((left_ids[i] + 0) < (right_ids[i] + 0)) exit 0
                    if ((left_ids[i] + 0) > (right_ids[i] + 0)) exit 1
                } else if (left_numeric != right_numeric) {
                    exit left_numeric ? 0 : 1
                } else {
                    if (left_ids[i] < right_ids[i]) exit 0
                    if (left_ids[i] > right_ids[i]) exit 1
                }
            }
            exit left_count < right_count ? 0 : 1
        }
    '
}

latest_stable_desktop() {
    best=""
    separator='?'
    case "$DESKTOP_FEED" in
        *\?*) separator='&' ;;
    esac
    payload=$(curl -fsSL "${DESKTOP_FEED}${separator}format=tags") \
        || die "stable desktop release feed is unavailable; select an explicit --version"
    for candidate in $payload; do
        if printf '%s\n' "$candidate" | grep -Eq '^desktop-v[0-9]+\.[0-9]+\.[0-9]+$'; then
            if [ -z "$best" ] || version_lt "${best#desktop-v}" "${candidate#desktop-v}"; then
                best=$candidate
            fi
        else
            die "stable desktop release feed returned invalid data"
        fi
    done
    [ -n "$best" ] || die "no stable desktop release found"
    printf '%s\n' "$best"
}

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

ownership_backup() {
    printf '%s/%s.previous' "$OWNERSHIP_DIR" "$1"
}

preserve_existing_wrapper() {
    path=$1
    name=$2
    backup=$(ownership_backup "$name")
    if { [ -e "$path" ] || [ -L "$path" ]; } \
        && ! { [ -f "$path" ] && grep -q '^# fd0-desktop-managed-v1$' "$path"; } \
        && [ ! -e "$backup" ] && [ ! -L "$backup" ]; then
        if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
            sudo mkdir -p "$OWNERSHIP_DIR"
            sudo cp -pP "$path" "$backup"
        else
            mkdir -p "$OWNERSHIP_DIR"
            cp -pP "$path" "$backup"
        fi
        printf '✓ preserved existing %s at %s\n' "$name" "$backup"
    fi
}

restore_preserved_wrapper() {
    path=$1
    name=$2
    backup=$(ownership_backup "$name")
    [ -e "$backup" ] || [ -L "$backup" ] || return 0
    if [ -e "$path" ] || [ -L "$path" ]; then
        printf '! kept preserved %s at %s because %s is now user-managed\n' "$name" "$backup" "$path" >&2
        return 0
    fi
    dir=$(dirname "$path")
    if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
        sudo mkdir -p "$dir"
        sudo mv "$backup" "$path"
    else
        mkdir -p "$dir"
        mv "$backup" "$path"
    fi
    printf '✓ restored previous %s at %s\n' "$name" "$path"
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
OWNERSHIP_DIR=$([ "$SYSTEM" = "1" ] && printf '/usr/local/share/fd0-desktop' || printf '%s/.local/share/fd0-desktop' "$HOME")

if [ "$UNINSTALL" = "1" ]; then
    confirm "uninstall fd0 Desktop and its managed CLI? Vault data will be kept." || { printf 'aborted.\n'; exit 1; }
    if [ "$OS" = "darwin" ] && [ -x "$TARGET/Contents/MacOS/fd0" ]; then
        "$TARGET/Contents/MacOS/fd0" --fd0-agent-service-uninstall >/dev/null 2>&1 || true
    elif [ "$OS" = "linux" ]; then
        unit="$HOME/.config/systemd/user/fd0-agent.service"
        if [ -f "$unit" ] && grep -q '^# fd0-desktop-managed-v1$' "$unit"; then
            systemctl --user disable --now fd0-agent.service >/dev/null 2>&1 || true
            rm -f "$unit"
            systemctl --user daemon-reload >/dev/null 2>&1 || true
        fi
    fi
    remove_managed_wrapper "$CLI_DIR/fd0"
    remove_managed_wrapper "$CLI_DIR/fd0-agent"
    restore_preserved_wrapper "$CLI_DIR/fd0" fd0
    restore_preserved_wrapper "$CLI_DIR/fd0-agent" fd0-agent
    remove_path "$TARGET"
    if [ "$OS" = "linux" ] && [ "$SYSTEM" != "1" ]; then
        remove_path "$HOME/.local/share/applications/sh.fd0.desktop.desktop"
    fi
    if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
        sudo rmdir "$OWNERSHIP_DIR" 2>/dev/null || true
    else
        rmdir "$OWNERSHIP_DIR" 2>/dev/null || true
    fi
    printf '✓ fd0 Desktop removed; %s was not changed\n' "${FD0_HOME:-$HOME/.fd0}"
    exit 0
fi

have curl || die "curl is required"
REQUESTED_LATEST=0
if [ "$VERSION" = "latest" ]; then
    REQUESTED_LATEST=1
    VERSION=$(latest_stable_desktop)
fi
case "$VERSION" in
    desktop-v*) ;;
    v[0-9]*|[0-9]*) VERSION="desktop-v${VERSION#v}" ;;
    *) die "invalid desktop release tag: $VERSION" ;;
esac
printf '%s\n' "$VERSION" | grep -Eq '^desktop-v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' \
    || die "invalid desktop release tag: $VERSION"
VERSION_NUM=${VERSION#desktop-v}

CURRENT=""
if [ "$OS" = "darwin" ] && [ -x "$TARGET/Contents/Resources/bin/fd0" ]; then
    CURRENT=$("$TARGET/Contents/Resources/bin/fd0" version 2>/dev/null | awk 'NR == 1 {print $2}' || true)
elif [ "$OS" = "linux" ] && [ -x "$TARGET" ]; then
    CURRENT=$(APPIMAGE_EXTRACT_AND_RUN=1 "$TARGET" --fd0-cli-relay version 2>/dev/null | awk 'NR == 1 {print $2}' || true)
fi
if printf '%s\n' "$CURRENT" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$' \
    && version_lt "$VERSION_NUM" "$CURRENT"; then
    if [ "$REQUESTED_LATEST" = "1" ] || [ "$ALLOW_DOWNGRADE" != "1" ]; then
        die "refusing downgrade from $CURRENT to $VERSION_NUM; select an explicit version and pass --allow-downgrade"
    fi
fi
if [ "$OS" = "darwin" ]; then
    ASSET="fd0-desktop_${VERSION_NUM}_${ASSET_OS}_${ASSET_ARCH}.dmg"
else
    ASSET="fd0-desktop_${VERSION_NUM}_${ASSET_OS}_${ASSET_ARCH}.AppImage"
fi

printf '\nfd0 Desktop installer\n'
printf '  release: %s\n' "$VERSION"
printf '  target:  %s\n' "$TARGET"
if [ -n "$CURRENT" ]; then printf '  current: %s\n' "$CURRENT"; fi
printf '  asset:   %s\n' "$ASSET"
printf '  verify:  sha256 + cosign (exact release workflow)\n\n'
confirm "install fd0 Desktop?" || { printf 'aborted.\n'; exit 1; }

TMP=$(mktemp -d)
MOUNT=""
cleanup() {
    if [ -n "$MOUNT" ]; then hdiutil detach "$MOUNT" -quiet >/dev/null 2>&1 || true; fi
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
prepare_cosign

DL="${RELEASE_BASE}/download/${VERSION}"
curl -fsSL "$DL/$ASSET" -o "$TMP/$ASSET" || die "could not download $ASSET"
curl -fsSL "$DL/checksums.txt" -o "$TMP/checksums.txt" || die "missing checksums.txt"
expected=$(awk -v target="$ASSET" '$2 == target || $2 == "*"target {print $1}' "$TMP/checksums.txt")
[ -n "$expected" ] || die "$ASSET is not listed in checksums.txt"
actual=$(sha256_file "$TMP/$ASSET")
[ "$actual" = "$expected" ] || die "SHA-256 mismatch; refusing to install"

curl -fsSL "$DL/checksums.txt.sig" -o "$TMP/checksums.txt.sig" || die "missing checksums.txt.sig"
curl -fsSL "$DL/checksums.txt.pem" -o "$TMP/checksums.txt.pem" || die "missing checksums.txt.pem"
IDENTITY_TAG=$(printf '%s' "$VERSION" | sed 's/\./\\./g')
"$COSIGN" verify-blob \
    --certificate "$TMP/checksums.txt.pem" \
    --signature "$TMP/checksums.txt.sig" \
    --certificate-identity-regexp "^https://github\\.com/k2b-dev/fd0\\.sh/\\.github/workflows/release-desktop\\.yml@refs/tags/${IDENTITY_TAG}$" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$TMP/checksums.txt" >/dev/null 2>&1 || die "Cosign verification failed"
printf '✓ verified release manifest with Cosign\n'

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
preserve_existing_wrapper "$CLI_DIR/fd0" fd0
preserve_existing_wrapper "$CLI_DIR/fd0-agent" fd0-agent
install_executable "$TMP/wrappers/fd0" "$CLI_DIR/fd0"
install_executable "$TMP/wrappers/fd0-agent" "$CLI_DIR/fd0-agent"

printf '✓ fd0 Desktop %s installed at %s\n' "$VERSION_NUM" "$TARGET"
printf '✓ desktop-managed fd0 and fd0-agent installed at %s\n' "$CLI_DIR"
case ":$PATH:" in
    *":$CLI_DIR:"*) ;;
    *) printf '! add %s to PATH to use the bundled fd0 CLI\n' "$CLI_DIR" >&2 ;;
esac
