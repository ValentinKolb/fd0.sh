#!/bin/sh
# fd0 installer / updater.
#
#   curl -fsSL https://raw.githubusercontent.com/ValentinKolb/fd0.sh/main/scripts/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/ValentinKolb/fd0.sh/main/scripts/install.sh | sh -s -- --system
#
# Detects OS+arch, downloads the matching tarball from GitHub Releases,
# installs `fd0`, `fd0-agent`, and `fd0-server` into ~/.local/bin (default)
# or /usr/local/bin (--system), and seeds ~/.fd0/config.toml if absent.

set -eu

REPO="ValentinKolb/fd0.sh"
PREFIX="${HOME}/.local/bin"
SYSTEM=0
VERSION="latest"

while [ $# -gt 0 ]; do
    case "$1" in
        --system)  SYSTEM=1; PREFIX="/usr/local/bin"; shift ;;
        --prefix=*) PREFIX="${1#--prefix=}"; shift ;;
        --version=*) VERSION="${1#--version=}"; shift ;;
        -h|--help)
            cat <<EOF
Usage: install.sh [options]
  --system            install into /usr/local/bin (needs sudo)
  --prefix=DIR        install into DIR
  --version=vX.Y.Z    install a specific tag (default: latest)
  -h, --help          show this help
EOF
            exit 0 ;;
        *)
            echo "unknown flag: $1" >&2; exit 2 ;;
    esac
done

# ─── platform detection ──────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
    linux|darwin) ;;
    *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac
case "$ARCH" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

# ─── version resolution ──────────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
              | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
    [ -n "$VERSION" ] || { echo "could not resolve latest version" >&2; exit 1; }
fi

# ─── current version short-circuit ───────────────────────────────────────
# Look at the target prefix (not just the first PATH match) and require all
# three binaries to be present and version-matched.
if [ -x "$PREFIX/fd0" ] && [ -x "$PREFIX/fd0-agent" ] && [ -x "$PREFIX/fd0-server" ]; then
    CURRENT=$("$PREFIX/fd0" version 2>/dev/null | awk '{print $2}' || true)
    if [ "$CURRENT" = "${VERSION#v}" ]; then
        echo "fd0 ${VERSION} already installed at $PREFIX"
        exit 0
    fi
fi

# ─── download + extract ──────────────────────────────────────────────────
TARBALL="fd0_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "fetching $URL"
curl -fsSL "$URL" -o "$TMP/${TARBALL}"
tar -xzf "$TMP/${TARBALL}" -C "$TMP"

# ─── install ─────────────────────────────────────────────────────────────
INSTALL() {
    src="$1"; dst="$2"
    if [ "$SYSTEM" = "1" ]; then
        sudo install -m 0755 "$src" "$dst"
    else
        mkdir -p "$(dirname "$dst")"
        install -m 0755 "$src" "$dst"
    fi
}

for bin in fd0 fd0-agent fd0-server; do
    if [ -f "$TMP/$bin" ]; then
        INSTALL "$TMP/$bin" "$PREFIX/$bin"
        echo "installed $PREFIX/$bin"
    fi
done

# ─── default config ──────────────────────────────────────────────────────
FD0_HOME="${FD0_HOME:-$HOME/.fd0}"
mkdir -p "$FD0_HOME"
chmod 700 "$FD0_HOME"
if [ ! -f "$FD0_HOME/config.toml" ]; then
    cat > "$FD0_HOME/config.toml" <<EOF
# fd0 client configuration. See https://github.com/${REPO}#configuration
# for the full reference.
#
# Uncomment the [sync] block once you have an fd0-server URL. Without a
# server, on_unlock=true would trigger failing background syncs.

# [sync]
# server    = "http://127.0.0.1:4048"
# interval  = "1h"
# on_unlock = true
EOF
    chmod 600 "$FD0_HOME/config.toml"
    echo "wrote default config to $FD0_HOME/config.toml"
fi

# ─── PATH hint ───────────────────────────────────────────────────────────
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *)
        echo
        echo "$PREFIX is not in your PATH. Add to your shell rc:"
        echo "    export PATH=\"$PREFIX:\$PATH\""
        ;;
esac

echo
echo "✓ fd0 ${VERSION} installed"
echo "  next: fd0 init"
