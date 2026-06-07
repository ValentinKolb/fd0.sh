#!/bin/sh
# fd0 — client installer / updater (workstation, laptop).
#
#   curl -fsSL https://fd0.sh/install | sh
#   curl -fsSL https://fd0.sh/install | sh -s -- --system
#   FD0_VERSION=v1.0.0 curl -fsSL https://fd0.sh/install | sh
#
# Supported platforms:
#   - linux  / amd64, arm64
#   - darwin / amd64, arm64   (macOS Intel + Apple Silicon)
#
# Windows: not yet built by the release pipeline. The fd0 client is
# pure Go and would cross-compile, but the AF_UNIX agent socket and
# %LOCALAPPDATA% path conventions have not been validated. Track at
# https://github.com/ValentinKolb/fd0.sh/issues.
#
# Installs `fd0` and `fd0-agent` into ~/.local/bin (default) or
# /usr/local/bin (--system), seeds ~/.fd0/config.toml if absent,
# and prints a PATH hint when ~/.local/bin isn't on $PATH.
#
# Doubles as an upgrade script: detects an existing install, prints
# `current → new`, and asks before touching anything. Verifies the
# release checksum manifest against the published cosign signature
# (skip with --no-verify or by not having cosign installed).
#
# For server-side deployments (fd0-server, fd0-witness) use the
# Docker compose blocks in deploy/ — see docs/HOSTING.md for the
# full production recipe.

set -eu

# ─── defaults ────────────────────────────────────────────────────────────
REPO="ValentinKolb/fd0.sh"
RELEASE_BASE="${FD0_RELEASE_BASE:-https://github.com/${REPO}/releases}"
API_BASE="${FD0_API_BASE:-https://api.github.com/repos/${REPO}}"
PREFIX="${HOME}/.local/bin"
SYSTEM=0
VERSION="${FD0_VERSION:-latest}"
VERIFY=1
ASSUME_YES=0
BINARIES="fd0 fd0-agent"

while [ $# -gt 0 ]; do
    case "$1" in
        --system)       SYSTEM=1; PREFIX="/usr/local/bin"; shift ;;
        --prefix=*)     PREFIX="${1#--prefix=}"; shift ;;
        --version=*)    VERSION="${1#--version=}"; shift ;;
        --no-verify)    VERIFY=0; shift ;;
        -y|--yes)       ASSUME_YES=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: install.sh [options]

Installs or upgrades the fd0 client (fd0, fd0-agent).

  --system            install into /usr/local/bin (needs sudo)
  --prefix=DIR        install into DIR (default: ~/.local/bin)
  --version=vX.Y.Z    install a specific release tag (default: latest)
  --no-verify         skip cosign verification of the release manifest
  -y, --yes           assume yes for the upgrade prompt
  -h, --help          show this help

Environment:
  FD0_VERSION         same as --version
  FD0_RELEASE_BASE    override the release-download base URL (for testing)
  FD0_API_BASE        override the GitHub API base URL (for testing)
EOF
            exit 0 ;;
        *)
            printf 'unknown flag: %s\n' "$1" >&2; exit 2 ;;
    esac
done

# ─── small helpers ───────────────────────────────────────────────────────
die() { printf 'fd0: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Prompt unless stdin isn't a tty or -y was passed. Default Y; only `n` or
# `N` aborts. Reads from /dev/tty so the prompt survives `curl … | sh`.
confirm() {
    [ "$ASSUME_YES" = "1" ] && return 0
    if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        printf 'fd0: not a terminal; pass -y to confirm non-interactively.\n' >&2
        exit 1
    fi
    printf '%s [Y/n] ' "$1"
    if [ -r /dev/tty ]; then
        IFS= read -r reply < /dev/tty || reply=""
    else
        IFS= read -r reply || reply=""
    fi
    case "$reply" in
        ''|y|Y|yes|YES) return 0 ;;
        *)              return 1 ;;
    esac
}

# Install with sudo only if we're touching a system path AND we aren't root.
INSTALL_BIN() {
    src="$1"; dst="$2"
    dir=$(dirname "$dst")
    if [ "$SYSTEM" = "1" ] && [ "$(id -u)" != "0" ]; then
        sudo install -d -m 0755 "$dir"
        sudo install -m 0755 "$src" "$dst"
    else
        install -d -m 0755 "$dir"
        install -m 0755 "$src" "$dst"
    fi
}

# ─── platform detection ──────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
    linux|darwin) ;;
    *) die "unsupported OS: $OS" ;;
esac
case "$ARCH" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported arch: $ARCH" ;;
esac

# ─── version resolution ──────────────────────────────────────────────────
if [ "$VERSION" = "latest" ]; then
    have curl || die "curl required"
    VERSION=$(curl -fsSL "${API_BASE}/releases/latest" \
              | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
    [ -n "$VERSION" ] || die "could not resolve latest version from ${API_BASE}"
fi
# Strip the optional scoped-tag prefix (e.g. `client-v` or `fd0-v`) and
# the leading `v` so VERSION_NUM is a plain semver like `0.0.5`. VERSION
# (with prefix) stays as-is and is used verbatim in release-download URLs.
VERSION_NUM=$(printf '%s' "$VERSION" | sed -E 's/^([a-z]+-)?v//')

# ─── detect existing install at the target prefix ────────────────────────
CURRENT=""
if [ -x "$PREFIX/fd0" ]; then
    CURRENT=$("$PREFIX/fd0" version 2>/dev/null | awk 'NR==1 {print $2}' || true)
fi

# Same version already there → idempotent no-op. Don't even prompt.
if [ -n "$CURRENT" ] && [ "$CURRENT" = "$VERSION_NUM" ]; then
    printf 'fd0 %s already installed at %s\n' "$VERSION" "$PREFIX"
    exit 0
fi

# ─── confirm install or upgrade ──────────────────────────────────────────
printf '\nfd0 client installer\n'
printf '  target:  %s\n' "$PREFIX"
if [ -n "$CURRENT" ]; then
    printf '  current: %s\n' "$CURRENT"
    printf '  new:     %s\n' "$VERSION_NUM"
    action="upgrade"
else
    printf '  version: %s\n' "$VERSION_NUM"
    action="install"
fi
if [ "$VERIFY" = "1" ] && have cosign; then
    printf '  verify:  cosign (keyless, github actions)\n'
elif [ "$VERIFY" = "1" ]; then
    printf '  verify:  skipped — cosign not installed (pass --no-verify to silence)\n'
    VERIFY=0
else
    printf '  verify:  disabled (--no-verify)\n'
fi
printf '\n'
confirm "proceed with ${action}?" || { printf 'aborted.\n'; exit 1; }

# ─── download manifest + tarball ─────────────────────────────────────────
have curl || die "curl required"
have tar  || die "tar required"

TARBALL="fd0_${OS}_${ARCH}.tar.gz"
DL="${RELEASE_BASE}/download/${VERSION}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

printf '→ fetching %s/%s\n' "$DL" "$TARBALL"
curl -fsSL "$DL/${TARBALL}" -o "$TMP/${TARBALL}" \
    || die "could not download tarball — bad version (${VERSION}) or no asset for ${OS}/${ARCH}?"

if [ "$VERIFY" = "1" ]; then
    printf '→ fetching checksum manifest + cosign signature\n'
    curl -fsSL "$DL/checksums.txt"     -o "$TMP/checksums.txt"     || die "missing checksums.txt"
    curl -fsSL "$DL/checksums.txt.sig" -o "$TMP/checksums.txt.sig" || die "missing checksums.txt.sig"
    curl -fsSL "$DL/checksums.txt.pem" -o "$TMP/checksums.txt.pem" || die "missing checksums.txt.pem"
    printf '→ verifying cosign signature on checksums.txt\n'
    cosign verify-blob \
        --certificate            "$TMP/checksums.txt.pem" \
        --signature              "$TMP/checksums.txt.sig" \
        --certificate-identity-regexp "^https://github.com/${REPO}/" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$TMP/checksums.txt" >/dev/null 2>&1 \
        || die "cosign verification failed — refusing to install"
    printf '→ verifying tarball sha256 against manifest\n'
    expected=$(awk -v t="$TARBALL" '$2 == t || $2 == "*"t {print $1}' "$TMP/checksums.txt")
    [ -n "$expected" ] || die "tarball not listed in checksums.txt"
    if have sha256sum; then
        actual=$(sha256sum "$TMP/${TARBALL}" | awk '{print $1}')
    elif have shasum; then
        actual=$(shasum -a 256 "$TMP/${TARBALL}" | awk '{print $1}')
    else
        die "need sha256sum or shasum to verify"
    fi
    [ "$actual" = "$expected" ] || die "sha256 mismatch — tarball does not match signed manifest"
fi

tar -xzf "$TMP/${TARBALL}" -C "$TMP" || die "could not extract tarball"

# ─── install the client binaries ─────────────────────────────────────────
for bin in $BINARIES; do
    [ -f "$TMP/$bin" ] || die "binary $bin missing from release tarball"
done
for bin in $BINARIES; do
    INSTALL_BIN "$TMP/$bin" "$PREFIX/$bin"
    printf '✓ %s → %s\n' "$bin" "$PREFIX/$bin"
done

# ─── seed client config (fresh install only) ─────────────────────────────
FD0_HOME="${FD0_HOME:-$HOME/.fd0}"
if [ -z "$CURRENT" ]; then
    mkdir -p "$FD0_HOME"
    chmod 700 "$FD0_HOME"
    if [ ! -f "$FD0_HOME/config.toml" ]; then
        cat > "$FD0_HOME/config.toml" <<EOF
# fd0 client configuration. See https://github.com/${REPO}#configuration
# for the full reference.
#
# By default the client targets the hosted fd0.sh instance (both
# replicas, multi-pushed). Override by uncommenting [sync].servers
# below; or use the singular [sync].server key when targeting one
# self-hosted server.

# [sync]
# servers   = ["https://your-server.example", "https://your-replica.example"]
# interval  = "1h"
# on_unlock = true
EOF
        chmod 600 "$FD0_HOME/config.toml"
        printf '✓ wrote default config to %s/config.toml\n' "$FD0_HOME"
    fi
fi

# ─── PATH hint ───────────────────────────────────────────────────────────
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *)
        printf '\n%s is not in your PATH. Add to your shell rc:\n' "$PREFIX"
        # shellcheck disable=SC2016
        printf '    export PATH="%s:$PATH"\n' "$PREFIX"
        ;;
esac

printf '\n✓ fd0 %s ' "$VERSION_NUM"
if [ -n "$CURRENT" ]; then
    printf 'upgraded\n'
else
    printf 'installed\n  next: fd0 init\n'
fi
