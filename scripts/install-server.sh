#!/bin/sh
# fd0 — server installer / updater (host that stores ciphertext + log).
#
#   curl -fsSL https://fd0.sh/install-server.sh | sudo sh
#   FD0_VERSION=v1.0.0 curl -fsSL https://fd0.sh/install-server.sh | sudo sh
#
# Installs `fd0-server` and `fd0-witness` into /usr/local/bin, creates a
# system user `fd0` with state under /var/lib/fd0, drops a systemd unit
# at /etc/systemd/system/fd0.service, and seeds /etc/default/fd0-server
# (env-var config). Does NOT enable or start the service — that is a
# deliberate step you take after reviewing the generated config.
#
# Doubles as an upgrade script: detects an existing install, prints
# `current → new`, asks before touching anything, and REFUSES to swap
# binaries while fd0.service is active (binary swaps under a live
# daemon are how subtle corruption happens — stop it first).
#
# For the client binaries (fd0, fd0-agent) use install.sh instead.

set -eu

# ─── defaults ────────────────────────────────────────────────────────────
REPO="ValentinKolb/fd0.sh"
RELEASE_BASE="${FD0_RELEASE_BASE:-https://github.com/${REPO}/releases}"
API_BASE="${FD0_API_BASE:-https://api.github.com/repos/${REPO}}"
PREFIX="${FD0_PREFIX:-/usr/local/bin}"
STATE_DIR="${FD0_STATE_DIR:-/var/lib/fd0}"
ETC_DIR="${FD0_ETC_DIR:-/etc/fd0}"
UNIT_DIR="${FD0_UNIT_DIR:-/etc/systemd/system}"
ENVFILE="${FD0_ENVFILE:-/etc/default/fd0-server}"
SERVICE_USER="${FD0_SERVICE_USER:-fd0}"
VERSION="${FD0_VERSION:-latest}"
VERIFY=1
ASSUME_YES=0
FORCE_DAEMON=0
BINARIES="fd0-server fd0-witness"

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix=*)        PREFIX="${1#--prefix=}"; shift ;;
        --version=*)       VERSION="${1#--version=}"; shift ;;
        --no-verify)       VERIFY=0; shift ;;
        -y|--yes)          ASSUME_YES=1; shift ;;
        --force-daemon-running)
            # ESCAPE HATCH. Lets you swap binaries while the daemon is
            # running. Not recommended; documented for emergencies.
            FORCE_DAEMON=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: install-server.sh [options]

Installs or upgrades fd0-server + fd0-witness.

  --prefix=DIR                install binaries into DIR (default: /usr/local/bin)
  --version=vX.Y.Z            install a specific release tag (default: latest)
  --no-verify                 skip cosign verification of the release manifest
  -y, --yes                   assume yes for the upgrade prompt
  --force-daemon-running      swap binaries even if fd0.service is active (NOT recommended)
  -h, --help                  show this help

Environment:
  FD0_VERSION                 same as --version
  FD0_PREFIX                  same as --prefix
  FD0_STATE_DIR               state directory (default: /var/lib/fd0)
  FD0_ETC_DIR                 config directory (default: /etc/fd0)
  FD0_SERVICE_USER            system user that runs fd0.service (default: fd0)
  FD0_RELEASE_BASE            override release-download base URL (for testing)
  FD0_API_BASE                override GitHub API base URL (for testing)
EOF
            exit 0 ;;
        *)
            printf 'unknown flag: %s\n' "$1" >&2; exit 2 ;;
    esac
done

# ─── small helpers ───────────────────────────────────────────────────────
die() { printf 'fd0-server: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

confirm() {
    [ "$ASSUME_YES" = "1" ] && return 0
    if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        printf 'fd0-server: not a terminal; pass -y to confirm non-interactively.\n' >&2
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

# Run a command as root if we aren't already. SUDO can be pre-set via env
# (e.g. SUDO="" if you trust the script to write to its targets directly,
# or SUDO="doas" on systems without sudo).
SUDO="${SUDO-unset}"
if [ "$SUDO" = "unset" ]; then
    if [ "$(id -u)" = "0" ]; then
        SUDO=""
    elif have sudo; then
        SUDO="sudo"
    else
        die "this script needs root, sudo, or a preset \$SUDO (e.g. doas)."
    fi
fi

# ─── platform detection ──────────────────────────────────────────────────
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
    linux) ;;
    darwin)
        # macOS gets the binaries but no systemd. Useful for dev hosts.
        printf 'note: macOS detected — installing binaries only, no systemd unit.\n' ;;
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
VERSION_NUM="${VERSION#v}"

# ─── detect existing install ─────────────────────────────────────────────
CURRENT=""
if [ -x "$PREFIX/fd0-server" ]; then
    CURRENT=$("$PREFIX/fd0-server" --version 2>/dev/null | awk 'NR==1 {print $NF}' || true)
    # Fall back to the kong-generated "fd0-server <version>" form.
    [ -z "$CURRENT" ] && CURRENT=$("$PREFIX/fd0-server" version 2>/dev/null | awk 'NR==1 {print $NF}' || true)
fi

# Same version already there → idempotent no-op.
if [ -n "$CURRENT" ] && [ "$CURRENT" = "$VERSION_NUM" ]; then
    printf 'fd0-server %s already installed at %s\n' "$VERSION" "$PREFIX"
    exit 0
fi

# ─── refuse upgrade while daemon is active ───────────────────────────────
# Only relevant on upgrade (CURRENT != "") and Linux with systemd.
DAEMON_ACTIVE=0
if [ -n "$CURRENT" ] && [ "$OS" = "linux" ] && have systemctl; then
    if systemctl is-active --quiet fd0.service 2>/dev/null; then
        DAEMON_ACTIVE=1
    fi
fi

if [ "$DAEMON_ACTIVE" = "1" ] && [ "$FORCE_DAEMON" = "0" ]; then
    cat >&2 <<EOF

fd0-server: refusing to upgrade — fd0.service is currently active.

  current: $CURRENT
  new:     $VERSION_NUM

  Swapping the binary under a running daemon is how subtle corruption
  happens (open file descriptors, half-flushed SQLite WAL, in-flight
  log entries). Stop the service first:

      sudo systemctl stop fd0

  …then re-run this script. The witness, if you run one separately,
  can keep running during the swap.

  Emergency override: --force-daemon-running (not recommended).

EOF
    exit 1
fi

# ─── confirm install or upgrade ──────────────────────────────────────────
printf '\nfd0 server installer\n'
printf '  target:  %s\n' "$PREFIX"
printf '  state:   %s\n' "$STATE_DIR"
printf '  config:  %s\n' "$ENVFILE"
printf '  unit:    %s/fd0.service\n' "$UNIT_DIR"
printf '  user:    %s\n' "$SERVICE_USER"
if [ -n "$CURRENT" ]; then
    printf '  current: %s\n' "$CURRENT"
    printf '  new:     %s\n' "$VERSION_NUM"
    action="upgrade"
    [ "$FORCE_DAEMON" = "1" ] && printf '  WARN:    --force-daemon-running set; daemon will keep running across swap.\n'
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

# ─── download + verify + extract ─────────────────────────────────────────
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

for bin in $BINARIES; do
    [ -f "$TMP/$bin" ] || die "binary $bin missing from release tarball"
done

# ─── install binaries ────────────────────────────────────────────────────
$SUDO install -d -m 0755 "$PREFIX"
for bin in $BINARIES; do
    $SUDO install -m 0755 "$TMP/$bin" "$PREFIX/$bin"
    printf '✓ %s → %s\n' "$bin" "$PREFIX/$bin"
done

# ─── macOS: stop here ────────────────────────────────────────────────────
if [ "$OS" != "linux" ]; then
    printf '\n✓ fd0-server %s ' "$VERSION_NUM"
    if [ -n "$CURRENT" ]; then printf 'upgraded'; else printf 'installed'; fi
    printf ' (binaries only; no systemd on %s)\n' "$OS"
    exit 0
fi

# ─── system user + state dir (fresh install only) ────────────────────────
if [ -z "$CURRENT" ]; then
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        if have useradd; then
            $SUDO useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin --user-group "$SERVICE_USER"
        elif have adduser; then
            $SUDO adduser --system --home "$STATE_DIR" --shell /usr/sbin/nologin --group "$SERVICE_USER"
        else
            die "neither useradd nor adduser available — create user '$SERVICE_USER' manually and re-run"
        fi
        printf '✓ created system user: %s\n' "$SERVICE_USER"
    fi
    $SUDO install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"
    $SUDO install -d -m 0755 "$ETC_DIR"
    printf '✓ state dir: %s\n' "$STATE_DIR"
fi

# ─── env file (fresh install only — never clobber operator edits) ────────
if [ ! -f "$ENVFILE" ]; then
    $SUDO install -d -m 0755 "$(dirname "$ENVFILE")"
    $SUDO tee "$ENVFILE" >/dev/null <<EOF
# fd0-server environment configuration.
# See: https://github.com/${REPO}#fd0-server-flags
#
# Listen address. Default is the wire-format port 0xFD0 = 4048.
FD0_BIND=:4048

# SQLite database file. Lives in the state dir created by the installer.
FD0_DB=${STATE_DIR}/fd0.db

# Maximum request body size (bytes). Default 8 MiB.
# FD0_MAX_BODY=8388608

# Verbose (debug) logging.
# FD0_VERBOSE=1

# Per-identity rate limits. Negative disables a class; FD0_RATELIMIT_OFF=1
# disables all rate limiting (single-instance only — don't do this behind
# a load balancer without external limiting).
# FD0_RATELIMIT_WRITES_PER_MIN=60
# FD0_RATELIMIT_BYTES_PER_MIN=33554432
# FD0_RATELIMIT_REGISTER_PER_HOUR=5
EOF
    $SUDO chmod 0644 "$ENVFILE"
    printf '✓ env file: %s\n' "$ENVFILE"
fi

# ─── systemd unit (always rewrite — it's our artifact, not the operator's) ──
$SUDO install -d -m 0755 "$UNIT_DIR"
$SUDO tee "$UNIT_DIR/fd0.service" >/dev/null <<EOF
[Unit]
Description=fd0 sync server
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
EnvironmentFile=-${ENVFILE}
ExecStart=${PREFIX}/fd0-server
Restart=on-failure
RestartSec=2s

# State + working dir live under StateDirectory; systemd sets up the
# permissions and exposes the path via \$STATE_DIRECTORY.
StateDirectory=fd0
WorkingDirectory=${STATE_DIR}

# Hardening — the server reads ciphertext blobs and signed metadata,
# never plaintext. There is no reason for it to write outside its state
# dir, talk to the network beyond its bind socket, or hold capabilities.
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=${STATE_DIR}

[Install]
WantedBy=multi-user.target
EOF
printf '✓ systemd unit: %s/fd0.service\n' "$UNIT_DIR"

# Reload systemd so it sees the new (or updated) unit.
if have systemctl; then
    $SUDO systemctl daemon-reload
fi

# ─── final hint ──────────────────────────────────────────────────────────
printf '\n✓ fd0-server %s ' "$VERSION_NUM"
if [ -n "$CURRENT" ]; then printf 'upgraded\n'; else printf 'installed\n'; fi

if [ -z "$CURRENT" ]; then
    cat <<EOF

next:
  1. review the config:           $ENVFILE
  2. enable + start the service:  sudo systemctl enable --now fd0
  3. check it came up:            sudo systemctl status fd0
  4. open the firewall to port:   4048 (default)

The witness (fd0-witness) is installed but not wired into systemd — it's
optional and typically run on a separate host. See WITNESS.md for setup.
EOF
elif [ "$FORCE_DAEMON" = "0" ]; then
    cat <<EOF

  start the service again:        sudo systemctl start fd0
EOF
fi
