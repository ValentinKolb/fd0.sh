#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BASE=$(mktemp -d "${TMPDIR:-/tmp}/fd0-desktop-installer.XXXXXX")
trap 'rm -rf "$BASE"' EXIT

RELEASE="$BASE/releases/download/desktop-v0.1.0"
FAKE_BIN="$BASE/bin"
mkdir -p "$RELEASE" "$FAKE_BIN"

printf 'mac artifact\n' > "$RELEASE/fd0-desktop_0.1.0_mac_arm64.dmg"
cat > "$RELEASE/fd0-desktop_0.1.0_linux_arm64.AppImage" <<'EOF'
#!/bin/sh
case "$1" in
  --fd0-cli-relay) shift; printf 'linux fd0 %s managed=%s\n' "$*" "${FD0_DESKTOP_MANAGED:-relay}" ;;
  --fd0-agent-relay) shift; printf 'linux agent %s\n' "$*" ;;
  *) printf 'desktop app\n' ;;
esac
EOF
chmod +x "$RELEASE/fd0-desktop_0.1.0_linux_arm64.AppImage"
(
  cd "$RELEASE"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum fd0-desktop_*
  else
    shasum -a 256 fd0-desktop_* | awk '{print $1 "  " $2}'
  fi
) > "$RELEASE/checksums.txt"

cat > "$FAKE_BIN/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf '%s\n' "${TEST_UNAME_S:?}" ;;
  -m) printf '%s\n' "${TEST_UNAME_M:?}" ;;
  *) exit 2 ;;
esac
EOF

cat > "$FAKE_BIN/hdiutil" <<'EOF'
#!/bin/sh
if [ "$1" = "detach" ]; then exit 0; fi
mount=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-mountpoint" ]; then mount=$2; shift 2; else shift; fi
done
test -n "$mount"
mkdir -p "$mount/fd0.app/Contents/Resources/bin"
printf 'desktop app\n' > "$mount/fd0.app/Contents/version"
cat > "$mount/fd0.app/Contents/Resources/bin/fd0" <<'EOS'
#!/bin/sh
printf 'mac fd0 %s managed=%s\n' "$*" "${FD0_DESKTOP_MANAGED:-}"
EOS
cat > "$mount/fd0.app/Contents/Resources/bin/fd0-agent" <<'EOS'
#!/bin/sh
printf 'mac agent %s\n' "$*"
EOS
chmod +x "$mount/fd0.app/Contents/Resources/bin/fd0" "$mount/fd0.app/Contents/Resources/bin/fd0-agent"
EOF

cat > "$FAKE_BIN/ditto" <<'EOF'
#!/bin/sh
cp -R "$1" "$2"
EOF
cat > "$FAKE_BIN/codesign" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$FAKE_BIN/spctl" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$FAKE_BIN/uname" "$FAKE_BIN/hdiutil" "$FAKE_BIN/ditto" "$FAKE_BIN/codesign" "$FAKE_BIN/spctl"

run_installer() {
  HOME=$1 \
  TEST_UNAME_S=$2 \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_DESKTOP_VERSION=desktop-v0.1.0 \
  FD0_DESKTOP_ASSUME_YES=1 \
  FD0_DESKTOP_VERIFY=0 \
    sh "$ROOT/scripts/install-desktop.sh"
}

MAC_HOME="$BASE/mac-home"
run_installer "$MAC_HOME" Darwin >/dev/null
test "$(cat "$MAC_HOME/Applications/fd0.app/Contents/version")" = "desktop app"
test "$(HOME="$MAC_HOME" "$MAC_HOME/.local/bin/fd0" version)" = "mac fd0 version managed=1"
test "$(HOME="$MAC_HOME" "$MAC_HOME/.local/bin/fd0-agent" check)" = "mac agent check"

LINUX_HOME="$BASE/linux-home"
run_installer "$LINUX_HOME" Linux >/dev/null
test -x "$LINUX_HOME/.local/bin/fd0-desktop"
test "$(HOME="$LINUX_HOME" "$LINUX_HOME/.local/bin/fd0" version)" = "linux fd0 version managed=relay"
test "$(HOME="$LINUX_HOME" "$LINUX_HOME/.local/bin/fd0-agent" check)" = "linux agent check"
grep -Fq "Exec=$LINUX_HOME/.local/bin/fd0-desktop" \
  "$LINUX_HOME/.local/share/applications/sh.fd0.desktop.desktop"

run_installer "$LINUX_HOME" Linux >/dev/null
test "$(HOME="$LINUX_HOME" "$LINUX_HOME/.local/bin/fd0" version)" = "linux fd0 version managed=relay"

MAIN_HOME="$BASE/main-installer-home"
HOME="$MAIN_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_DESKTOP_INSTALL_URL="file://$ROOT/scripts/install-desktop.sh" \
FD0_RELEASE_BASE="file://$BASE/releases" \
FD0_DESKTOP_VERIFY=0 \
  sh "$ROOT/scripts/install.sh" --desktop --version=0.1.0 --no-verify --yes >/dev/null
test "$(HOME="$MAIN_HOME" "$MAIN_HOME/.local/bin/fd0" version)" = "linux fd0 version managed=relay"

mkdir -p "$MAIN_HOME/.fd0"
printf 'keep\n' > "$MAIN_HOME/.fd0/vault.enc"
HOME="$MAIN_HOME" \
TEST_UNAME_S=Linux \
TEST_UNAME_M=arm64 \
PATH="$FAKE_BIN:$PATH" \
FD0_DESKTOP_ASSUME_YES=1 \
  sh "$ROOT/scripts/install-desktop.sh" --uninstall --yes >/dev/null
test ! -e "$MAIN_HOME/.local/bin/fd0-desktop"
test ! -e "$MAIN_HOME/.local/bin/fd0"
test ! -e "$MAIN_HOME/.local/bin/fd0-agent"
test "$(cat "$MAIN_HOME/.fd0/vault.enc")" = "keep"

printf 'tampered\n' >> "$RELEASE/fd0-desktop_0.1.0_linux_arm64.AppImage"
TAMPERED_HOME="$BASE/tampered-home"
if run_installer "$TAMPERED_HOME" Linux >/dev/null 2>&1; then
  echo "desktop installer accepted a checksum mismatch" >&2
  exit 1
fi
test ! -e "$TAMPERED_HOME/.local/bin/fd0-desktop"

if HOME="$BASE/invalid-home" \
  TEST_UNAME_S=Linux \
  TEST_UNAME_M=arm64 \
  PATH="$FAKE_BIN:$PATH" \
  FD0_RELEASE_BASE="file://$BASE/releases" \
  FD0_DESKTOP_VERSION='desktop-v../../escape' \
  FD0_DESKTOP_ASSUME_YES=1 \
  FD0_DESKTOP_VERIFY=0 \
    sh "$ROOT/scripts/install-desktop.sh" >/dev/null 2>&1; then
  echo "desktop installer accepted an invalid release tag" >&2
  exit 1
fi

echo "ok desktop installer"
