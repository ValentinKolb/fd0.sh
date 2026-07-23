#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

set -euo pipefail
export FD0_AUTO_PIN=1

BASE="$FD0_TEST_ROOT/scope-history-repair"
FD0_BIN=${FD0:-$HOME/go/bin/fd0}
AGENT_BIN=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}
DROP_HELPER=$HOME/go/bin/fd0-test-drop-scope-event
PORT=14060
URL="http://127.0.0.1:$PORT"

cleanup() {
    kill "${SERVER_PID:-}" 2>/dev/null || true
    fd0_test_stop_agents
}
trap cleanup EXIT

rm -rf "$BASE"
mkdir -p "$BASE/home" "$BASE/fd0" "$BASE/server"
export HOME="$BASE/home"
export FD0_HOME="$BASE/fd0"
export FD0_SSH_SOCK="$BASE/ssh.sock"
export FD0_AGENT_BIN="$AGENT_BIN"

cat > "$FD0_HOME/config.toml" <<EOF
[sync]
server = "$URL"
on_unlock = false
EOF

FD0_BIND=":$PORT" FD0_DB="$BASE/server/fd0.db" FD0_RATELIMIT_OFF=1 \
    "$SERVER_BIN" >"$BASE/server.log" 2>&1 &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -sf "$URL/health" >/dev/null && break
    sleep 0.2
done
curl -sf "$URL/health" >/dev/null

printf 'test-pass\ntest-pass\n' | "$FD0_BIN" init >/dev/null
printf 'test-pass\n' | "$FD0_BIN" unlock >/dev/null
"$FD0_BIN" scope create --label repair >/dev/null
"$FD0_BIN" set TARGET old --scope repair >/dev/null
"$FD0_BIN" set TARGET current --scope repair >/dev/null
"$FD0_BIN" set FINAL tail --scope repair >/dev/null
"$FD0_BIN" sync >/dev/null

scope_chain=$(find "$FD0_HOME/chains" -maxdepth 1 -type f -name 's_*.cbor' -print -quit)
test -n "$scope_chain"
"$DROP_HELPER" "$scope_chain" >"$BASE/drop.log"

if "$FD0_BIN" get TARGET --scope repair >"$BASE/get-before.log" 2>&1; then
    echo "gapped scope history was exposed before repair" >&2
    exit 1
fi
grep -q "scope history is non-contiguous" "$BASE/get-before.log"

"$FD0_BIN" sync >"$BASE/repair.log" 2>&1
grep -q "repairing legacy scope history" "$BASE/repair.log"
test "$("$FD0_BIN" get TARGET --scope repair --raw)" = "current"
test "$("$FD0_BIN" get FINAL --scope repair --raw)" = "tail"
"$FD0_BIN" doctor >/dev/null

echo "ok scope history repair"
