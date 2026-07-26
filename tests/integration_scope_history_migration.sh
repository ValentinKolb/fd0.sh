#!/usr/bin/env bash
# Automatic migration of scope chains written by the retired v1 compactor.
#
# The point of this test is what it does NOT run: there is no `fd0 sync`, no
# repair flag, no maintenance command anywhere between compacting the chain
# and reading a secret back. The user unlocks and reads; everything else has
# to happen on its own.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

set -euo pipefail
export FD0_AUTO_PIN=1

BASE="$FD0_TEST_ROOT/scope-history-migration"
FD0_BIN=${FD0:-$HOME/go/bin/fd0}
AGENT_BIN=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}
COMPACT_HELPER=$HOME/go/bin/fd0-test-compact-scope-chain
DROP_HELPER=$HOME/go/bin/fd0-test-drop-scope-event
PORT=14061
URL="http://127.0.0.1:$PORT"

SERVER_PID=
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

start_server() {
    FD0_BIND=":$PORT" FD0_DB="$BASE/server/fd0.db" FD0_RATELIMIT_OFF=1 \
        "$SERVER_BIN" >>"$BASE/server.log" 2>&1 &
    SERVER_PID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        curl -sf "$URL/health" >/dev/null && return 0
        sleep 0.2
    done
    curl -sf "$URL/health" >/dev/null
}

stop_server() {
    [ -n "$SERVER_PID" ] || return 0
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
}

scope_chain_path() {
    find "$FD0_HOME/chains" -maxdepth 1 -type f -name 's_*.cbor' -print -quit
}

start_server

printf 'test-pass\ntest-pass\n' | "$FD0_BIN" init >/dev/null
printf 'test-pass\n' | "$FD0_BIN" unlock >/dev/null
"$FD0_BIN" scope create --label legacy >/dev/null
"$FD0_BIN" set ALPHA one --scope legacy >/dev/null
"$FD0_BIN" set BETA two --scope legacy >/dev/null
"$FD0_BIN" set GAMMA three --scope legacy >/dev/null
"$FD0_BIN" set DELTA four --scope legacy >/dev/null
# The one and only sync: it pins the server and publishes the full history,
# exactly as a pre-migration client would have left things.
"$FD0_BIN" sync >/dev/null

CHAIN=$(scope_chain_path)
test -n "$CHAIN"

# ---------------------------------------------------------------------------
# 1. A read migrates lazily — no repair command, no `fd0 sync`.
# ---------------------------------------------------------------------------
"$COMPACT_HELPER" "$CHAIN" 2 >"$BASE/compact-1.log"
grep -q "compacted to genesis" "$BASE/compact-1.log"

# Sanity: the compacted chain really is unreadable by the replay rules.
# (Proven by the classifier inside the helper plus the offline check below.)
test "$("$FD0_BIN" get ALPHA --scope legacy --raw)" = "one"
test "$("$FD0_BIN" get DELTA --scope legacy --raw)" = "four"

# `doctor` replays every chain without the lazy hook, so a clean run proves
# the file on disk is genuinely contiguous again — not merely readable.
"$FD0_BIN" doctor >/dev/null

# Nothing may have been re-published: migration restores history, it does not
# advance it, and it must not touch the vault's sealed tip.
grep -q "repairing legacy scope history" "$BASE"/*.log 2>/dev/null && {
    echo "migration went through the sync repair path" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# 2. Offline: a specific, actionable message — never the generic failure.
# ---------------------------------------------------------------------------
"$COMPACT_HELPER" "$CHAIN" 2 >"$BASE/compact-2.log"
CHAIN_BEFORE=$(shasum -a 256 "$CHAIN" | awk '{print $1}')
VAULT_BEFORE=$(shasum -a 256 "$FD0_HOME/vault.enc" | awk '{print $1}')
stop_server

if "$FD0_BIN" get ALPHA --scope legacy >"$BASE/offline.log" 2>&1; then
    echo "read succeeded while the server was down" >&2
    exit 1
fi
grep -q "older version of fd0" "$BASE/offline.log"
grep -q "one-time history repair" "$BASE/offline.log"
grep -q "retrying is safe" "$BASE/offline.log"
grep -q "could not complete that action" "$BASE/offline.log" && {
    echo "offline failure fell back to the generic message" >&2
    exit 1
}

# A failed migration leaves the chain file and the vault byte-identical.
test "$(shasum -a 256 "$CHAIN" | awk '{print $1}')" = "$CHAIN_BEFORE"
test "$(shasum -a 256 "$FD0_HOME/vault.enc" | awk '{print $1}')" = "$VAULT_BEFORE"

# ---------------------------------------------------------------------------
# 3. Retry is safe: with the server back, the same read just works.
# ---------------------------------------------------------------------------
start_server
test "$("$FD0_BIN" get BETA --scope legacy --raw)" = "two"
"$FD0_BIN" doctor >/dev/null

# ---------------------------------------------------------------------------
# 4. Unlock alone migrates, before any read happens.
# ---------------------------------------------------------------------------
"$COMPACT_HELPER" "$CHAIN" 2 >"$BASE/compact-3.log"
"$FD0_BIN" lock >/dev/null 2>&1
printf 'test-pass\n' | "$FD0_BIN" unlock >"$BASE/unlock.log" 2>&1
grep -q "older version of fd0" "$BASE/unlock.log"
grep -q "history repair complete" "$BASE/unlock.log"
# doctor bypasses the lazy read hook, so this can only pass if unlock did it.
"$FD0_BIN" doctor >/dev/null
test "$("$FD0_BIN" get GAMMA --scope legacy --raw)" = "three"

# ---------------------------------------------------------------------------
# 5. A gap the compactor could not have produced is never auto-migrated.
# ---------------------------------------------------------------------------
"$DROP_HELPER" "$CHAIN" >"$BASE/drop.log"
if "$FD0_BIN" get DELTA --scope legacy >"$BASE/midgap.log" 2>&1; then
    echo "a mid-history gap was silently repaired" >&2
    exit 1
fi
grep -q "scope history is non-contiguous" "$BASE/midgap.log"
# It still has the ordinary, explicit repair path.
"$FD0_BIN" sync >"$BASE/sync-repair.log" 2>&1
grep -q "repairing legacy scope history" "$BASE/sync-repair.log"
test "$("$FD0_BIN" get DELTA --scope legacy --raw)" = "four"

echo "ok scope history migration"
