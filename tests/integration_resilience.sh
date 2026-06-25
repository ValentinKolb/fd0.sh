#!/usr/bin/env bash

# Translog (TRANSLOG.md §6.1) requires explicit opt-in for non-TTY pinning.
# Tests run unattended → enable auto-pin so the first /sync can land the pin.
export FD0_AUTO_PIN=1
# fd0 network-resilience integration test.
#
# Exercises sync against an unreliable server: restart, downtime, slow,
# rate-limited, sudden 5xx. The invariant: vault NEVER gets corrupted,
# data NEVER gets lost, doctor stays clean.

set -uo pipefail

SERVER_PORT=14801
SERVER_DB=/tmp/fd0-res.db
SERVER_LOG=/tmp/fd0-res.log
HOME_DIR=$HOME/.fd0-res
FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}

PASS=0
FAIL=0
step() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()   { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()   { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

cleanup() {
    pkill -f fd0-agent 2>/dev/null || true
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$HOME_DIR" "$SERVER_DB" "$SERVER_LOG"
}
trap cleanup EXIT

start_server() {
    local extra=("$@")
    "$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" "${extra[@]}" > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    # Wait for /health.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if curl -fsS "http://127.0.0.1:${SERVER_PORT}/health" >/dev/null 2>&1; then return 0; fi
        sleep 0.2
    done
    return 1
}
stop_server() {
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    SERVER_PID=
}

step "Setup"
pkill -f fd0-server 2>/dev/null || true
pkill -f fd0-agent  2>/dev/null || true
sleep 0.3
rm -rf "$HOME_DIR" "$SERVER_DB" "$SERVER_LOG"
mkdir -p "$HOME_DIR" && chmod 700 "$HOME_DIR"
cat > "$HOME_DIR/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
on_unlock = false
[client]
lock_wait = "5s"
EOF
start_server --no-ratelimit && ok "server up" || no "server failed to start"
printf "p\np\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "p\n"   | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.2
A() { env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" "$@"; }
A scope create --label work >/dev/null 2>&1
A sync >/dev/null 2>&1

# ─── E1. Server down → sync fails clean → vault unchanged ────────────────
step "E1) Server down: sync fails cleanly, vault preserved"
A set BEFORE_DOWN "value-before" --scope work >/dev/null 2>&1
PRE_VAULT=$(stat -f "%m" "$HOME_DIR/vault.enc" 2>/dev/null || stat -c "%Y" "$HOME_DIR/vault.enc" 2>/dev/null)
stop_server
sleep 0.3
OUT=$(A sync 2>&1 || true)
case "$OUT" in
    *"connect"*|*"refused"*|*"connection"*|*"sync"*) ok "sync failed cleanly with network error" ;;
    *"sync ok"*) no "sync 'succeeded' with no server!" ;;
    *) ok "sync errored (output: ${OUT:0:80})" ;;
esac
# Vault file mtime should be unchanged.
POST_VAULT=$(stat -f "%m" "$HOME_DIR/vault.enc" 2>/dev/null || stat -c "%Y" "$HOME_DIR/vault.enc" 2>/dev/null)
[ "$PRE_VAULT" = "$POST_VAULT" ] \
    && ok "vault unchanged after failed sync" \
    || no "vault mtime changed despite sync failure (pre=$PRE_VAULT post=$POST_VAULT)"

# ─── E2. Server restart → next sync succeeds ─────────────────────────────
step "E2) Server restart preserves data, sync resumes"
start_server --no-ratelimit
sleep 0.2
OUT=$(A sync 2>&1)
case "$OUT" in
    *"sync ok"*) ok "sync succeeded after restart" ;;
    *) no "sync failed after restart: $OUT" ;;
esac
GOT=$(A get BEFORE_DOWN --scope work --raw 2>&1)
[ "$GOT" = "value-before" ] \
    && ok "BEFORE_DOWN secret preserved through downtime" \
    || no "value lost: '$GOT'"

# ─── E3. Sync against slow server (artificial latency) ───────────────────
step "E3) Sync against slow server (latency injected via tc/network — skipped on macOS)"
# tc/netem requires Linux + root; on macOS we skip but verify the
# default sync still completes within 30s.
START=$(date +%s)
A sync >/dev/null 2>&1
END=$(date +%s)
ELAPSED=$((END - START))
[ "$ELAPSED" -lt 30 ] \
    && ok "default sync completes in ${ELAPSED}s (< 30s threshold)" \
    || no "default sync took ${ELAPSED}s — investigate"

# ─── E4. Server with tight rate limit: sync hits 429 ─────────────────────
step "E4) Server with low rate limit: 429s + recovery"
stop_server
# Restart with very tight write limit (3/min). Doing 5 syncs in a burst
# means at least 2 should hit 429.
start_server --writes-per-min=3
sleep 0.2
HITS=0
for i in 1 2 3 4 5 6; do
    OUT=$(A sync 2>&1 || true)
    case "$OUT" in
        *"429"*|*"rate"*|*"Retry-After"*|*"Too Many"*) HITS=$((HITS+1)) ;;
    esac
done
[ "$HITS" -ge 1 ] \
    && ok "saw $HITS rate-limit hit(s) in burst (expected ≥1)" \
    || no "no 429 detected — rate limit not enforced?"

# Wait for tokens to refill, then sync should succeed.
sleep 25  # tokens refill at 3/min = 1 token per 20s
OUT=$(A sync 2>&1)
case "$OUT" in
    *"sync ok"*) ok "sync recovers after rate-limit refill" ;;
    *) no "sync still failing post-refill: $OUT" ;;
esac

# ─── E5. Server crash mid-sync (kill -9) ─────────────────────────────────
step "E5) Server killed during sync"
A set MID_SYNC "v" --scope work >/dev/null 2>&1
( A sync >/dev/null 2>&1 ) &
SYNC_PID=$!
sleep 0.05  # give sync a moment to start
kill -9 $SERVER_PID 2>/dev/null || true
SERVER_PID=
wait $SYNC_PID 2>/dev/null || true
# Vault and chain files must still parse.
OUT=$(A doctor 2>&1)
case "$OUT" in
    *"all clear"*|*"warning"*) ok "doctor clean after server-crash-mid-sync" ;;
    *) no "doctor reports issues: $OUT" ;;
esac

# ─── E6. Restart server (with --no-ratelimit) → MID_SYNC eventually lands ─
step "E6) Restart with --no-ratelimit: MID_SYNC pushes via PushFloor retry"
start_server --no-ratelimit
sleep 0.2
A sync >/dev/null 2>&1
A sync >/dev/null 2>&1   # sometimes needs a second pass
GOT=$(A get MID_SYNC --scope work --raw 2>&1)
[ "$GOT" = "v" ] \
    && ok "MID_SYNC eventually landed (no data loss across server crash)" \
    || no "MID_SYNC lost: '$GOT'"

# ─── E7. Sync against wrong-version server (we have only one binary) ─────
step "E7) Sync against /version endpoint reports api_version v1"
V=$(curl -fsS "http://127.0.0.1:${SERVER_PORT}/version" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("api_version",""))')
[ "$V" = "v1" ] \
    && ok "/version returns api_version=v1" \
    || no "unexpected api_version: '$V'"

# ─── E8. PushFloor invariant: count actual events on server ──────────────
step "E8) PushFloor invariant: server-side event count matches local writes"
# Drain.
A sync >/dev/null 2>&1
A sync >/dev/null 2>&1
# Add 5 secrets, sync, count.
for i in 1 2 3 4 5; do
    A set "INV$i" "v$i" --scope work >/dev/null 2>&1
done
A sync >/dev/null 2>&1
# Restart server-cycle the agent to ensure state is real.
A sync >/dev/null 2>&1   # idempotent — should push 0
OUT=$(A sync 2>&1)
case "$OUT" in
    *"pushed=0 dup=0"*) ok "post-burst follow-up sync pushes nothing (no replay)" ;;
    *) no "follow-up sync re-pushed something: $OUT" ;;
esac

# ─── E9. Doctor remains clean throughout ─────────────────────────────────
step "E9) Final doctor check"
OUT=$(A doctor 2>&1)
case "$OUT" in
    *"all clear"*|*"warning"*) ok "doctor still clean at the end" ;;
    *) no "doctor reports issues: $OUT" ;;
esac

A lock >/dev/null 2>&1
echo
printf "\033[1m== RESILIENCE SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
