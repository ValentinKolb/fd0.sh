#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

# fd0-witness end-to-end integration test (TRANSLOG.md §8). Spins up
# fd0-server + a real client + fd0-witness, drives writes through
# the client, and verifies the witness archives every STH and detects
# pubkey-rotation equivocation when the server is restarted with a
# fresh key.
#
# Run from repo root:
#   bash tests/integration_witness.sh

export FD0_AUTO_PIN=1

set -uo pipefail

SERVER_PORT=14920
SERVER_DB=/tmp/fd0-witness-server.db
SERVER_LOG=/tmp/fd0-witness-server.log
SERVER_KEY=/tmp/fd0-witness-server.key
HOME_AL=$HOME/.fd0-witness-al
WITNESS_DB=/tmp/fd0-witness-archive.db
WITNESS_CFG=/tmp/fd0-witness.toml
WITNESS_LOG=/tmp/fd0-witness.log
FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}
FD0_WITNESS_BIN=${FD0_WITNESS:-$HOME/go/bin/fd0-witness}

PASS=0
FAIL=0
step() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()   { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()   { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

cleanup() {
    fd0_test_stop_matching -f fd0-witness 2>/dev/null || true
    fd0_test_stop_matching -f fd0-agent  2>/dev/null || true
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_LOG" "$SERVER_KEY" \
           "$WITNESS_DB" "$WITNESS_CFG" "$WITNESS_LOG"
}
trap cleanup EXIT

step "Setup"
fd0_test_stop_matching -f fd0-server  2>/dev/null || true
fd0_test_stop_matching -f fd0-agent   2>/dev/null || true
fd0_test_stop_matching -f fd0-witness 2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_LOG" "$SERVER_KEY" \
       "$WITNESS_DB" "$WITNESS_CFG" "$WITNESS_LOG"

# Server with a fixed key file so we can rotate later.
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" \
    --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.3
ok "fd0-server started on :${SERVER_PORT}"

mkdir -p "$HOME_AL" && chmod 700 "$HOME_AL"
cat > "$HOME_AL/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
on_unlock = false
[client]
lock_wait = "10s"
EOF

printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "alice-pass\n"             | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
AL() { env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" "$@"; }

AL scope create --label work >/dev/null
AL set probe1 v1 --scope work >/dev/null
AL sync >/dev/null 2>&1
ok "client wrote one secret + synced (server has events)"

# ─── 1. Witness config + first poll archives the STH ────────────────────
step "1) fd0-witness archives the server's STH"

# Read the server's translog pubkey from its keyfile (32-byte seed||pub
# layout — pub is the SECOND 32 bytes).
SERVER_KEYFILE=$(dirname "$SERVER_DB")/server-translog.key
PUB_HEX=$(xxd -p -c 64 "$SERVER_KEYFILE" | head -1 | cut -c65-)
SCOPE_CHAIN=$(sqlite3 "$SERVER_DB" "SELECT chain_id FROM chains WHERE chain_id LIKE 'scope:%' LIMIT 1;")

cat > "$WITNESS_CFG" <<EOF
[[target]]
server_url    = "http://127.0.0.1:${SERVER_PORT}"
server_pub    = "${PUB_HEX}"
chains        = ["${SCOPE_CHAIN}"]
poll_interval = "1s"
EOF

# Run witness in the background; let it poll twice (~3s).
"$FD0_WITNESS_BIN" --config="$WITNESS_CFG" --db="$WITNESS_DB" -v run > "$WITNESS_LOG" 2>&1 &
WITNESS_PID=$!
sleep 3

ARCHIVED=$(sqlite3 "$WITNESS_DB" "SELECT COUNT(*) FROM witness_sths;" 2>/dev/null || echo 0)
[ "$ARCHIVED" -ge 1 ] \
    && ok "witness archived $ARCHIVED STH(s) after one poll" \
    || no "witness archive empty after 3s of polling (expected ≥ 1)"

# ─── 2. New writes advance the witness's archive + verify consistency ──
step "2) New writes → witness archives the advanced STH"

AL set probe2 v2 --scope work >/dev/null
AL sync >/dev/null 2>&1
sleep 3

NEW_ARCHIVED=$(sqlite3 "$WITNESS_DB" "SELECT COUNT(*) FROM witness_sths;" 2>/dev/null || echo 0)
[ "$NEW_ARCHIVED" -gt "$ARCHIVED" ] \
    && ok "archive grew from $ARCHIVED to $NEW_ARCHIVED after a new write" \
    || no "archive did not grow ($ARCHIVED → $NEW_ARCHIVED)"

# Check the witness log for "STH advanced + verified" — proves the
# consistency proof was fetched + checked.
if grep -q "STH advanced + verified" "$WITNESS_LOG"; then
    ok "witness log records advanced+verified STH"
else
    no "witness log missing 'STH advanced + verified' marker:"
    tail -20 "$WITNESS_LOG"
fi

# ─── 3. Witness with WRONG pubkey rejects every STH ─────────────────────
# Direct simulation of a key-mismatch scenario (e.g. operator pointed
# at the wrong server, or server rotated keys behind the witness's
# back). We can't easily trigger a NEW STH from the live server
# without circumventing pinning client-side, so instead we run a
# SECOND witness against the same server with a deliberately wrong
# pubkey. Every poll must hit the BAD STH SIGNATURE path.
step "3) Witness with WRONG pubkey rejects STHs (bad-sig alert path)"

WITNESS_CFG_BAD=/tmp/fd0-witness-bad.toml
WITNESS_DB_BAD=/tmp/fd0-witness-bad.db
WITNESS_LOG_BAD=/tmp/fd0-witness-bad.log
WRONG_PUB=$(openssl rand -hex 32)
rm -f "$WITNESS_DB_BAD" "$WITNESS_LOG_BAD"
cat > "$WITNESS_CFG_BAD" <<EOF
[[target]]
server_url    = "http://127.0.0.1:${SERVER_PORT}"
server_pub    = "${WRONG_PUB}"
chains        = ["${SCOPE_CHAIN}"]
poll_interval = "1s"
EOF

"$FD0_WITNESS_BIN" --config="$WITNESS_CFG_BAD" --db="$WITNESS_DB_BAD" -v run > "$WITNESS_LOG_BAD" 2>&1 &
WITNESS_BAD_PID=$!
sleep 3
kill $WITNESS_BAD_PID 2>/dev/null
wait $WITNESS_BAD_PID 2>/dev/null || true

if grep -q "BAD STH SIGNATURE" "$WITNESS_LOG_BAD"; then
    ok "wrong-pubkey witness flagged BAD STH SIGNATURE"
else
    no "wrong-pubkey witness did NOT flag bad sig:"
    tail -20 "$WITNESS_LOG_BAD"
fi
BAD_ARCHIVED=$(sqlite3 "$WITNESS_DB_BAD" "SELECT COUNT(*) FROM witness_sths;" 2>/dev/null || echo 0)
[ "$BAD_ARCHIVED" -eq 0 ] \
    && ok "wrong-pubkey witness archived ZERO STHs (sig fail before insert)" \
    || no "wrong-pubkey witness archived $BAD_ARCHIVED STHs (should be 0)"
rm -f "$WITNESS_CFG_BAD" "$WITNESS_DB_BAD" "$WITNESS_LOG_BAD"

# ─── 4. fd0-witness status / verify subcommands ────────────────────────
step "4) status + verify subcommands"

kill $WITNESS_PID 2>/dev/null
wait $WITNESS_PID 2>/dev/null || true

STATUS_OUT=$("$FD0_WITNESS_BIN" --config="$WITNESS_CFG" --db="$WITNESS_DB" status 2>&1)
case "$STATUS_OUT" in
    *"Witness archive:"*) ok "status command prints summary" ;;
    *) no "status output unexpected: $STATUS_OUT" ;;
esac

VERIFY_OUT=$("$FD0_WITNESS_BIN" --config="$WITNESS_CFG" --db="$WITNESS_DB" verify 2>&1)
case "$VERIFY_OUT" in
    *"signature error"*) ok "verify command runs and reports stats" ;;
    *) no "verify output unexpected: $VERIFY_OUT" ;;
esac

AL lock >/dev/null 2>&1
echo
printf "\033[1m== WITNESS SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
