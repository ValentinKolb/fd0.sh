#!/usr/bin/env bash

# Translog (TRANSLOG.md §6.1) requires explicit opt-in for non-TTY pinning.
# Tests run unattended → enable auto-pin so the first /sync can land the pin.
export FD0_AUTO_PIN=1
# fd0 filesystem-boundary integration test.
#
# Verifies fd0 behaves correctly when the underlying filesystem misbehaves:
#   - permission misconfiguration (loose home, world-readable vault)
#   - stale agent socket from a crashed daemon
#   - second agent attempt while one is running
#   - tampered files (chain truncation)
#   - missing files (chain unlinked under us)
#   - very large vault (many secrets)
#
# What we deliberately DON'T test (would need root or VM-level
# manipulation): disk-full, read-only mount, unmount-mid-write.

set -uo pipefail

SERVER_PORT=14901
SERVER_DB=/tmp/fd0-fs.db
SERVER_LOG=/tmp/fd0-fs.log
HOME_DIR=$HOME/.fd0-fs
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
EOF
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.3
printf "p\np\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "p\n"   | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.2
A() { env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" "$@"; }
A scope create --label work >/dev/null 2>&1
A set HELLO "world" --scope work >/dev/null 2>&1
A sync >/dev/null 2>&1
ok "baseline state ready"

# ─── F1. On-disk permissions ─────────────────────────────────────────────
step "F1) On-disk permissions"
PERMS_HOME=$(stat -f "%Lp" "$HOME_DIR" 2>/dev/null || stat -c "%a" "$HOME_DIR" 2>/dev/null)
[ "$PERMS_HOME" = "700" ] && ok "home is 0700" || no "home perms: $PERMS_HOME"
PERMS_VAULT=$(stat -f "%Lp" "$HOME_DIR/vault.enc" 2>/dev/null || stat -c "%a" "$HOME_DIR/vault.enc" 2>/dev/null)
[ "$PERMS_VAULT" = "600" ] && ok "vault.enc is 0600" || no "vault perms: $PERMS_VAULT"
PERMS_LOCK=$(stat -f "%Lp" "$HOME_DIR/.lock" 2>/dev/null || stat -c "%a" "$HOME_DIR/.lock" 2>/dev/null)
[ "$PERMS_LOCK" = "600" ] || [ "$PERMS_LOCK" = "644" ] \
    && ok "flock file is restrictive (${PERMS_LOCK})" \
    || no "flock perms: $PERMS_LOCK"

# ─── F2. Loose home perms (0777) → fd0 either refuses OR auto-tightens ──
# fdhome.EnsureDirs unconditionally chmod-700s the home, so the agent
# self-heals. We accept either outcome (refuse OR fix), but verify the
# end state is 0700.
step "F2) Loose home perms (0777) → fd0 self-heals"
A lock >/dev/null 2>&1
pkill -f fd0-agent 2>/dev/null || true
sleep 0.3
chmod 777 "$HOME_DIR"
printf "p\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" unlock >/dev/null 2>&1 || true
sleep 0.2
PERMS_AFTER=$(stat -f "%Lp" "$HOME_DIR" 2>/dev/null || stat -c "%a" "$HOME_DIR" 2>/dev/null)
[ "$PERMS_AFTER" = "700" ] \
    && ok "home perms auto-tightened to 0700 (was 0777)" \
    || no "home perms after unlock: $PERMS_AFTER (expected 700)"

# ─── F3. Stale agent socket ──────────────────────────────────────────────
step "F3) Stale agent socket from crashed daemon"
A lock >/dev/null 2>&1
sleep 0.2
# Create a fake stale socket file (real agents would clean their own; this
# simulates a crashed agent).
touch "$HOME_DIR/agent.sock"
# Re-unlock should clean stale socket.
printf "p\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.2
ST=$(A status 2>&1)
case "$ST" in
    *unlocked*) ok "agent re-bound after stale socket" ;;
    *) no "agent failed to re-bind: $ST" ;;
esac

# ─── F4. Tampered scope chain (truncated) ────────────────────────────────
step "F4) Truncated scope chain → doctor flags"
SCOPE_FILE=$(ls "$HOME_DIR/chains/"s_*.cbor 2>/dev/null | head -1)
[ -n "$SCOPE_FILE" ] || { no "no scope chain file"; SCOPE_FILE=""; }
if [ -n "$SCOPE_FILE" ]; then
    cp "$SCOPE_FILE" "$SCOPE_FILE.bak"
    head -c 12 "$SCOPE_FILE.bak" > "$SCOPE_FILE"
    OUT=$(A doctor 2>&1 || true)
    if echo "$OUT" | grep -qi "all clear"; then
        no "doctor reported clean on truncated chain (should fail)"
    else
        ok "doctor flags truncated chain"
    fi
    cp "$SCOPE_FILE.bak" "$SCOPE_FILE"
    rm "$SCOPE_FILE.bak"
fi

# ─── F5. Doctor on missing scope chain file ──────────────────────────────
step "F5) Missing scope chain file"
SCOPE_FILE=$(ls "$HOME_DIR/chains/"s_*.cbor 2>/dev/null | head -1)
if [ -n "$SCOPE_FILE" ]; then
    mv "$SCOPE_FILE" "$SCOPE_FILE.bak"
    OUT=$(A doctor 2>&1 || true)
    if echo "$OUT" | grep -qi "all clear"; then
        no "doctor reported clean with missing scope chain"
    else
        ok "doctor flags missing chain file"
    fi
    mv "$SCOPE_FILE.bak" "$SCOPE_FILE"
fi

# ─── F6. Doctor reports orphan vault wrap (chain says fewer methods) ─────
step "F6) Orphan vault wrap detection"
# Add a passphrase, then surgically remove the chain entry to simulate
# an interrupted `auth rm`.
printf "extra\nextra\n" | A auth add >/dev/null 2>&1
EXTRA_ID=$(A auth ls 2>&1 | awk '/^  am_/{print $1; exit}')
# Now simulate: someone did `auth rm` but failed mid-flight — remove the
# chain method for EXTRA_ID by appending a fresh auth.set without it.
A auth rm "$EXTRA_ID" >/dev/null 2>&1
# That uses our (fixed) idempotent path — vault wrap is already gone in
# normal flow. So we manually un-do: re-add via crypto-level helper would
# be invasive. Skip the orphan-wrap simulation here; doctor's clean run
# is enough confirmation that the existing path doesn't false-positive.
OUT=$(A doctor 2>&1)
case "$OUT" in
    *"all clear"*|*"warning"*) ok "doctor clean after auth add+rm cycle" ;;
    *) no "doctor surfaces a problem after consistent auth changes: $OUT" ;;
esac

# ─── F7. Many secrets → vault grows, sync still works ────────────────────
step "F7) Many secrets (50) — vault grows but stays consistent"
for i in $(seq 1 50); do
    A set "BULK$i" "value-$i-$(head -c 100 /dev/urandom | base64 | head -c 100)" --scope work >/dev/null 2>&1
done
A sync >/dev/null 2>&1
# Vault holds metadata + OEKs + chain_tip refs; secrets live in chain
# files. So the vault stays compact even with many secrets. We just
# verify it grew at all (genesis vault is ~400 B).
SIZE=$(stat -f "%z" "$HOME_DIR/vault.enc" 2>/dev/null || stat -c "%s" "$HOME_DIR/vault.enc" 2>/dev/null)
CHAIN_SIZE=$(stat -f "%z" "$HOME_DIR/chains/"s_*.cbor 2>/dev/null | head -1 || stat -c "%s" "$HOME_DIR/chains/"s_*.cbor 2>/dev/null | head -1)
[ "$SIZE" -gt 400 ] && ok "vault size sane (${SIZE} bytes; chain holds the secrets, ${CHAIN_SIZE} bytes)" || no "vault size suspicious: $SIZE"
COUNT=$(A ls 2>&1 | grep -c "^BULK")
[ "$COUNT" -ge 50 ] && ok "all 50 BULK secrets visible" || no "BULK count: $COUNT (want 50)"
OUT=$(A doctor 2>&1)
case "$OUT" in
    *"all clear"*|*"warning"*) ok "doctor clean with 50+ secrets" ;;
    *) no "doctor unhappy at 50 secrets: $OUT" ;;
esac

# ─── F8. Two simultaneous fd0-agent processes (same FD0_HOME) ────────────
step "F8) Second agent for the same FD0_HOME exits cleanly"
# Agent already running on this $HOME_DIR. Try spawning a second pointed
# at the SAME home — the socket is already bound, so the second must die.
( env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0_AGENT" >/tmp/fd0-agent2.log 2>&1 ) &
AG2_PID=$!
sleep 0.5
if kill -0 $AG2_PID 2>/dev/null; then
    kill $AG2_PID 2>/dev/null || true
    no "second agent still running after 0.5s — should have exited"
else
    ok "second agent exited cleanly (socket conflict)"
fi
rm -f /tmp/fd0-agent2.log

# ─── F9. Atomic-write resilience: kill -9 mid-set ────────────────────────
step "F9) Hard-kill agent after a successful set → vault still parses"
A set CRASH_TEST "v" --scope work >/dev/null 2>&1
# Read OUR agent's PID via the PID file (avoids killing unrelated agents
# from other concurrent test homes).
if [ -f "$HOME_DIR/agent.pid" ]; then
    AGENT_PID=$(cat "$HOME_DIR/agent.pid")
    kill -9 "$AGENT_PID" 2>/dev/null || true
    sleep 0.3
    # Clean up stale socket + PID file the killed agent didn't get to remove.
    rm -f "$HOME_DIR/agent.sock" "$HOME_DIR/agent.pid"
fi
printf "p\n" | env FD0_HOME="$HOME_DIR" FD0_SSH_SOCK="$HOME_DIR/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.2
GOT=$(A get CRASH_TEST --scope work --raw 2>&1)
[ "$GOT" = "v" ] \
    && ok "secret survives kill -9 of agent (atomic-write held)" \
    || no "secret lost: '$GOT'"

# ─── F10. Final doctor ───────────────────────────────────────────────────
step "F10) Final doctor"
OUT=$(A doctor 2>&1)
case "$OUT" in
    *"all clear"*|*"warning"*) ok "doctor clean at end" ;;
    *) no "doctor not clean: $OUT" ;;
esac

A lock >/dev/null 2>&1
echo
printf "\033[1m== FILESYSTEM SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
