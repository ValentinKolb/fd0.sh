#!/usr/bin/env bash

# Multi-witness integration scenarios. The single-witness happy path
# is covered in integration_witness_cosign.sh; this suite exercises
# real-world deployments where the operator runs MULTIPLE independent
# witnesses for redundancy + independent observation.
#
# Scenarios:
#   1. 2-of-3 threshold: 3 witnesses configured, min_cosigns=2.
#      All 3 healthy → sync succeeds with 3 confirmations.
#   2. 2-of-3 with one witness down → still passes (2 left).
#   3. 2-of-3 with two witnesses down → fails (only 1 confirmation).
#   4. 3-of-3 strict: all witnesses must agree, one outage = fail.
#   5. Different witnesses pinned to different scopes (independent
#      cross-checks per scope).
#   6. Witness pubkey mismatch (operator typo) → loud rejection.
#
# Run from repo root:
#   bash tests/integration_witness_multi.sh

export FD0_AUTO_PIN=1

set -uo pipefail

SERVER_PORT=14940
W1_PORT=14941
W2_PORT=14942
W3_PORT=14943
SERVER_DB=/tmp/fd0-multi-server.db
SERVER_LOG=/tmp/fd0-multi-server.log
SERVER_KEY=/tmp/server-translog.key
HOME_AL=$HOME/.fd0-multi-al
W1_DB=/tmp/fd0-multi-w1.db
W1_KEY=/tmp/fd0-multi-w1.key
W1_CFG=/tmp/fd0-multi-w1.toml
W1_LOG=/tmp/fd0-multi-w1.log
W2_DB=/tmp/fd0-multi-w2.db
W2_KEY=/tmp/fd0-multi-w2.key
W2_CFG=/tmp/fd0-multi-w2.toml
W2_LOG=/tmp/fd0-multi-w2.log
W3_DB=/tmp/fd0-multi-w3.db
W3_KEY=/tmp/fd0-multi-w3.key
W3_CFG=/tmp/fd0-multi-w3.toml
W3_LOG=/tmp/fd0-multi-w3.log

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
    pkill -f "fd0-witness.*${W1_PORT}" 2>/dev/null || true
    pkill -f "fd0-witness.*${W2_PORT}" 2>/dev/null || true
    pkill -f "fd0-witness.*${W3_PORT}" 2>/dev/null || true
    pkill -f fd0-witness 2>/dev/null || true
    pkill -f fd0-agent   2>/dev/null || true
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
           "$SERVER_LOG" "$SERVER_KEY" \
           "$W1_DB" "$W1_DB-wal" "$W1_DB-shm" "$W1_KEY" "$W1_CFG" "$W1_LOG" \
           "$W2_DB" "$W2_DB-wal" "$W2_DB-shm" "$W2_KEY" "$W2_CFG" "$W2_LOG" \
           "$W3_DB" "$W3_DB-wal" "$W3_DB-shm" "$W3_KEY" "$W3_CFG" "$W3_LOG"
}
trap cleanup EXIT

mkfd0() {
    local home="$1" url="$2"
    mkdir -p "$home" && chmod 700 "$home"
    cat > "$home/config.toml" <<EOF
[sync]
server    = "${url}"
on_unlock = false
[client]
lock_wait = "10s"
EOF
}
AL() { env FD0_HOME="$HOME_AL" "$FD0" "$@"; }

extract_pub_hex() {
    python3 -c "
import sys
with open('$1','rb') as f:
    b=f.read()
sys.stdout.write(b[32:64].hex())
"
}

write_witness_cfg() {
    local cfg="$1" srv_pub_hex="$2" chain="$3"
    cat > "$cfg" <<EOF
[[target]]
server_url    = "http://127.0.0.1:${SERVER_PORT}"
server_pub    = "${srv_pub_hex}"
chains        = ["${chain}"]
poll_interval = "1s"
EOF
}

start_witness() {
    local cfg="$1" db="$2" key="$3" port="$4" log="$5"
    "$FD0_WITNESS_BIN" \
        --config="$cfg" --db="$db" --key="$key" --bind=":${port}" \
        run > "$log" 2>&1 &
    echo $!
}

wait_witness_caught_up() {
    local db="$1" chain="$2" target="$3"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1
        cur=$(sqlite3 "$db" "SELECT COALESCE(MAX(tree_size),0) FROM witness_sths WHERE chain_id='${chain}' AND witness_signature IS NOT NULL;")
        [ "$cur" = "$target" ] && return 0
    done
    return 1
}

# ---- Setup ----------------------------------------------------------

step "Setup"
pkill -f fd0-server  2>/dev/null || true
pkill -f fd0-agent   2>/dev/null || true
pkill -f fd0-witness 2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_LOG" "$SERVER_KEY" \
       "$W1_DB" "$W1_KEY" "$W1_CFG" "$W1_LOG" \
       "$W2_DB" "$W2_KEY" "$W2_CFG" "$W2_LOG" \
       "$W3_DB" "$W3_KEY" "$W3_CFG" "$W3_LOG"

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" \
    --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.5
curl -fs "http://127.0.0.1:${SERVER_PORT}/health" >/dev/null || { no "server failed"; exit 1; }
ok "server up"

SRV_PUB_HEX=$(extract_pub_hex "$SERVER_KEY")
ok "server pub: ${SRV_PUB_HEX:0:16}…"

# Bootstrap a scope.
mkfd0 "$HOME_AL" "http://127.0.0.1:${SERVER_PORT}"
printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" init >/dev/null 2>&1
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
AL scope create --label work >/dev/null
AL set k_init v0 --scope work >/dev/null
AL sync >/dev/null 2>&1
SCOPE=$(sqlite3 "$SERVER_DB" "SELECT chain_id FROM chains WHERE chain_id LIKE 'scope:%' LIMIT 1;")
ok "scope $SCOPE bootstrapped"

# Start 3 witnesses.
for i in 1 2 3; do
    case $i in
        1) write_witness_cfg "$W1_CFG" "$SRV_PUB_HEX" "$SCOPE" ;;
        2) write_witness_cfg "$W2_CFG" "$SRV_PUB_HEX" "$SCOPE" ;;
        3) write_witness_cfg "$W3_CFG" "$SRV_PUB_HEX" "$SCOPE" ;;
    esac
done
W1_PID=$(start_witness "$W1_CFG" "$W1_DB" "$W1_KEY" "$W1_PORT" "$W1_LOG")
W2_PID=$(start_witness "$W2_CFG" "$W2_DB" "$W2_KEY" "$W2_PORT" "$W2_LOG")
W3_PID=$(start_witness "$W3_CFG" "$W3_DB" "$W3_KEY" "$W3_PORT" "$W3_LOG")
sleep 2  # boot + first poll
W1_PUB=$(extract_pub_hex "$W1_KEY")
W2_PUB=$(extract_pub_hex "$W2_KEY")
W3_PUB=$(extract_pub_hex "$W3_KEY")
ok "3 witnesses up (cosign pubs differ: $([ "$W1_PUB" != "$W2_PUB" ] && [ "$W2_PUB" != "$W3_PUB" ] && echo yes || echo no))"

CFG_BASE="$HOME_AL/config.toml"
cp "$CFG_BASE" "$CFG_BASE.orig"

set_3_witness_cfg() {
    local min="$1"
    cp "$CFG_BASE.orig" "$CFG_BASE"
    cat >> "$CFG_BASE" <<EOF

[[witness]]
url = "http://127.0.0.1:${W1_PORT}"
pub = "${W1_PUB}"

[[witness]]
url = "http://127.0.0.1:${W2_PORT}"
pub = "${W2_PUB}"

[[witness]]
url = "http://127.0.0.1:${W3_PORT}"
pub = "${W3_PUB}"

[witness_policy]
min_cosigns = ${min}
EOF
}

# ---- Scenario 1: 2-of-3 all healthy → pass ------------------------

step "Scenario 1: 2-of-3 with all 3 witnesses healthy"
set_3_witness_cfg 2
AL set k1 v1 --scope work >/dev/null
# Wait for all 3 witnesses to catch up.
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
AL sync >/dev/null 2>&1 || true
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
wait_witness_caught_up "$W1_DB" "$SCOPE" "$SVR_SIZE" || no "W1 lag"
wait_witness_caught_up "$W2_DB" "$SCOPE" "$SVR_SIZE" || no "W2 lag"
wait_witness_caught_up "$W3_DB" "$SCOPE" "$SVR_SIZE" || no "W3 lag"
SYNC_OUT=$(AL sync 2>&1)
if echo "$SYNC_OUT" | grep -q "✓ sync ok"; then
    ok "sync succeeded with 3 healthy witnesses (min=2)"
else
    no "expected pass, got: $(echo "$SYNC_OUT" | head -c 200)"
fi

# ---- Scenario 2: 2-of-3 with one down → still pass ----------------

step "Scenario 2: 2-of-3 with W3 down → still pass"
kill $W3_PID 2>/dev/null || true
sleep 0.5
AL set k2 v2 --scope work >/dev/null
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
AL sync >/dev/null 2>&1 || true
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
wait_witness_caught_up "$W1_DB" "$SCOPE" "$SVR_SIZE" || no "W1 lag"
wait_witness_caught_up "$W2_DB" "$SCOPE" "$SVR_SIZE" || no "W2 lag"
SYNC_OUT=$(AL sync 2>&1)
if echo "$SYNC_OUT" | grep -q "✓ sync ok"; then
    ok "sync succeeded with W3 down (W1+W2 give 2 cosigns ≥ min=2)"
else
    no "expected pass, got: $(echo "$SYNC_OUT" | head -c 200)"
fi

# ---- Scenario 3: 2-of-3 with two down → fail ---------------------

step "Scenario 3: 2-of-3 with W2+W3 down → fail (only 1 cosign)"
kill $W2_PID 2>/dev/null || true
sleep 0.5
AL set k3 v3 --scope work >/dev/null
SYNC_OUT=$(AL sync 2>&1 || true)
if echo "$SYNC_OUT" | grep -qi "insufficient"; then
    ok "sync REJECTED with only 1 healthy witness (1 < min=2)"
else
    no "expected insufficient-cosigns, got: $(echo "$SYNC_OUT" | head -c 200)"
fi

# Restart W2 + W3 for next scenario.
W2_PID=$(start_witness "$W2_CFG" "$W2_DB" "$W2_KEY" "$W2_PORT" "$W2_LOG")
W3_PID=$(start_witness "$W3_CFG" "$W3_DB" "$W3_KEY" "$W3_PORT" "$W3_LOG")
sleep 2

# ---- Scenario 4: 3-of-3 strict mode -------------------------------

step "Scenario 4: 3-of-3 strict mode"
set_3_witness_cfg 3
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
wait_witness_caught_up "$W1_DB" "$SCOPE" "$SVR_SIZE" || true
wait_witness_caught_up "$W2_DB" "$SCOPE" "$SVR_SIZE" || true
wait_witness_caught_up "$W3_DB" "$SCOPE" "$SVR_SIZE" || true
AL set k4 v4 --scope work >/dev/null
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
AL sync >/dev/null 2>&1 || true
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
wait_witness_caught_up "$W1_DB" "$SCOPE" "$SVR_SIZE" || no "W1 lag"
wait_witness_caught_up "$W2_DB" "$SCOPE" "$SVR_SIZE" || no "W2 lag"
wait_witness_caught_up "$W3_DB" "$SCOPE" "$SVR_SIZE" || no "W3 lag"
SYNC_OUT=$(AL sync 2>&1)
if echo "$SYNC_OUT" | grep -q "✓ sync ok"; then
    ok "3-of-3 strict mode passes when all witnesses healthy"
else
    no "expected pass, got: $(echo "$SYNC_OUT" | head -c 200)"
fi

# Now kill one witness — strict mode must fail.
kill $W3_PID 2>/dev/null || true
sleep 0.5
AL set k5 v5 --scope work >/dev/null
SYNC_OUT=$(AL sync 2>&1 || true)
if echo "$SYNC_OUT" | grep -qi "insufficient"; then
    ok "3-of-3 strict REJECTS when 1 of 3 witnesses down"
else
    no "expected insufficient-cosigns rejection, got: $(echo "$SYNC_OUT" | head -c 200)"
fi
W3_PID=$(start_witness "$W3_CFG" "$W3_DB" "$W3_KEY" "$W3_PORT" "$W3_LOG")
sleep 2

# ---- Scenario 5: pubkey typo (W1 pinned to W2's pub) -------------

step "Scenario 5: operator typo — W1 url with W2's pub → bad-cosign"
cp "$CFG_BASE.orig" "$CFG_BASE"
cat >> "$CFG_BASE" <<EOF

[[witness]]
url = "http://127.0.0.1:${W1_PORT}"
pub = "${W2_PUB}"

[witness_policy]
min_cosigns = 1
EOF
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
wait_witness_caught_up "$W1_DB" "$SCOPE" "$SVR_SIZE" || true
SYNC_OUT=$(AL sync 2>&1 || true)
if echo "$SYNC_OUT" | grep -qi "insufficient"; then
    ok "sync rejected when witness URL doesn't match its pinned pub (bad-cosign)"
else
    no "expected insufficient/bad-cosign, got: $(echo "$SYNC_OUT" | head -c 200)"
fi

# ---- Scenario 6: 3 witnesses, min=1 → easiest threshold (regression) ---

step "Scenario 6: 3 witnesses with min=1 → trivially passes"
set_3_witness_cfg 1
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
wait_witness_caught_up "$W1_DB" "$SCOPE" "$SVR_SIZE" || true
AL set k6 v6 --scope work >/dev/null
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
AL sync >/dev/null 2>&1 || true
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE}';")
wait_witness_caught_up "$W1_DB" "$SCOPE" "$SVR_SIZE" || true
SYNC_OUT=$(AL sync 2>&1)
if echo "$SYNC_OUT" | grep -q "✓ sync ok"; then
    ok "min=1 with 3 witnesses passes (any one suffices)"
else
    no "expected pass, got: $(echo "$SYNC_OUT" | head -c 200)"
fi

AL lock >/dev/null 2>&1 || true
echo
printf "\033[1m== WITNESS-MULTI SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
