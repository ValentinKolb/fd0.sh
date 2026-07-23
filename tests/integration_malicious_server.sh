#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

export FD0_AUTO_PIN=1

# fd0 malicious-server integration test. Sends Alice's traffic
# through fd0-test-mitm (a TEST-ONLY HTTP proxy) which mutates
# server responses according to a per-scenario mode. Verifies the
# client's translog verifier hard-fails for every attack mode while
# accepting the passthrough baseline.
#
# Setup: Bob (DIRECT) creates a shared scope and adds Alice. Alice
# always goes through the proxy. In each scenario, Bob writes a new
# secret directly; Alice syncs through the proxy and the verifier
# decides.
#
# Modes:
#
#   passthrough      — sanity: client works through proxy unchanged.
#   tamper-sth       — flip a byte in the STH signature.
#   tamper-inclusion — flip a byte in inclusion proof audit_path.
#   tamper-consistency — flip a byte in consistency_proof.nodes.
#   drop-sth         — strip mandatory STH from /sync responses.
#   drop-inclusion   — strip mandatory inclusion proofs.
#   swap-chain-id    — rewrite STH chain_id (also breaks signature).
#   bad-leaf-index   — bump leaf_index in inclusion proof.
#
# (replay-stale lives in the proxy too but only intercepts /v1/sth/,
# which the regular client never hits — it's exercised in the
# witness suite, not here.)
#
# Run from repo root:
#   bash tests/integration_malicious_server.sh

set -uo pipefail

SERVER_PORT=15012
PROXY_PORT=15013
SERVER_DB=/tmp/fd0-mitm-server.db
SERVER_LOG=/tmp/fd0-mitm-server.log
PROXY_LOG=/tmp/fd0-mitm-proxy.log
HOME_AL=$HOME/.fd0-mitm-al   # Alice — always goes through proxy
HOME_BL=$HOME/.fd0-mitm-bl   # Bob — connects directly to server

FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}
FD0_MITM_BIN=${FD0_MITM:-$HOME/go/bin/fd0-test-mitm}

PASS=0
FAIL=0
SEQ=0
phase() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()    { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()    { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

cleanup() {
    fd0_test_stop_matching -f fd0-test-mitm 2>/dev/null || true
    fd0_test_stop_matching -f fd0-agent     2>/dev/null || true
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$HOME_AL" "$HOME_BL" "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
           "$SERVER_LOG" "$PROXY_LOG"
}
trap cleanup EXIT

mkfd0() {
    local home="$1"
    local server_url="$2"
    mkdir -p "$home" && chmod 700 "$home"
    cat > "$home/config.toml" <<EOF
[sync]
server    = "${server_url}"
on_unlock = false
[client]
lock_wait = "10s"
EOF
}

AL() { env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" "$@"; }
BL() { env FD0_HOME="$HOME_BL" FD0_SSH_SOCK="$HOME_BL/ssh.sock" "$FD0" "$@"; }

start_proxy() {
    local mode="$1"
    fd0_test_stop_matching -f fd0-test-mitm 2>/dev/null || true
    sleep 0.2
    "$FD0_MITM_BIN" \
        --listen=":${PROXY_PORT}" \
        --upstream="http://127.0.0.1:${SERVER_PORT}" \
        --mode="$mode" \
        > "$PROXY_LOG" 2>&1 &
    PROXY_PID=$!
    sleep 0.4
}

# Run one attack scenario:
#   $1 = mode
#   $2 = expected outcome ("accept" or "reject")
#   $3 = optional substring required in the rejection error
#
# Bob writes a fresh secret directly to the server, then Alice
# syncs through the proxy. The proxy mutates Bob's events on the
# wire. Alice's verifier decides.
run_scenario() {
    local mode="$1"
    local expected="$2"
    local needle="${3:-}"
    # expected_path: which proxy path the APPLIED log should
    # mention. Defaults to /sync since most modes target the
    # inline-proof envelope; replay-stale targets /v1/sth/.
    local expected_path="${4:-/sync}"

    SEQ=$((SEQ + 1))
    local key="MITM_K${SEQ}"
    local val="malicious-test-${SEQ}"
    # Bob's write + sync MUST succeed — otherwise the scenario tests
    # nothing (Alice would just be syncing stale state).
    if ! BL set "$key" "$val" --scope work >/dev/null 2>&1; then
        no "[mode=$mode] BL set failed before scenario — test invalid"
        return
    fi
    if ! BL sync >/dev/null 2>&1; then
        no "[mode=$mode] BL sync failed before scenario — test invalid"
        return
    fi

    start_proxy "$mode"
    AL sync >/dev/null 2>"$HOME_AL/lastsync.err"
    local rc=$?
    SYNC_OUT=$(cat "$HOME_AL/lastsync.err" 2>/dev/null)

    case "$expected" in
        accept)
            # rc=0 is the contract: client sync exited successfully.
            if [ $rc -ne 0 ]; then
                no "[mode=$mode] client sync rc=$rc (expected: accept): $(echo "$SYNC_OUT" | head -c 250)"
                kill -KILL $PROXY_PID 2>/dev/null || true; wait $PROXY_PID 2>/dev/null || true
                sleep 0.2
                return
            fi
            # Stronger: the value must actually be readable now.
            if [ "$(AL get "$key" --scope work --raw 2>/dev/null)" = "$val" ]; then
                ok "[mode=$mode] sync succeeded AND value reads back correctly"
            else
                no "[mode=$mode] sync claimed ok but value not readable"
            fi
            ;;
        reject)
            if [ $rc -eq 0 ]; then
                no "[mode=$mode] client sync rc=0 but should have rejected"
                kill -KILL $PROXY_PID 2>/dev/null || true; wait $PROXY_PID 2>/dev/null || true
                sleep 0.2
                return
            fi
            # Verify proxy ACTUALLY mutated AT THE EXPECTED PATH.
            # Without the path constraint, a mode that mutates
            # /v1/sth/ (which Alice's sync never hits) would log
            # APPLIED but not affect the request under test.
            if ! grep -q "APPLIED mode=$mode path=$expected_path" "$PROXY_LOG"; then
                no "[mode=$mode] proxy never APPLIED at $expected_path (test invalid). log tail:"
                tail -5 "$PROXY_LOG" | sed 's/^/    /'
                kill -KILL $PROXY_PID 2>/dev/null || true; wait $PROXY_PID 2>/dev/null || true
                sleep 0.2
                return
            fi
            # Verify the secret did NOT leak into Alice's view.
            if [ -n "$(AL get "$key" --scope work --raw 2>/dev/null)" ]; then
                no "[mode=$mode] reject was claimed but secret IS readable on Alice"
                kill -KILL $PROXY_PID 2>/dev/null || true; wait $PROXY_PID 2>/dev/null || true
                sleep 0.2
                return
            fi
            # Verify error message matches expected pattern (when given).
            if [ -n "$needle" ]; then
                if echo "$SYNC_OUT" | grep -qiF "$needle"; then
                    ok "[mode=$mode] rejected (rc=$rc) + APPLIED at $expected_path + secret hidden + pattern '$needle' matched"
                else
                    no "[mode=$mode] rejected but pattern '$needle' missing: $(echo "$SYNC_OUT" | head -c 300)"
                fi
            else
                ok "[mode=$mode] rejected (rc=$rc) + APPLIED at $expected_path + secret hidden"
            fi
            ;;
    esac
    kill -KILL $PROXY_PID 2>/dev/null || true; wait $PROXY_PID 2>/dev/null || true
    sleep 0.2
}

phase "Setup: server, proxy in passthrough, Bob bootstraps shared scope"
fd0_test_stop_matching -f fd0-server     2>/dev/null || true
fd0_test_stop_matching -f fd0-agent      2>/dev/null || true
fd0_test_stop_matching -f fd0-test-mitm  2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$HOME_BL" "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
       "$SERVER_LOG" "$PROXY_LOG"

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.3
ok "fd0-server up on :${SERVER_PORT}"

# Both clients init. AL goes through proxy from the start so her
# pin is for the proxy URL throughout. BL connects direct.
mkfd0 "$HOME_BL" "http://127.0.0.1:${SERVER_PORT}"
mkfd0 "$HOME_AL" "http://127.0.0.1:${PROXY_PORT}"
printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "bob-pass\nbob-pass\n"     | env FD0_HOME="$HOME_BL" FD0_SSH_SOCK="$HOME_BL/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" unlock >/dev/null 2>&1
printf "bob-pass\n"   | env FD0_HOME="$HOME_BL" FD0_SSH_SOCK="$HOME_BL/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.3

# Card exchange.
AC=$(AL card export); BC=$(BL card export)
AL card import "$BC" --label bob   --yes >/dev/null
BL card import "$AC" --label alice --yes >/dev/null

# Bob creates the scope and adds Alice. The proxy is launched in
# passthrough so AL's first sync (which establishes the pin) gets
# a clean response.
start_proxy passthrough
BL scope create --label work >/dev/null
BL scope add-member alice --scope work >/dev/null
BL set seed1 v1 --scope work >/dev/null
BL sync >/dev/null 2>&1
sleep 0.3
AL sync >/dev/null 2>&1   # discovers + pins through passthrough proxy
AL sync >/dev/null 2>&1
sleep 0.3
GOT=$(AL get seed1 --scope work --raw 2>/dev/null)
if [ "$GOT" = "v1" ]; then
    ok "Alice pinned proxy + discovered shared scope through passthrough"
else
    no "Alice did NOT discover the scope: got '$GOT'"
fi
fd0_test_stop_matching -f fd0-test-mitm 2>/dev/null || true
sleep 0.2

phase "Scenario 1: passthrough — baseline"
run_scenario passthrough accept

phase "Scenario 2: tamper-sth — STH signature flipped"
run_scenario tamper-sth reject "STH signature"

phase "Scenario 3: tamper-inclusion — inclusion proof flipped"
run_scenario tamper-inclusion reject "inclusion"

phase "Scenario 4: tamper-consistency — consistency proof flipped"
run_scenario tamper-consistency reject "consistency"

phase "Scenario 5: drop-sth — STH stripped"
run_scenario drop-sth reject "missing"

phase "Scenario 6: drop-inclusion — inclusion proofs stripped"
run_scenario drop-inclusion reject "inclusion"

phase "Scenario 7: swap-chain-id — STH chain_id rewritten (sig + binding fail)"
# Hits VerifyTranslogResponse's chain_id binding check OR the
# upstream signature check, depending on order. Either way the
# client refuses.
run_scenario swap-chain-id reject ""

phase "Scenario 8: bad-leaf-index — inclusion proof claims wrong leaf"
# Proof is otherwise valid; only leaf_index is bumped. Catches
# the leaf_index match check we added to VerifyTranslogResponse.
run_scenario bad-leaf-index reject "leaf_index"

# NOTE: replay-stale (proxy freezes /v1/sth/) is NOT exercised here
# because the regular client sync only hits /sync, not /v1/sth/.
# That path is meaningful for witnesses; coverage lives in
# integration_witness.sh — adding it here would just be a no-op
# pretending to be an attack (codex flagged this trap).

AL lock >/dev/null 2>&1 || true
BL lock >/dev/null 2>&1 || true
echo
printf "\033[1m== MALICIOUS-SERVER SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
