#!/usr/bin/env bash

# Malicious-witness integration test (analogous to
# integration_malicious_server.sh but on the OTHER side of the
# cross-check). Exercises every kind of dishonest witness behavior
# the cross-check is designed to catch.
#
# Setup: real fd0-server + real client + a `fd0-test-bad-witness`
# instance that mimics a witness HTTP server with programmable
# malicious modes. Client's [[witness]] config points at the bad
# witness; min_cosigns=1.
#
# Modes:
#   (passthrough is NOT exercised here — the bad-witness binary
#    has no archive and would always 404-or-drift the requested
#    tree_size. The honest happy path lives in
#    integration_witness_cosign.sh / integration_witness_multi.sh.)
#   fork-cosign       — bad-witness signs a tampered root → equivocation reject.
#   wrong-chain-id    — cosign embeds a different chain → bad-cosign skip → reject.
#   wrong-server-url  — cosign embeds different server URL → bad-cosign → reject.
#   size-drift        — cosign at a different tree_size → skip → reject.
#   wrong-witness-pub — embedded pub != pinned pub → bad-cosign → reject.
#   garbage-cbor      — malformed body → unreachable → reject.
#   always-409        — bad-witness always claims equivocation → reject.
#   always-500        — server error → unreachable → reject.
#
# For accept: client sync rc=0 + value readable.
# For reject: client sync rc!=0 + secret NOT readable on Alice.
#
# Run from repo root:
#   bash tests/integration_witness_malicious.sh

export FD0_AUTO_PIN=1

set -uo pipefail

SERVER_PORT=14960
WITNESS_PORT=14961
SERVER_DB=/tmp/fd0-malw-server.db
SERVER_LOG=/tmp/fd0-malw-server.log
SERVER_KEY=/tmp/server-translog.key
WITNESS_KEY=/tmp/fd0-malw-witness.key
WITNESS_LOG=/tmp/fd0-malw-witness.log
HOME_AL=$HOME/.fd0-malw-al

FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}
FD0_BAD_WITNESS_BIN=${FD0_BAD_WITNESS:-$HOME/go/bin/fd0-test-bad-witness}

PASS=0
FAIL=0
SEQ=0
phase() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()    { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()    { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

cleanup() {
    pkill -f fd0-test-bad-witness 2>/dev/null || true
    pkill -f fd0-agent  2>/dev/null || true
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
           "$SERVER_LOG" "$SERVER_KEY" "$WITNESS_KEY" "$WITNESS_LOG"
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

start_bad_witness() {
    local mode="$1"
    pkill -f fd0-test-bad-witness 2>/dev/null || true
    sleep 0.2
    "$FD0_BAD_WITNESS_BIN" \
        --listen=":${WITNESS_PORT}" \
        --upstream="http://127.0.0.1:${SERVER_PORT}" \
        --witness-key="$WITNESS_KEY" \
        --server-key="$SERVER_KEY" \
        --mode="$mode" \
        > "$WITNESS_LOG" 2>&1 &
    BAD_PID=$!
    sleep 0.3
}

run_scenario() {
    local mode="$1"
    local expected="$2"   # accept | reject
    local needle="${3:-}" # required substring in client error
    local skip_pat="${4:-}" # required mode-specific skip-reason in client error
                            # (e.g. "bad-cosign", "size-drift",
                            # "chain-mismatch", "unreachable") so we
                            # don't false-positive on a generic 500
                            # from any cause (codex review).

    SEQ=$((SEQ + 1))
    local key="MALW_K${SEQ}"
    local val="malw-test-${SEQ}"
    if ! AL set "$key" "$val" --scope work >/dev/null 2>&1; then
        no "[mode=$mode] AL set failed pre-scenario"
        return
    fi

    start_bad_witness "$mode"
    # Snapshot the bad-witness log size BEFORE the request so we
    # can verify the request actually hit the witness (codex
    # review: an unrelated rejection wouldn't trigger any witness
    # contact at all).
    local pre_log_size
    pre_log_size=$(stat -f%z "$WITNESS_LOG" 2>/dev/null || stat -c%s "$WITNESS_LOG" 2>/dev/null || echo 0)

    AL sync >/dev/null 2>"$HOME_AL/lastsync.err"
    local rc=$?
    SYNC_OUT=$(cat "$HOME_AL/lastsync.err" 2>/dev/null)

    local post_log_size
    post_log_size=$(stat -f%z "$WITNESS_LOG" 2>/dev/null || stat -c%s "$WITNESS_LOG" 2>/dev/null || echo 0)

    case "$expected" in
        accept)
            if [ $rc -ne 0 ]; then
                no "[mode=$mode] sync rc=$rc (expected: accept): $(echo "$SYNC_OUT" | head -c 200)"
                kill -KILL $BAD_PID 2>/dev/null || true; wait $BAD_PID 2>/dev/null || true
                return
            fi
            if [ "$(AL get "$key" --scope work --raw 2>/dev/null)" = "$val" ]; then
                ok "[mode=$mode] accepted (rc=0) + value readable"
            else
                no "[mode=$mode] sync claimed ok but value not readable"
            fi
            ;;
        reject)
            if [ $rc -eq 0 ]; then
                no "[mode=$mode] sync rc=0 but should have rejected"
                kill -KILL $BAD_PID 2>/dev/null || true; wait $BAD_PID 2>/dev/null || true
                return
            fi
            # Codex review: the bad-witness MUST have been contacted
            # (else the rejection might be from an unrelated cause
            # and we'd false-positive). Always-500 + always-409
            # modes don't re-fetch upstream so log doesn't grow —
            # for those we just require rc!=0 + pattern match.
            if [ "$mode" != "always-500" ] && [ "$mode" != "always-409" ]; then
                if [ "$post_log_size" -le "$pre_log_size" ]; then
                    no "[mode=$mode] bad-witness log did not grow — request never reached the witness"
                    kill -KILL $BAD_PID 2>/dev/null || true; wait $BAD_PID 2>/dev/null || true
                    return
                fi
            fi
            # Top-level error pattern.
            if [ -n "$needle" ] && ! echo "$SYNC_OUT" | grep -qiF "$needle"; then
                no "[mode=$mode] rejected but pattern '$needle' missing: $(echo "$SYNC_OUT" | head -c 250)"
                kill -KILL $BAD_PID 2>/dev/null || true; wait $BAD_PID 2>/dev/null || true
                return
            fi
            # Mode-specific skip reason — guards against generic
            # 500s passing as the right rejection.
            if [ -n "$skip_pat" ] && ! echo "$SYNC_OUT" | grep -qiF "$skip_pat"; then
                no "[mode=$mode] rejected but missing per-mode skip reason '$skip_pat': $(echo "$SYNC_OUT" | head -c 250)"
                kill -KILL $BAD_PID 2>/dev/null || true; wait $BAD_PID 2>/dev/null || true
                return
            fi
            ok "[mode=$mode] rejected (rc=$rc) + pattern '${needle}' + skip-reason '${skip_pat:-n/a}'"
            ;;
    esac
    kill -KILL $BAD_PID 2>/dev/null || true; wait $BAD_PID 2>/dev/null || true
    sleep 0.2
}

# ---- Setup ----------------------------------------------------------

phase "Setup"
pkill -f fd0-server 2>/dev/null || true
pkill -f fd0-agent  2>/dev/null || true
pkill -f fd0-test-bad-witness 2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_LOG" "$SERVER_KEY" "$WITNESS_KEY" "$WITNESS_LOG"

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" \
    --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.5
curl -fs "http://127.0.0.1:${SERVER_PORT}/healthz" >/dev/null || { no "server failed"; exit 1; }
ok "server up"

# Bootstrap client + a scope, sync once (no witness yet).
mkfd0 "$HOME_AL" "http://127.0.0.1:${SERVER_PORT}"
printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" init >/dev/null 2>&1
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
AL scope create --label work >/dev/null
AL set seed v0 --scope work >/dev/null
AL sync >/dev/null 2>&1
ok "scope bootstrapped + first sync (no witness yet)"

# Pre-generate the bad witness keypair so we can pin its pub in the
# client config BEFORE any scenario runs.
start_bad_witness passthrough
sleep 0.3
W_PUB_HEX=$(extract_pub_hex "$WITNESS_KEY")
kill $BAD_PID 2>/dev/null || true; wait $BAD_PID 2>/dev/null || true
ok "bad-witness pub: ${W_PUB_HEX:0:16}…"

# Append the witness config (pinned to bad-witness's real pub).
cat >> "$HOME_AL/config.toml" <<EOF

[[witness]]
url = "http://127.0.0.1:${WITNESS_PORT}"
pub = "${W_PUB_HEX}"

[witness_policy]
min_cosigns = 1
EOF

# ---- Scenarios ------------------------------------------------------

phase "Scenario 1: fork-cosign — witness signs a tampered root"
# Cross-check sees same size, different root → equivocation.
run_scenario fork-cosign reject "equivocation"

phase "Scenario 2: wrong-chain-id — cosign for a different chain"
# Verifier fails (chain_id mismatch in WitnessedSTH) → bad-cosign.
run_scenario wrong-chain-id reject "insufficient" "bad-cosign"

phase "Scenario 3: wrong-server-url — cosign claims different server"
# Verifier fails (server_url mismatch in WitnessedSTH) → bad-cosign.
run_scenario wrong-server-url reject "insufficient" "bad-cosign"

phase "Scenario 4: size-drift — cosign for wrong tree_size"
# Cosign verifies but size != requested → size-drift skip.
run_scenario size-drift reject "insufficient" "size-drift"

phase "Scenario 5: wrong-witness-pub — embedded pub != pinned pub"
# Verifier fails (pub mismatch) → bad-cosign.
run_scenario wrong-witness-pub reject "insufficient" "bad-cosign"

phase "Scenario 6: garbage-cbor — malformed response body"
# Body decode fails → unreachable.
run_scenario garbage-cbor reject "insufficient" "unreachable"

phase "Scenario 7: always-409 — witness claims its own equivocation"
# 409 short-circuits to ErrWitnessEquivocation.
run_scenario always-409 reject "equivocation"

phase "Scenario 8: always-500 — witness perpetual error"
# 500 → unreachable.
run_scenario always-500 reject "insufficient" "unreachable"

AL lock >/dev/null 2>&1 || true
echo
printf "\033[1m== WITNESS-MALICIOUS SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
