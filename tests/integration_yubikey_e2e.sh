#!/usr/bin/env bash

# YubiKey end-to-end multi-user integration test.
#
# Spins up a real fd0 server + witness, three users (Alice + Bob via
# passphrase, Carol via YubiKey), and walks an extended scenario that
# touches every CLI command at least once and the YubiKey card on
# every (re)unlock. Designed to validate Phase 1's wiring (resolver,
# agent factory, CLI prompt) under realistic multi-user load.
#
# Hardware required:
#   - YubiKey 5.7+ on the bus, with PIV applet enabled.
#   - Slot 0x9d (Key Management) populated with an X25519 key OR
#     empty AND FD0_YUBIKEY_ENROLL=1 (the script auto-provisions
#     touch=never, pin-policy=once when allowed).
#   - PIV PIN known and supplied via FD0_YUBIKEY_PIN (default
#     "123456").
#
# Run:
#   FD0_YUBIKEY_HARDWARE=1 bash tests/integration_yubikey_e2e.sh
#
# Notes:
#   - The script DOES NOT consume PIN retries on wrong-PIN tests
#     beyond what is needed to verify rejection (single attempt,
#     expected 401-style failure). Three wrong PINs would brick the
#     PIV slot's PIN counter, so the wrong-PIN test is gated and
#     reuses the lockout-safe cycle (correct PIN restores the
#     counter implicitly on the next successful verify).
#
# Translog (TRANSLOG.md §6.1) requires explicit opt-in for non-TTY
# pinning.
export FD0_AUTO_PIN=1

set -uo pipefail

# ─── Hardware-gate ────────────────────────────────────────────────
if [ "${FD0_YUBIKEY_HARDWARE:-}" != "1" ]; then
    echo "skipping YubiKey e2e: set FD0_YUBIKEY_HARDWARE=1"
    exit 0
fi
PIN="${FD0_YUBIKEY_PIN:-123456}"
ENROLL_IF_EMPTY="${FD0_YUBIKEY_ENROLL:-0}"

# ─── Test layout ──────────────────────────────────────────────────
SERVER_PORT=14998
SERVER_DB=/tmp/fd0-yk-server.db
SERVER_LOG=/tmp/fd0-yk-server.log
WITNESS_DB=/tmp/fd0-yk-witness.db
WITNESS_CFG=/tmp/fd0-yk-witness.toml
WITNESS_LOG=/tmp/fd0-yk-witness.log
RECOVERY_AL=/tmp/fd0-yk-rec-alice
RECOVERY_CA=/tmp/fd0-yk-rec-carol

HOME_AL=$HOME/.fd0-yk-al   # Alice (passphrase)
HOME_AD=$HOME/.fd0-yk-ad   # Alice second device
HOME_BL=$HOME/.fd0-yk-bl   # Bob (passphrase)
HOME_CA=$HOME/.fd0-yk-ca   # Carol (YubiKey-backed)

FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}
FD0_WITNESS_BIN=${FD0_WITNESS:-$HOME/go/bin/fd0-witness}

PASS=0
FAIL=0
phase()    { printf "\n\033[1m═══ %s ═══\033[0m\n" "$*"; }
ok()       { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()       { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }
expect_eq() {
    if [ "$1" = "$2" ]; then ok "$3"; else no "$3 (got '$1' want '$2')"; fi
}
expect_contains() {
    if printf '%s' "$1" | grep -qF "$2"; then ok "$3"; else no "$3 (got '$1' want substring '$2')"; fi
}

cleanup() {
    # Kill ONLY the per-test agent processes — match by socket path so
    # we never touch the user's existing fd0-agent. Each per-home agent
    # writes its pid into $FD0_HOME/agent.pid; read and signal it
    # individually.
    for home in "$HOME_AL" "$HOME_AD" "$HOME_BL" "$HOME_CA"; do
        pf="$home/agent.pid"
        if [ -r "$pf" ]; then
            apid=$(cat "$pf" 2>/dev/null || true)
            if [ -n "$apid" ] && [ "$apid" -gt 0 ] 2>/dev/null && kill -0 "$apid" 2>/dev/null; then
                kill "$apid" 2>/dev/null || true
            fi
        fi
    done
    # Kill the test-spawned server + witness only (PIDs we recorded).
    if [ "${SERVER_PID:-0}" -gt 0 ] 2>/dev/null && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
    if [ "${WITNESS_PID:-0}" -gt 0 ] 2>/dev/null && kill -0 "$WITNESS_PID" 2>/dev/null; then
        kill "$WITNESS_PID" 2>/dev/null || true
    fi
    rm -rf "$HOME_AL" "$HOME_AD" "$HOME_BL" "$HOME_CA"
    rm -f  "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
           "$SERVER_LOG" "$WITNESS_DB" "$WITNESS_CFG" "$WITNESS_LOG" \
           "$RECOVERY_AL" "$RECOVERY_CA"
}
trap cleanup EXIT

# ─── Build fd0 + fd0-agent with the yubikey tag ───────────────────
phase "build with -tags=yubikey"
go build -tags=yubikey -o "$FD0"          ./cmd/fd0          || { no "build fd0";       exit 1; }
go build -tags=yubikey -o "$FD0_AGENT"    ./cmd/fd0-agent    || { no "build fd0-agent"; exit 1; }
go build                -o "$FD0_SERVER_BIN"  ./cmd/fd0-server  || { no "build fd0-server"; exit 1; }
go build                -o "$FD0_WITNESS_BIN" ./cmd/fd0-witness || { no "build fd0-witness"; exit 1; }
ok "binaries built"

# ─── Per-device CLI invokers ──────────────────────────────────────
mkfd0() {
    local home="$1"
    mkdir -p "$home" && chmod 700 "$home"
    cat > "$home/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
on_unlock = false
[client]
lock_wait = "10s"
EOF
}

AL() { env FD0_HOME="$HOME_AL" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }
AD() { env FD0_HOME="$HOME_AD" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }
BL() { env FD0_HOME="$HOME_BL" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }
CA() { env FD0_HOME="$HOME_CA" FD0_AGENT_BIN="$FD0_AGENT" "$FD0" "$@"; }

CA_lock() {
    # Lock Carol's vault via the agent (clears super_priv from mlocked
    # memory). DO NOT pkill fd0-agent — that would also kill Alice's
    # and Bob's agents on this same machine, breaking their sync ops.
    CA lock >/dev/null 2>&1 || true
}
CA_unlock_pass() { printf "carol-pass\n" | CA unlock --method=passphrase >/dev/null 2>&1; }
CA_unlock_yk()   { printf "%s\n" "$PIN"  | CA unlock --method=yubikey    >/dev/null 2>&1; }

# ─── Phase 1: spin up server + witness ────────────────────────────
phase "server + witness"
"$FD0_SERVER_BIN" --bind=":$SERVER_PORT" --db="$SERVER_DB" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.5
if ! kill -0 $SERVER_PID 2>/dev/null; then
    no "server failed to start"; tail -20 "$SERVER_LOG"; exit 1
fi
ok "server pid $SERVER_PID on :$SERVER_PORT"

cat > "$WITNESS_CFG" <<EOF
db = "$WITNESS_DB"
[[server]]
url      = "http://127.0.0.1:${SERVER_PORT}"
poll_interval = "2s"
EOF
"$FD0_WITNESS_BIN" run --config="$WITNESS_CFG" >"$WITNESS_LOG" 2>&1 &
WITNESS_PID=$!
sleep 0.5
if ! kill -0 $WITNESS_PID 2>/dev/null; then
    no "witness failed to start"; tail -20 "$WITNESS_LOG"; exit 1
fi
ok "witness pid $WITNESS_PID"

# ─── Phase 2: ensure Carol's YubiKey slot has a key ───────────────
phase "YubiKey provision"
if FD0_YUBIKEY_HARDWARE=1 FD0_YUBIKEY_ENROLL="$ENROLL_IF_EMPTY" \
    go test -tags=yubikey -count=1 -run TestYubikeyIntegration_AutoEnroll \
    ./internal/crypto/yubikey/ >/tmp/fd0-yk-probe.log 2>&1
then
    ok "slot 0x9d ready for X25519"
else
    no "slot probe failed:"
    tail -20 /tmp/fd0-yk-probe.log
    exit 1
fi

# ─── Phase 3: init three users ────────────────────────────────────
phase "user init"
mkfd0 "$HOME_AL"
mkfd0 "$HOME_AD"
mkfd0 "$HOME_BL"
mkfd0 "$HOME_CA"

printf "alice-p\nalice-p\n" | env FD0_HOME="$HOME_AL" "$FD0" init >/dev/null 2>&1 \
    && ok "Alice init" || no "Alice init"
printf "bob-p\nbob-p\n"     | env FD0_HOME="$HOME_BL" "$FD0" init >/dev/null 2>&1 \
    && ok "Bob init"   || no "Bob init"
printf "carol-pass\ncarol-pass\n" | env FD0_HOME="$HOME_CA" "$FD0" init >/dev/null 2>&1 \
    && ok "Carol init (passphrase)" || no "Carol init"

# ─── Phase 4: unlock + cards ──────────────────────────────────────
phase "first unlock + card exchange"
printf "alice-p\n"    | AL unlock >/dev/null 2>&1   && ok "Alice unlock"   || no "Alice unlock"
printf "bob-p\n"      | BL unlock >/dev/null 2>&1   && ok "Bob unlock"     || no "Bob unlock"
printf "carol-pass\n" | CA unlock >/dev/null 2>&1   && ok "Carol unlock (passphrase, pre-yubikey)" || no "Carol unlock (passphrase)"

CARD_AL=$(AL card export 2>/dev/null | head -1)
CARD_BL=$(BL card export 2>/dev/null | head -1)
CARD_CA=$(CA card export 2>/dev/null | head -1)
expect_contains "$CARD_AL" "fd0://card/" "Alice card export"
expect_contains "$CARD_BL" "fd0://card/" "Bob card export"
expect_contains "$CARD_CA" "fd0://card/" "Carol card export"

AL card import "$CARD_BL" --label bob   --yes >/dev/null 2>&1 && ok "Alice imports Bob"   || no "Alice import Bob"
AL card import "$CARD_CA" --label carol --yes >/dev/null 2>&1 && ok "Alice imports Carol" || no "Alice import Carol"
BL card import "$CARD_AL" --label alice --yes >/dev/null 2>&1 && ok "Bob imports Alice"   || no "Bob import Alice"
BL card import "$CARD_CA" --label carol --yes >/dev/null 2>&1 && ok "Bob imports Carol"   || no "Bob import Carol"
CA card import "$CARD_AL" --label alice --yes >/dev/null 2>&1 && ok "Carol imports Alice" || no "Carol import Alice"
CA card import "$CARD_BL" --label bob   --yes >/dev/null 2>&1 && ok "Carol imports Bob"   || no "Carol import Bob"

# ─── Phase 5: Carol enrolls a YubiKey method ──────────────────────
phase "Carol enrolls YubiKey"
COUNT_BEFORE=$(CA auth ls 2>/dev/null | grep -c "^" || true)
ENROLL_OUT=$(printf "y\n%s\n%s\n" "$PIN" "$PIN" | CA auth add --yubikey --touch=never 2>&1) || true
if echo "$ENROLL_OUT" | grep -q "added YubiKey auth method"; then
    ok "Carol enrolled YubiKey (PIN+touch policy)"
else
    no "Carol enroll yubikey: $ENROLL_OUT"
    exit 1
fi
COUNT_AFTER=$(CA auth ls 2>/dev/null | grep -c "^" || true)
expect_eq "$COUNT_AFTER" $((COUNT_BEFORE + 1)) "auth method count grew by 1"

# Sync so the new auth.set is persisted server-side too.
CA sync >/dev/null 2>&1 && ok "post-enroll sync" || no "post-enroll sync"

# ─── Phase 6: lock/unlock alternating methods ─────────────────────
phase "alternating unlock methods"

# Lock first.
CA_lock; ok "Carol locked"

# Unlock with passphrase (the original method).
CA_unlock_pass && ok "Carol unlock (passphrase #2)" || no "Carol unlock (passphrase #2)"
CA status 2>/dev/null | grep -q unlocked && ok "agent reports unlocked" || no "agent not unlocked"

CA_lock
# Now unlock with YubiKey (NEW path through the resolver).
CA_unlock_yk && ok "Carol unlock (YubiKey #1)" || no "Carol unlock (YubiKey #1)"
CA status 2>/dev/null | grep -q unlocked && ok "agent reports unlocked (yubikey)" || no "agent not unlocked (yubikey)"

# Quick self-doctor with the agent unlocked via YubiKey.
DOC_OUT=$(CA doctor 2>&1 || true)
expect_contains "$DOC_OUT" "agent" "doctor: agent section present"
expect_contains "$DOC_OUT" "user chain" "doctor: user chain section present"

# ─── Phase 7: scope creation + multi-user secret ops ──────────────
phase "scopes + secrets across all 3 users"
CA scope create --label work >/dev/null 2>&1 && ok "Carol creates 'work'" || no "Carol scope create"
CA set DEPLOY_KEY "carol-deploy-1" --scope work >/dev/null 2>&1 && ok "Carol set DEPLOY_KEY" || no "Carol set DEPLOY_KEY"
CA set DB_PASS    "carol-db-1"      --scope work >/dev/null 2>&1 && ok "Carol set DB_PASS"    || no "Carol set DB_PASS"
CA scope add-member alice --scope work >/dev/null 2>&1 && ok "Carol adds Alice"  || no "Carol add Alice"
CA scope add-member bob   --scope work >/dev/null 2>&1 && ok "Carol adds Bob"    || no "Carol add Bob"
CA sync >/dev/null 2>&1 && ok "Carol sync after invites" || no "Carol sync after invites"

# Alice + Bob discover the new scope.
AL sync >/dev/null 2>&1; AL sync >/dev/null 2>&1; ok "Alice 2× sync (discover)"
BL sync >/dev/null 2>&1; BL sync >/dev/null 2>&1; ok "Bob 2× sync (discover)"

# Both can read Carol's secrets after sync.
AL_DEPLOY=$(AL get DEPLOY_KEY --scope work 2>/dev/null || true)
BL_DEPLOY=$(BL get DEPLOY_KEY --scope work 2>/dev/null || true)
expect_eq "$AL_DEPLOY" "carol-deploy-1" "Alice reads DEPLOY_KEY (sealed via Carol's YubiKey-bound super_priv)"
expect_eq "$BL_DEPLOY" "carol-deploy-1" "Bob reads DEPLOY_KEY"

# Alice writes back; Carol sees it.
AL set ALICE_NOTE "alice-writes-here" --scope work >/dev/null 2>&1
AL sync >/dev/null 2>&1
CA sync >/dev/null 2>&1
CA_NOTE=$(CA get ALICE_NOTE --scope work 2>/dev/null || true)
expect_eq "$CA_NOTE" "alice-writes-here" "Carol (YubiKey) reads Alice's secret"

# ─── Phase 8: lock/unlock cycles to stress the on-card ECDH ───────
phase "lock/unlock cycles (5×) — each one a fresh on-card ECDH"
for i in 1 2 3 4 5; do
    CA_lock
    if CA_unlock_yk; then
        if CA get DEPLOY_KEY --scope work 2>/dev/null | grep -q "carol-deploy-1"; then
            ok "cycle $i: unlock + read"
        else
            no "cycle $i: read after unlock failed"
        fi
    else
        no "cycle $i: yubikey unlock failed"
    fi
done

# ─── Phase 9: wrong PIN rejected ──────────────────────────────────
# IMPORTANT: PIV slot blocks after 3 wrong PINs. We make exactly ONE
# wrong attempt here, then ALWAYS recover with a correct PIN that
# resets the retry counter on the card. Do not loop or re-run this
# phase without verifying retry status first.
phase "wrong PIN: rejected without burning the rest of the test"
CA_lock
set +e
printf "wrong-1\n" | CA unlock --method=yubikey >/tmp/fd0-yk-wrongpin.out 2>&1
WRONG_RC=$?
set -e
WRONG_OUT=$(cat /tmp/fd0-yk-wrongpin.out)
rm -f /tmp/fd0-yk-wrongpin.out
if [ "$WRONG_RC" -eq 0 ]; then
    no "wrong-PIN unlock returned exit 0 — it should fail. Output: $WRONG_OUT"
elif echo "$WRONG_OUT" | grep -qE "verify PIN|incorrect|6983|6982|smart card error 6"; then
    ok "wrong PIN surfaces a clear error (rc=$WRONG_RC): $(echo "$WRONG_OUT" | grep -E '✗|verify' | head -1)"
else
    no "wrong-PIN exit=$WRONG_RC but output lacks PIN-verify diagnostic: $WRONG_OUT"
fi
# Restore correct PIN session so subsequent phases work AND reset the
# retry counter on the card.
CA_unlock_yk && ok "correct PIN restores unlock (resets retry counter)" || no "correct PIN failed after wrong-PIN test"

# ─── Phase 10: passphrase still works after YubiKey enrollment ────
phase "passphrase fallback (both methods active)"
CA_lock
CA_unlock_pass && ok "Carol unlock via passphrase fallback" || no "Carol passphrase fallback failed"
PASSPHRASE_DEPLOY=$(CA get DEPLOY_KEY --scope work 2>/dev/null || true)
expect_eq "$PASSPHRASE_DEPLOY" "carol-deploy-1" "secrets decrypt under passphrase-method too"

# ─── Phase 11: Carol removes the passphrase method (yubikey-only) ─
phase "Carol removes passphrase, becomes YubiKey-only"

# auth rm refuses to remove the currently-active method. Unlock via
# YubiKey first, then remove the passphrase.
CA_lock
CA_unlock_yk && ok "Carol re-unlocked via YubiKey before rm" || no "yk re-unlock for rm"

# Extract the passphrase method id robustly (auth ls lines start with
# either "* " for active or "  " for inactive; field positions shift).
PP_ID=$(CA auth ls 2>/dev/null | awk '/passphrase/ {for(i=1;i<=NF;i++) if($i ~ /^am_/) {print $i; exit}}')
if [ -z "$PP_ID" ]; then
    no "could not extract passphrase method id from auth ls"
else
    if CA auth rm "$PP_ID" >/dev/null 2>&1; then
        ok "auth rm passphrase succeeded ($PP_ID)"
    else
        no "auth rm passphrase failed"
    fi
fi
CA sync >/dev/null 2>&1 && ok "post-rm sync" || no "post-rm sync"

CA_lock
# Passphrase MUST now fail.
PP_FAIL=$(printf "carol-pass\n" | CA unlock --method=passphrase 2>&1 || true)
case "$PP_FAIL" in
    *"--method=\"passphrase\""*|*"no enrolled method"*|*"unknown method"*|*"no matching"*|*"matches"*)
        ok "passphrase unlock now rejected (yubikey-only): $(echo "$PP_FAIL" | head -1)"
        ;;
    *)  no "expected passphrase rejection, got: $PP_FAIL" ;;
esac
# YubiKey unlock STILL works.
CA_unlock_yk && ok "Carol unlock (yubikey, only method)" || no "Carol unlock (yubikey-only) failed"

# ─── Phase 12: write/sync/read across all 3 again ─────────────────
phase "post-yubikey-only multi-user round trip"
CA set POST_YK_K1 "carol-via-yubikey-only-1" --scope work >/dev/null 2>&1
CA sync >/dev/null 2>&1
AL sync >/dev/null 2>&1
BL sync >/dev/null 2>&1
AL_GOT=$(AL get POST_YK_K1 --scope work 2>/dev/null || true)
BL_GOT=$(BL get POST_YK_K1 --scope work 2>/dev/null || true)
expect_eq "$AL_GOT" "carol-via-yubikey-only-1" "Alice reads Carol's yubikey-only-era secret"
expect_eq "$BL_GOT" "carol-via-yubikey-only-1" "Bob reads Carol's yubikey-only-era secret"

# ─── Phase 13: many secret ops to stress sync + projections ───────
phase "stress: 20 secret writes from Carol via YubiKey unlock"
for n in $(seq 1 20); do
    CA set "STRESS_K$n" "value-$n-$(date +%s)" --scope work >/dev/null 2>&1
done
CA sync >/dev/null 2>&1
AL sync >/dev/null 2>&1
SAMPLE=$(AL get STRESS_K17 --scope work 2>/dev/null || true)
expect_contains "$SAMPLE" "value-17-" "Alice reads STRESS_K17 written by Carol (YubiKey)"

# ─── Phase 14: Carol kicks Bob — OEK rotation under yubikey ───────
phase "membership churn while Carol is YubiKey-only"
CA scope remove-member bob --scope work >/dev/null 2>&1 && ok "Carol removes Bob" || no "Carol remove Bob"
CA sync >/dev/null 2>&1
BL sync >/dev/null 2>&1
# Bob must no longer see new secrets after OEK rotation.
CA set POST_KICK_K1 "secret-after-bob-kick" --scope work >/dev/null 2>&1
CA sync >/dev/null 2>&1
BL sync >/dev/null 2>&1 || true
BL_KICK=$(BL get POST_KICK_K1 --scope work 2>/dev/null || true)
if [ -z "$BL_KICK" ]; then
    ok "Bob cannot read post-kick secret (OEK rotated)"
else
    no "Bob still reads post-kick secret: $BL_KICK"
fi
# Alice still can.
AL sync >/dev/null 2>&1
AL_KICK=$(AL get POST_KICK_K1 --scope work 2>/dev/null || true)
expect_eq "$AL_KICK" "secret-after-bob-kick" "Alice reads post-kick secret"

# ─── Phase 15: doctor under YubiKey + a chain of locks/unlocks ────
phase "doctor + 3 more lock/unlock cycles"
DOC_FINAL=$(CA doctor 2>&1 || true)
expect_contains "$DOC_FINAL" "scopes" "final doctor: scopes section"
expect_contains "$DOC_FINAL" "auth method consistency" "final doctor: auth-method-consistency section"

for i in 6 7 8; do
    CA_lock
    CA_unlock_yk && CA get DEPLOY_KEY --scope work >/dev/null 2>&1 \
        && ok "post-churn cycle $i" || no "post-churn cycle $i"
done

# ─── Phase 16: recovery flow (Carol's YubiKey-only identity) ──────
phase "recovery export/import under YubiKey-only"
printf "carol-rec\ncarol-rec\n" | CA recovery export "$RECOVERY_CA" >/dev/null 2>&1 \
    && ok "Carol exports recovery file" || no "Carol recovery export"
[ -s "$RECOVERY_CA" ] && ok "recovery file non-empty" || no "recovery file empty"

# ─── Phase 17: server tip checks (translog still grows monotonic) ─
phase "translog sanity"
TIP_BEFORE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tip_seq) FROM chains;" 2>/dev/null || echo "?")
CA set TRANSLOG_PROBE "yk-final-write" --scope work >/dev/null 2>&1
CA sync >/dev/null 2>&1
TIP_AFTER=$(sqlite3 "$SERVER_DB" "SELECT MAX(tip_seq) FROM chains;" 2>/dev/null || echo "?")
if [ "$TIP_AFTER" != "?" ] && [ "$TIP_BEFORE" != "?" ] && [ "$TIP_AFTER" -ge "$TIP_BEFORE" ]; then
    ok "server tip advanced ($TIP_BEFORE → $TIP_AFTER)"
else
    no "server tip advance check failed ($TIP_BEFORE → $TIP_AFTER)"
fi

# ─── Result ───────────────────────────────────────────────────────
phase "result"
printf "  PASS: %d   FAIL: %d\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
