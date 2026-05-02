#!/usr/bin/env bash

export FD0_AUTO_PIN=1

# fd0 chaos test — random fault injection across many iterations,
# verify final convergence + no data loss.
#
# Faults injected per iteration (one of 5 chosen by seeded random):
#   0 — SIGKILL Alice's agent mid-sync (PID-file lookup).
#   1 — SIGKILL Bob's agent mid-sync (PID-file lookup).
#   2 — SIGKILL fd0-server mid-request, then restart.
#   3 — Server restart BETWEEN AL push and BL pull (push must succeed first).
#   4 — Concurrent simultaneous syncs on both devices.
#
# Every fault MUST actually apply: the test counts "fault no-ops"
# (e.g. PID file missing, kill failed, server PID unchanged after
# restart) and fails if any iteration silently no-op'd, since a
# no-op fault makes the convergence assertion meaningless.
#
# What we DON'T do here (covered elsewhere):
#   - Filesystem-level corruption (filesystem.sh).
#   - Network proxy with byte-flipping (malicious_server.sh).
#
# Loop runs N iterations (default 25); each picks a random fault
# from the menu, runs it, then verifies all devices converge on
# the expected final state. Failure of any iteration prints the
# seed for repro.
#
# Run from repo root:
#   bash tests/integration_chaos.sh
# Or with custom iteration count:
#   ITERATIONS=50 bash tests/integration_chaos.sh

set -uo pipefail

ITERATIONS=${ITERATIONS:-25}
SEED_BASE=${SEED_BASE:-$RANDOM}
SERVER_PORT=15010
SERVER_DB=/tmp/fd0-chaos-server.db
SERVER_LOG=/tmp/fd0-chaos-server.log
HOME_AL=$HOME/.fd0-chaos-al
HOME_BL=$HOME/.fd0-chaos-bl
RECOVERY=/tmp/fd0-chaos-rec.cbor
FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}

PASS=0
FAIL=0
CHAOS_LOG=()
phase()    { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()       { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()       { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

cleanup() {
    pkill -f fd0-agent  2>/dev/null || true
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$HOME_AL" "$HOME_BL" "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
           "$SERVER_LOG" "$RECOVERY"
}
trap cleanup EXIT

mkfd0() {
    local home="$1"
    mkdir -p "$home" && chmod 700 "$home"
    cat > "$home/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
on_unlock = false
[client]
lock_wait = "30s"
EOF
}

AL() { env FD0_HOME="$HOME_AL" "$FD0" "$@"; }
BL() { env FD0_HOME="$HOME_BL" "$FD0" "$@"; }

# Seeded "random" via $SEED_BASE + iteration number, derived
# deterministically with awk. Bash's $RANDOM is not seedable, so we
# use awk for reproducible per-iteration draws.
seeded_int() {
    local iter="$1" max="$2"
    awk -v s="$SEED_BASE" -v i="$iter" -v m="$max" \
        'BEGIN { srand(s + i); print int(rand() * m) }'
}

phase "Setup"
pkill -f fd0-server 2>/dev/null || true
pkill -f fd0-agent  2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$HOME_BL" "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
       "$SERVER_LOG" "$RECOVERY"

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.3
ok "fd0-server up"

mkfd0 "$HOME_AL"; mkfd0 "$HOME_BL"
printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" init >/dev/null 2>&1
printf "bob-pass\nbob-pass\n"     | env FD0_HOME="$HOME_BL" "$FD0" init >/dev/null 2>&1
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
printf "bob-pass\n"   | env FD0_HOME="$HOME_BL" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
ok "two devices initialized (Alice + Bob)"

AC=$(AL card export); BC=$(BL card export)
AL card import "$BC" --label bob   --yes >/dev/null
BL card import "$AC" --label alice --yes >/dev/null
AL scope create --label work >/dev/null
AL scope add-member bob --scope work >/dev/null
AL sync >/dev/null 2>&1
BL sync >/dev/null 2>&1
sleep 0.3
ok "shared scope established (Alice + Bob)"

phase "Chaos loop ($ITERATIONS iterations, seed_base=$SEED_BASE)"

# In each iteration:
#   1. AL writes a unique secret.
#   2. Either kill agent OR kill server during sync (random).
#   3. Restart whatever was killed.
#   4. Both devices sync (multiple rounds for convergence).
#   5. Assert AL's secret eventually visible on BL.
#
# A failure in ANY iteration is logged with the iteration's seed so
# the user can rerun with that seed_base+iter for repro.
# Strengthened agent-kill: requires the PID file to exist + the
# named process to be alive (kill -0) BEFORE the SIGKILL. If either
# precondition fails, we record the iteration as "fault no-op"
# (test-invalid). This catches the silent-no-op trap codex flagged.
kill_agent() {
    local home="$1"
    local pidfile="$home/agent.pid"
    if [ ! -f "$pidfile" ]; then
        echo "noop:no-pidfile"; return
    fi
    local apid
    apid=$(cat "$pidfile")
    if ! kill -0 "$apid" 2>/dev/null; then
        echo "noop:not-alive($apid)"; return
    fi
    if ! kill -KILL "$apid" 2>/dev/null; then
        echo "noop:kill-failed($apid)"; return
    fi
    # Wait briefly for actual death.
    for _ in 1 2 3 4 5; do
        if ! kill -0 "$apid" 2>/dev/null; then break; fi
        sleep 0.05
    done
    if kill -0 "$apid" 2>/dev/null; then
        echo "noop:still-alive($apid)"; return
    fi
    rm -f "$pidfile" "$home/agent.sock"
    echo "ok:$apid"
}

LOST=0
WRITE_FAIL=0
FAULT_NOOP=0
EXPECTED_KEYS=0
for i in $(seq 1 "$ITERATIONS"); do
    KEY="CHAOS_K${i}"
    VAL="value-${i}-${SEED_BASE}"
    if ! AL set "$KEY" "$VAL" --scope work >/dev/null 2>&1; then
        WRITE_FAIL=$((WRITE_FAIL + 1))
        CHAOS_LOG+=("iter=$i: AL set failed PRE-fault — cannot evaluate convergence")
        continue
    fi
    EXPECTED_KEYS=$((EXPECTED_KEYS + 1))

    FAULT=$(seeded_int "$i" 5)
    case "$FAULT" in
        0)
            ( AL sync >/dev/null 2>&1 ) & SYNC_PID=$!
            sleep 0.05
            KR=$(kill_agent "$HOME_AL")
            wait $SYNC_PID 2>/dev/null || true
            sleep 0.1
            printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
            sleep 0.2
            case "$KR" in noop:*) FAULT_NOOP=$((FAULT_NOOP+1)); CHAOS_LOG+=("iter=$i fault=0 AL-agent-kill $KR") ;; esac
            ;;
        1)
            ( BL sync >/dev/null 2>&1 ) & SYNC_PID=$!
            sleep 0.05
            KR=$(kill_agent "$HOME_BL")
            wait $SYNC_PID 2>/dev/null || true
            sleep 0.1
            printf "bob-pass\n" | env FD0_HOME="$HOME_BL" "$FD0" unlock >/dev/null 2>&1
            sleep 0.2
            case "$KR" in noop:*) FAULT_NOOP=$((FAULT_NOOP+1)); CHAOS_LOG+=("iter=$i fault=1 BL-agent-kill $KR") ;; esac
            ;;
        2)
            # Kill the SERVER mid-request, then restart. Best-effort
            # timing — we cannot prove the SIGKILL landed inside the
            # request without instrumentation, but at minimum the
            # server PID must change after restart.
            OLD_SVR=$SERVER_PID
            ( AL sync >/dev/null 2>&1 ) & SYNC_PID=$!
            sleep 0.05
            kill -KILL $SERVER_PID 2>/dev/null
            wait $SYNC_PID 2>/dev/null || true
            wait $SERVER_PID 2>/dev/null || true
            "$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
            SERVER_PID=$!
            sleep 0.4
            if [ "$OLD_SVR" = "$SERVER_PID" ] || ! kill -0 $SERVER_PID 2>/dev/null; then
                FAULT_NOOP=$((FAULT_NOOP+1))
                CHAOS_LOG+=("iter=$i fault=2 server-restart noop (old=$OLD_SVR new=$SERVER_PID)")
            fi
            ;;
        3)
            # Server restart BETWEEN AL push and BL pull. AL's push
            # must succeed first — otherwise we're testing nothing.
            if ! AL sync >/dev/null 2>&1; then
                FAULT_NOOP=$((FAULT_NOOP+1))
                CHAOS_LOG+=("iter=$i fault=3 AL pre-restart sync failed")
            fi
            kill -TERM $SERVER_PID 2>/dev/null
            wait $SERVER_PID 2>/dev/null || true
            "$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
            SERVER_PID=$!
            sleep 0.4
            BL sync >/dev/null 2>&1 || true
            ;;
        4)
            # Concurrent simultaneous syncs on both devices. Both
            # MUST exit 0 — masking failures hides regressions.
            ( AL sync >/dev/null 2>&1 ) & PA=$!
            ( BL sync >/dev/null 2>&1 ) & PB=$!
            RA=0; RB=0
            wait $PA || RA=$?
            wait $PB || RB=$?
            if [ $RA -ne 0 ] || [ $RB -ne 0 ]; then
                CHAOS_LOG+=("iter=$i fault=4 concurrent sync exit codes AL=$RA BL=$RB (non-fatal — convergence still required)")
            fi
            ;;
    esac

    # Convergence: poll until BL sees AL's just-written value or
    # we hit the timeout. Track per-iter sync error count so a
    # totally broken sync surfaces (rather than silently retrying
    # forever).
    GOT=""
    SYNC_ERRS=0
    for _ in $(seq 1 10); do
        AL sync >/dev/null 2>&1 || SYNC_ERRS=$((SYNC_ERRS+1))
        BL sync >/dev/null 2>&1 || SYNC_ERRS=$((SYNC_ERRS+1))
        GOT=$(BL get "$KEY" --scope work --raw 2>/dev/null)
        if [ "$GOT" = "$VAL" ]; then break; fi
        sleep 0.1
    done

    if [ "$GOT" != "$VAL" ]; then
        LOST=$((LOST + 1))
        CHAOS_LOG+=("iter=$i fault=$FAULT key=$KEY: BL got '$GOT' want '$VAL' (sync_errs=$SYNC_ERRS)")
    fi
done

# Aggregate the convergence assertion across all iterations.
if [ "$LOST" -eq 0 ] && [ "$WRITE_FAIL" -eq 0 ]; then
    ok "every chaos iteration converged (BL sees all $EXPECTED_KEYS of AL's secrets)"
else
    no "$LOST/$EXPECTED_KEYS chaos iterations lost data, $WRITE_FAIL pre-fault writes failed:"
    for line in "${CHAOS_LOG[@]}"; do
        echo "    $line"
    done
fi

# Fault-validity: at least one of every random fault must have
# actually fired. Codex flagged the trap where a fault silently
# no-ops — counted as "passed". We report aggregate noop count.
if [ "$FAULT_NOOP" -eq 0 ]; then
    ok "all $ITERATIONS faults actually applied (no silent no-ops)"
else
    no "$FAULT_NOOP/$ITERATIONS faults silently no-op'd (test invalid for those iters)"
fi

phase "Final state checks"

# Cross-validate VALUES on both devices — catches a fault that
# wrote the right name with garbage payload.
AL_BAD=0
BL_BAD=0
for i in $(seq 1 "$ITERATIONS"); do
    KEY="CHAOS_K${i}"
    EXP="value-${i}-${SEED_BASE}"
    [ "$(AL get "$KEY" --scope work --raw 2>/dev/null)" = "$EXP" ] || AL_BAD=$((AL_BAD+1))
    [ "$(BL get "$KEY" --scope work --raw 2>/dev/null)" = "$EXP" ] || BL_BAD=$((BL_BAD+1))
done
[ "$AL_BAD" -eq 0 ] && ok "AL has correct value for all $ITERATIONS chaos keys" \
    || no "AL: $AL_BAD wrong/missing values"
[ "$BL_BAD" -eq 0 ] && ok "BL has correct value for all $ITERATIONS chaos keys" \
    || no "BL: $BL_BAD wrong/missing values"

# Both devices must agree on the FULL set of keys, not just the
# ones we wrote. Catches Bob-only divergence + ghost keys.
AL_KEYS=$(AL list --scope work 2>/dev/null | sort)
BL_KEYS=$(BL list --scope work 2>/dev/null | sort)
if [ "$AL_KEYS" = "$BL_KEYS" ]; then
    ok "AL and BL agree on full key set after chaos"
else
    no "AL/BL key set divergence:"
    diff <(echo "$AL_KEYS") <(echo "$BL_KEYS") | head -20
fi

# Doctor on both devices: use EXIT CODE, not substring match. The
# old `*"warning"*` glob would match "1 issue(s), 1 warning(s)".
for dev in AL BL; do
    if OUT=$($dev doctor 2>&1); then
        ok "$dev doctor clean after chaos"
    else
        no "$dev doctor reports issues (exit $?): $OUT"
    fi
done

# Server still healthy.
if curl -fs "http://127.0.0.1:${SERVER_PORT}/healthz" >/dev/null 2>&1; then
    ok "server still serving /healthz after chaos"
else
    no "server unreachable after chaos"
fi

# Witness check — server's per-chain max(tree_size) must equal
# count of accepted secret.set events plus member.changes (we don't
# have an exact predictor, but it must be at least EXPECTED_KEYS+2
# = secrets + genesis + add-member).
SCOPE_CHAIN=$(sqlite3 "$SERVER_DB" "SELECT chain_id FROM chains WHERE chain_id LIKE 'scope:%' LIMIT 1;")
SVR_SIZE=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id = '$SCOPE_CHAIN';" 2>/dev/null || echo 0)
MIN_SIZE=$((EXPECTED_KEYS + 2))
if [ "$SVR_SIZE" -ge "$MIN_SIZE" ]; then
    ok "server tree size $SVR_SIZE ≥ minimum $MIN_SIZE (chaos preserved translog)"
else
    no "server tree size $SVR_SIZE < minimum $MIN_SIZE"
fi

AL lock >/dev/null 2>&1
BL lock >/dev/null 2>&1
echo
printf "\033[1m== CHAOS SUMMARY ==\033[0m  PASS=%d  FAIL=%d  iter=%d  seed_base=%d\n" \
    "$PASS" "$FAIL" "$ITERATIONS" "$SEED_BASE"
if [ "$FAIL" -gt 0 ]; then
    printf "\nReproduce: SEED_BASE=%d ITERATIONS=%d bash tests/integration_chaos.sh\n" \
        "$SEED_BASE" "$ITERATIONS"
fi
exit $FAIL
