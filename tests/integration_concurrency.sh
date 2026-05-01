#!/usr/bin/env bash
# fd0 concurrency / race-matrix integration test.
#
# Verifies fd0 handles every reasonable race without corruption:
#   - same-device parallel writes (flock serializes)
#   - same-identity multi-device simultaneous writes (server reconcile)
#   - parallel auth-method changes
#   - sync racing against writes / lock
#   - concurrent member.change ops
#
# Important: bare `wait` deadlocks when child subshells fork detached
# fd0-agent processes, because bash inherits them as session children.
# Always use `wait $PID` explicitly.

set -uo pipefail

SERVER_PORT=14601
SERVER_DB=/tmp/fd0-conc.db
SERVER_LOG=/tmp/fd0-conc.log
HOME_AL=$HOME/.fd0-conc-al
HOME_AD=$HOME/.fd0-conc-ad
HOME_BL=$HOME/.fd0-conc-bl
RECOVERY=/tmp/fd0-conc-rec.cbor
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
    rm -rf "$HOME_AL" "$HOME_AD" "$HOME_BL" "$SERVER_DB" "$SERVER_LOG" "$RECOVERY"
}
trap cleanup EXIT

step "Setup"
pkill -f fd0-server 2>/dev/null || true
pkill -f fd0-agent  2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$HOME_AD" "$HOME_BL" "$SERVER_DB" "$SERVER_LOG" "$RECOVERY"
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.3

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

mkfd0 "$HOME_AL"; mkfd0 "$HOME_AD"; mkfd0 "$HOME_BL"

printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" init >/dev/null 2>&1
printf "bob-pass\nbob-pass\n"     | env FD0_HOME="$HOME_BL" "$FD0" init >/dev/null 2>&1
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
printf "bob-pass\n"   | env FD0_HOME="$HOME_BL" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
printf "alice-rec\nalice-rec\n" | env FD0_HOME="$HOME_AL" "$FD0" recovery export "$RECOVERY" >/dev/null
printf "alice-rec\nalice-d\nalice-d\n" | env FD0_HOME="$HOME_AD" "$FD0" recovery import "$RECOVERY" >/dev/null 2>&1
printf "alice-d\n" | env FD0_HOME="$HOME_AD" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
ok "3 devices initialized"

AL() { env FD0_HOME="$HOME_AL" "$FD0" "$@"; }
AD() { env FD0_HOME="$HOME_AD" "$FD0" "$@"; }
BL() { env FD0_HOME="$HOME_BL" "$FD0" "$@"; }

AC=$(AL card export); BC=$(BL card export)
AL card import "$BC" --label bob   --yes >/dev/null
AD card import "$BC" --label bob   --yes >/dev/null
BL card import "$AC" --label alice --yes >/dev/null
AL scope create --label work >/dev/null
AL scope add-member bob --scope work >/dev/null
AL sync >/dev/null
BL sync >/dev/null
AD sync >/dev/null

# ─── C1. Same-device parallel sets ───────────────────────────────────────
step "C1) 10 parallel sets on the same device → all land"
PIDS=()
for i in $(seq 1 10); do
    (AL set "P$i" "v$i" --scope work >/dev/null 2>&1) & PIDS+=($!)
done
for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
COUNT=$(AL ls 2>&1 | grep -c "^P[0-9]" || true)
[ "$COUNT" -eq 10 ] && ok "all 10 parallel sets landed" || no "expected 10, got $COUNT"
ALL_OK=1
for i in $(seq 1 10); do
    GOT=$(AL get "P$i" --scope work --raw 2>/dev/null)
    if [ "$GOT" != "v$i" ]; then ALL_OK=0; break; fi
done
[ "$ALL_OK" = "1" ] && ok "every parallel value matches" || no "value mismatch"

# ─── C2. Disjoint keys across devices ────────────────────────────────────
step "C2) Alice/laptop + Alice/desktop write disjoint keys"
AL sync >/dev/null
AD sync >/dev/null
( for i in $(seq 1 5); do AL set "L$i" "lv$i" --scope work >/dev/null 2>&1; done ) & PA=$!
( for i in $(seq 1 5); do AD set "D$i" "dv$i" --scope work >/dev/null 2>&1; done ) & PB=$!
wait "$PA" 2>/dev/null || true
wait "$PB" 2>/dev/null || true
AL sync >/dev/null 2>&1; AD sync >/dev/null 2>&1
AL sync >/dev/null 2>&1; AD sync >/dev/null 2>&1

L_COUNT=$(AL ls 2>&1 | grep -c "^L[0-9]" || true)
D_COUNT=$(AL ls 2>&1 | grep -c "^D[0-9]" || true)
[ "$L_COUNT" = "5" ] && ok "AL sees its 5 own keys" || no "AL L_COUNT=$L_COUNT"
[ "$D_COUNT" = "5" ] && ok "AL sees AD's 5 keys" || no "AL D_COUNT=$D_COUNT (reconcile broken)"
L_COUNT=$(AD ls 2>&1 | grep -c "^L[0-9]" || true)
D_COUNT=$(AD ls 2>&1 | grep -c "^D[0-9]" || true)
[ "$L_COUNT" = "5" ] && ok "AD sees AL's 5 keys" || no "AD L_COUNT=$L_COUNT"
[ "$D_COUNT" = "5" ] && ok "AD sees its 5 own keys" || no "AD D_COUNT=$D_COUNT"

# ─── C3. Same-key collision ──────────────────────────────────────────────
step "C3) Two devices write COLLIDE_KEY simultaneously"
( AL set COLLIDE_KEY "from-laptop"  --scope work >/dev/null 2>&1 ) & PA=$!
( AD set COLLIDE_KEY "from-desktop" --scope work >/dev/null 2>&1 ) & PB=$!
wait "$PA" 2>/dev/null || true
wait "$PB" 2>/dev/null || true
AL sync >/dev/null 2>&1; AD sync >/dev/null 2>&1
AL sync >/dev/null 2>&1; AD sync >/dev/null 2>&1
AL_VAL=$(AL get COLLIDE_KEY --scope work --raw 2>/dev/null)
AD_VAL=$(AD get COLLIDE_KEY --scope work --raw 2>/dev/null)
[ "$AL_VAL" = "$AD_VAL" ] \
    && ok "convergent value: '$AL_VAL'" \
    || no "DIVERGENT: AL='$AL_VAL', AD='$AD_VAL'"
case "$AL_VAL" in
    "from-laptop"|"from-desktop") ok "value is one of the writes" ;;
    *) no "value is neither: $AL_VAL" ;;
esac

# ─── C4. Cross-user same-key ─────────────────────────────────────────────
step "C4) Alice + Bob write SHARED_KEY simultaneously"
( AL set SHARED_KEY "alice-version" --scope work >/dev/null 2>&1 ) & PA=$!
( BL set SHARED_KEY "bob-version"   --scope work >/dev/null 2>&1 ) & PB=$!
wait "$PA" 2>/dev/null || true
wait "$PB" 2>/dev/null || true
AL sync >/dev/null 2>&1; BL sync >/dev/null 2>&1
AL sync >/dev/null 2>&1; BL sync >/dev/null 2>&1
AL_VAL=$(AL get SHARED_KEY --scope work --raw 2>/dev/null)
BL_VAL=$(BL get SHARED_KEY --scope work --raw 2>/dev/null)
[ "$AL_VAL" = "$BL_VAL" ] \
    && ok "cross-user converges: '$AL_VAL'" \
    || no "DIVERGENT cross-user: AL='$AL_VAL', BL='$BL_VAL'"

# ─── C5. Sync + set racing on same device ────────────────────────────────
step "C5) Sync racing against set"
( AL sync >/dev/null 2>&1 ) & SYNC_PID=$!
sleep 0.05
( AL set FLOCK_TEST "v1" --scope work >/dev/null 2>&1 ) & WRITE_PID=$!
wait "$SYNC_PID" 2>/dev/null || true
wait "$WRITE_PID" 2>/dev/null || true
GOT=$(AL get FLOCK_TEST --scope work --raw 2>/dev/null)
[ "$GOT" = "v1" ] \
    && ok "set survived sync contention" \
    || no "set lost: '$GOT'"

# ─── C6. Lock during sync ────────────────────────────────────────────────
step "C6) Lock issued mid-sync"
( AL sync >/dev/null 2>&1 ) & SYNC_PID=$!
sleep 0.05
AL lock 2>&1 || true
wait "$SYNC_PID" 2>/dev/null || true
sleep 0.2
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
sleep 0.2
OUT=$(AL doctor 2>&1)
case "$OUT" in
    *"all clear"*|*"warning"*) ok "doctor clean after lock-mid-sync" ;;
    *) no "doctor reports issues: $OUT" ;;
esac

# ─── C7. Parallel auth add on independent user-chains ────────────────────
step "C7) Parallel auth add on AL + AD (independent chains)"
( printf "new-laptop-pass\nnew-laptop-pass\n" | AL auth add >/dev/null 2>&1 ) & PA=$!
( printf "new-desktop-pass\nnew-desktop-pass\n" | AD auth add >/dev/null 2>&1 ) & PB=$!
wait "$PA" 2>/dev/null || true
wait "$PB" 2>/dev/null || true
AL_COUNT=$(AL auth ls 2>&1 | grep -c "^[* ]")
AD_COUNT=$(AD auth ls 2>&1 | grep -c "^[* ]")
[ "$AL_COUNT" = "2" ] && ok "AL has 2 methods" || no "AL_COUNT=$AL_COUNT"
[ "$AD_COUNT" = "2" ] && ok "AD has 2 methods" || no "AD_COUNT=$AD_COUNT"

# ─── C8. Two simultaneous unlock attempts ────────────────────────────────
step "C8) Two simultaneous unlock attempts"
AL lock >/dev/null 2>&1
sleep 0.2
( printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1 ) & PA=$!
( printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1 ) & PB=$!
wait "$PA" 2>/dev/null || true
wait "$PB" 2>/dev/null || true
sleep 0.3
OUT=$(AL status 2>&1)
case "$OUT" in
    *unlocked*) ok "agent unlocked (one of the two attempts won)" ;;
    *) no "agent not unlocked: $OUT" ;;
esac

# ─── C9. Concurrent member.change ────────────────────────────────────────
step "C9) Both alice devices add the same new member"
HOME_CL=$HOME/.fd0-conc-cl
mkfd0 "$HOME_CL"
printf "carol-pass\ncarol-pass\n" | env FD0_HOME="$HOME_CL" "$FD0" init >/dev/null 2>&1
printf "carol-pass\n" | env FD0_HOME="$HOME_CL" "$FD0" unlock >/dev/null 2>&1
sleep 0.2
CC=$(env FD0_HOME="$HOME_CL" "$FD0" card export)
AL card import "$CC" --label carol --yes >/dev/null
AD card import "$CC" --label carol --yes >/dev/null
( AL scope add-member carol --scope work >/dev/null 2>&1 ) & PA=$!
( AD scope add-member carol --scope work >/dev/null 2>&1 ) & PB=$!
wait "$PA" 2>/dev/null || true
wait "$PB" 2>/dev/null || true
AL sync >/dev/null 2>&1; AD sync >/dev/null 2>&1
AL sync >/dev/null 2>&1; AD sync >/dev/null 2>&1
AL_M=$(AL scope members work 2>&1 | sort)
AD_M=$(AD scope members work 2>&1 | sort)
[ "$AL_M" = "$AD_M" ] \
    && ok "alice-l and alice-d converge on member set" \
    || no "DIVERGENT member sets"
env FD0_HOME="$HOME_CL" "$FD0" lock >/dev/null 2>&1
rm -rf "$HOME_CL"

# ─── C10. Doctor on all surviving devices ────────────────────────────────
step "C10) doctor on all devices"
for dev in AL AD BL; do
    OUT=$($dev doctor 2>&1)
    case "$OUT" in
        *"all clear"*|*"warning"*) ok "$dev: clean" ;;
        *) no "$dev: doctor issues — $OUT" ;;
    esac
done

AL lock >/dev/null 2>&1
AD lock >/dev/null 2>&1
BL lock >/dev/null 2>&1
echo
printf "\033[1m== CONCURRENCY SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
