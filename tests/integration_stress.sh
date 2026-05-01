#!/usr/bin/env bash

# Translog (TRANSLOG.md §6.1) requires explicit opt-in for non-TTY pinning.
# Tests run unattended → enable auto-pin so the first /sync can land the pin.
export FD0_AUTO_PIN=1
# fd0 multi-device stress / convergence test.
#
#   bash tests/integration_stress.sh                    # 100 iters, seed 1337
#   SEED=42  ITERS=500  bash tests/integration_stress.sh
#
# Scenario:
#   - 4 devices: alice-laptop, alice-desktop, bob-laptop, bob-desktop
#   - 2 shared scopes: shared-rw (alice creates, adds bob),
#                      shared-fin (bob creates, adds alice)
#   - Auto-sync every 1s on every device.
#   - $ITERS random ops; weighted set/rm/concurrent.
#   - Convergence checkpoint every 25 ops:
#       all devices sync explicitly, then for each shared scope all
#       members must agree on (a) chain_tip seq+hash and (b) the secret
#       index (modulo eventual-consistency tolerance).
#   - Final check: fd0 doctor on all 4 devices.
#   - Memory tracking: agent RSS sampled before, mid-run, and at end.

set -uo pipefail

SEED="${SEED:-1337}"
ITERS="${ITERS:-100}"
# Auto-sync is intentionally OFF in the stress test: we want deterministic
# convergence checkpoints without worker ops contending with background
# sync goroutines for the flock. Sync is driven explicitly at each
# checkpoint via sync_all().
SYNC_INTERVAL="${SYNC_INTERVAL:-}"
SERVER_PORT="${SERVER_PORT:-14048}"
CHECKPOINT_EVERY="${CHECKPOINT_EVERY:-25}"

SERVER_DB=/tmp/fd0-stress.db
SERVER_LOG=/tmp/fd0-stress.log
RECOVERY=/tmp/fd0-stress-recovery
FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}

PASS=0
FAIL=0
START_AT=$(date +%s)

step() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()   { PASS=$((PASS+1)); }                       # silent success at scale
no()   { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }
log()  { printf "  %s\n" "$*"; }

# Per-device wrappers with FD0_LOCK_WAIT for queueing behind auto-sync.
make_alias() {
    local name="$1" home="$2"
    eval "
${name}() {
    env FD0_HOME='$home' FD0_SERVER='http://127.0.0.1:${SERVER_PORT}' '$FD0' \"\$@\"
}"
}

unlock_one() {
    local home="$1" pass="$2"
    printf "%s\n" "$pass" | env FD0_HOME="$home" "$FD0" unlock >/dev/null 2>&1
}

write_config() {
    local home="$1"
    mkdir -p "$home"
    chmod 700 "$home"
    if [ -n "$SYNC_INTERVAL" ]; then
        cat > "$home/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
interval  = "${SYNC_INTERVAL}"
on_unlock = false
EOF
    else
        cat > "$home/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
on_unlock = false
EOF
    fi
}

# ─── setup ────────────────────────────────────────────────────────────────
step "Setup (seed=$SEED iters=$ITERS interval=$SYNC_INTERVAL)"
pkill -f fd0-server 2>/dev/null || true
pkill -f fd0-agent  2>/dev/null || true
sleep 0.3
rm -f "$SERVER_DB" "$SERVER_LOG" "$RECOVERY".alice "$RECOVERY".bob
rm -rf "$HOME/.fd0-alice-laptop" "$HOME/.fd0-alice-desktop" \
       "$HOME/.fd0-bob-laptop"   "$HOME/.fd0-bob-desktop"

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; pkill -f fd0-agent 2>/dev/null || true' EXIT
sleep 0.5
curl -fsS "http://127.0.0.1:${SERVER_PORT}/healthz" >/dev/null
log "fd0-server up"

write_config "$HOME/.fd0-alice-laptop"
write_config "$HOME/.fd0-alice-desktop"
write_config "$HOME/.fd0-bob-laptop"
write_config "$HOME/.fd0-bob-desktop"

make_alias AL "$HOME/.fd0-alice-laptop"
make_alias AD "$HOME/.fd0-alice-desktop"
make_alias BL "$HOME/.fd0-bob-laptop"
make_alias BD "$HOME/.fd0-bob-desktop"

DEVICES=(AL AD BL BD)
DEV_HOMES=(
    "$HOME/.fd0-alice-laptop"
    "$HOME/.fd0-alice-desktop"
    "$HOME/.fd0-bob-laptop"
    "$HOME/.fd0-bob-desktop"
)

# ─── identity bootstrap ──────────────────────────────────────────────────
printf "alice-l\nalice-l\n" | env FD0_HOME="$HOME/.fd0-alice-laptop" "$FD0" init >/dev/null 2>&1
printf "bob-l\nbob-l\n"     | env FD0_HOME="$HOME/.fd0-bob-laptop"   "$FD0" init >/dev/null 2>&1
unlock_one "$HOME/.fd0-alice-laptop" "alice-l"
unlock_one "$HOME/.fd0-bob-laptop"   "bob-l"
sleep 0.3
printf "rec-a\nrec-a\n" | AL recovery export "$RECOVERY".alice >/dev/null
printf "rec-b\nrec-b\n" | BL recovery export "$RECOVERY".bob   >/dev/null
printf "rec-a\nalice-d\nalice-d\n" | env FD0_HOME="$HOME/.fd0-alice-desktop" "$FD0" recovery import "$RECOVERY".alice >/dev/null 2>&1
printf "rec-b\nbob-d\nbob-d\n"     | env FD0_HOME="$HOME/.fd0-bob-desktop"   "$FD0" recovery import "$RECOVERY".bob   >/dev/null 2>&1
unlock_one "$HOME/.fd0-alice-desktop" "alice-d"
unlock_one "$HOME/.fd0-bob-desktop"   "bob-d"
sleep 0.3

# Card exchange (each device pins both peers)
ALICE_CARD=$(AL card export 2>/dev/null)
BOB_CARD=$(BL card export 2>/dev/null)
for fn in AL AD; do $fn card import "$BOB_CARD"   --label bob   --yes >/dev/null; done
for fn in BL BD; do $fn card import "$ALICE_CARD" --label alice --yes >/dev/null; done

# ─── shared scopes ───────────────────────────────────────────────────────
AL scope create --label shared-rw  >/dev/null
AL scope add-member bob --scope shared-rw  >/dev/null
BL scope create --label shared-fin >/dev/null
BL scope add-member alice --scope shared-fin >/dev/null
# Cross-fertilise: each device pulls the other's events.
AL sync >/dev/null; BL sync >/dev/null
AL sync >/dev/null; BL sync >/dev/null   # second pass picks up cross-creates
AD sync >/dev/null; BD sync >/dev/null   # desktops discover

# Snapshot scope_ids for use in the loop.
SCOPE_RW=$(AL scope ls | awk '/shared-rw/{print $2}' | sed 's/…//')
SCOPE_FIN=$(BL scope ls | awk '/shared-fin/{print $2}' | sed 's/…//')
log "shared-rw  ≈ $SCOPE_RW"
log "shared-fin ≈ $SCOPE_FIN"

# Sanity: each device sees both shared scopes.
for fn in AL AD BL BD; do
    OUT=$($fn scope ls)
    if printf "%s" "$OUT" | grep -q "shared-rw"; then ok; else no "$fn missing shared-rw at setup"; fi
    if printf "%s" "$OUT" | grep -q "shared-fin"; then ok; else no "$fn missing shared-fin at setup"; fi
done

# ─── memory baseline ─────────────────────────────────────────────────────
agent_rss() {
    # Sum RSS (KiB) for all fd0-agent processes.
    pgrep -f "$FD0_AGENT" | xargs -I{} ps -o rss= -p {} 2>/dev/null | awk '{s+=$1}END{print s}'
}
RSS_START=$(agent_rss)
log "agent RSS start: ${RSS_START} KiB"
RSS_MAX=$RSS_START

# ─── convergence check ───────────────────────────────────────────────────
sync_all() {
    AL sync >/dev/null 2>&1 || true
    BL sync >/dev/null 2>&1 || true
    AD sync >/dev/null 2>&1 || true
    BD sync >/dev/null 2>&1 || true
}

# tip_for_scope: prints "$seq" for the scope (label-resolvable) on the device.
tip_for_scope() {
    local fn="$1" scope_label="$2"
    $fn scope ls 2>/dev/null | awk -v lbl="$scope_label" '$1==lbl{ for(i=1;i<=NF;i++) if($i~/^tip=/){gsub("tip=","",$i); print $i; exit} }'
}

# ls_in_scope: prints sorted secret names (excluding _meta, tombstones) for scope.
ls_in_scope() {
    local fn="$1" scope_label="$2"
    # `fd0 ls` lists across ALL scopes; we filter by trailing scope label column.
    $fn ls 2>/dev/null | awk -v lbl="$scope_label" '$NF==lbl{print $1}' | sort
}

checkpoint() {
    local at="$1"
    sync_all
    sleep 1
    sync_all   # second pass to catch any post-reconcile straggler
    sleep 1
    local mismatches=0
    for label in shared-rw shared-fin; do
        # AL+BL+AD+BD all members of both shared scopes.
        local AL_TIP AD_TIP BL_TIP BD_TIP
        AL_TIP=$(tip_for_scope AL "$label")
        AD_TIP=$(tip_for_scope AD "$label")
        BL_TIP=$(tip_for_scope BL "$label")
        BD_TIP=$(tip_for_scope BD "$label")
        if [ "$AL_TIP" = "$AD_TIP" ] && [ "$AL_TIP" = "$BL_TIP" ] && [ "$AL_TIP" = "$BD_TIP" ]; then
            ok
        else
            no "checkpoint@$at: tip diverges for $label (AL=$AL_TIP AD=$AD_TIP BL=$BL_TIP BD=$BD_TIP)"
            mismatches=$((mismatches+1))
        fi
        local AL_LIST AD_LIST BL_LIST BD_LIST
        AL_LIST=$(ls_in_scope AL "$label")
        AD_LIST=$(ls_in_scope AD "$label")
        BL_LIST=$(ls_in_scope BL "$label")
        BD_LIST=$(ls_in_scope BD "$label")
        if [ "$AL_LIST" = "$AD_LIST" ] && [ "$AL_LIST" = "$BL_LIST" ] && [ "$AL_LIST" = "$BD_LIST" ]; then
            ok
        else
            no "checkpoint@$at: secret list diverges for $label"
            mismatches=$((mismatches+1))
            printf "  AL[%s]:\n%s\n  AD[%s]:\n%s\n  BL[%s]:\n%s\n  BD[%s]:\n%s\n" \
                "$AL_TIP" "$AL_LIST" "$AD_TIP" "$AD_LIST" "$BL_TIP" "$BL_LIST" "$BD_TIP" "$BD_LIST"
        fi
    done
    local cur
    cur=$(agent_rss)
    if [ "$cur" -gt "$RSS_MAX" ]; then RSS_MAX=$cur; fi
    if [ "$mismatches" = "0" ]; then
        log "checkpoint@$at OK  agent RSS=${cur} KiB"
    fi
}

# ─── workload ────────────────────────────────────────────────────────────
step "Running $ITERS random ops"
RANDOM=$SEED
SCOPES=(shared-rw shared-fin)
KEY_SPACE=80          # number of distinct keys we cycle through

for ((i=1; i<=ITERS; i++)); do
    DEV="${DEVICES[$((RANDOM % 4))]}"
    SCOPE="${SCOPES[$((RANDOM % 2))]}"
    KEY="K$((RANDOM % KEY_SPACE))"
    VAL="v${RANDOM}_${i}"
    OP=$((RANDOM % 100))
    if   (( OP < 70 )); then
        # set
        $DEV set "$KEY" "$VAL" --scope "$SCOPE" >/dev/null 2>&1 || true
    elif (( OP < 85 )); then
        # rm (silently no-op if key not present)
        $DEV rm "$KEY" --scope "$SCOPE" >/dev/null 2>&1 || true
    elif (( OP < 95 )); then
        # concurrent: another device writes the same key with a different
        # value. We `wait` on specific PIDs (not bare `wait`, which would
        # also block on the agents that bash inherited as session children).
        DEV2="${DEVICES[$((RANDOM % 4))]}"
        if [ "$DEV2" = "$DEV" ]; then DEV2="${DEVICES[$(( (RANDOM % 3) + 1 ))]}"; fi
        VAL2="v${RANDOM}_${i}_other"
        ($DEV  set "$KEY" "$VAL"  --scope "$SCOPE" >/dev/null 2>&1 || true) & P1=$!
        ($DEV2 set "$KEY" "$VAL2" --scope "$SCOPE" >/dev/null 2>&1 || true) & P2=$!
        wait $P1 2>/dev/null || true
        wait $P2 2>/dev/null || true
    else
        # 5%: idle (lets the auto-sync catch up)
        :
    fi
    if (( i % CHECKPOINT_EVERY == 0 )); then
        checkpoint "$i"
    fi
done

# ─── final convergence + doctor ──────────────────────────────────────────
step "Final convergence"
checkpoint "FINAL"

step "fd0 doctor on all four devices"
for fn in AL AD BL BD; do
    OUT=$($fn doctor 2>&1 || true)
    if printf "%s" "$OUT" | grep -q "all clear"; then
        ok
    else
        no "$fn doctor reported issues"
        printf "%s\n" "$OUT" | sed 's/^/    /'
    fi
done

# ─── summary ─────────────────────────────────────────────────────────────
DUR=$(( $(date +%s) - START_AT ))
RSS_END=$(agent_rss)
echo
printf "\033[1m== STRESS SUMMARY ==\033[0m  PASS=%d  FAIL=%d  duration=%ds\n" "$PASS" "$FAIL" "$DUR"
printf "  agent RSS: start=%d  max=%d  end=%d (KiB)\n" "$RSS_START" "$RSS_MAX" "$RSS_END"
printf "  iters=%d  seed=%d  checkpoints=%d\n" "$ITERS" "$SEED" "$((ITERS / CHECKPOINT_EVERY))"
exit $FAIL
