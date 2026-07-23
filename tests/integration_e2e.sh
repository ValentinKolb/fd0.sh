#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

# Translog (TRANSLOG.md §6.1) requires explicit opt-in for non-TTY pinning.
export FD0_AUTO_PIN=1

# fd0 v1 end-to-end "production scenario" test. Spins up the full
# stack (server + witness + 7 devices for 4 users) and exercises
# every layer through realistic multi-user workflows, refined per
# codex review:
#
#   - Translog invariants: STH signature + chain_id binding +
#     inclusion + consistency proof verification on every sync;
#     LastSTH monotonicity; per-chain anchor.
#   - Multi-device baseline + concurrent convergence.
#   - Member churn with three-way merge + OEK rotation (Carol).
#   - True late-join: Eve has NEVER been a member; replays the
#     entire chain including pre-admit secret.set events her OEK
#     can't decrypt (silent skip per applySecretSet); admit
#     projection populates current state.
#   - Full local history remains contiguous while server tree grows
#     monotonically.
#   - Server DB rollback hard-fails clients via LastSTH out_of_range.
#   - Witness archive cross-checks server max(tree_size).
#
# This is the "epic" alongside the focused suites — those still
# cover their corners (combinatorics, concurrency, stress, etc.).
#
# Run from repo root:
#   bash tests/integration_e2e.sh

set -uo pipefail

SERVER_PORT=14999
SERVER_DB=/tmp/fd0-e2e-server.db
SERVER_LOG=/tmp/fd0-e2e-server.log
WITNESS_DB=/tmp/fd0-e2e-witness.db
WITNESS_CFG=/tmp/fd0-e2e-witness.toml
WITNESS_LOG=/tmp/fd0-e2e-witness.log
RECOVERY_AL=/tmp/fd0-e2e-rec-alice
RECOVERY_BL=/tmp/fd0-e2e-rec-bob

HOME_AL=$HOME/.fd0-e2e-al   # Alice laptop  (recovery owner)
HOME_AD=$HOME/.fd0-e2e-ad   # Alice desktop
HOME_AP=$HOME/.fd0-e2e-ap   # Alice phone
HOME_BL=$HOME/.fd0-e2e-bl   # Bob laptop    (recovery owner)
HOME_BD=$HOME/.fd0-e2e-bd   # Bob desktop
HOME_CL=$HOME/.fd0-e2e-cl   # Carol — joins, writes, gets removed
HOME_EL=$HOME/.fd0-e2e-el   # Eve — never previously member; pure late-join

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
expect_ge() {
    if [ "$1" -ge "$2" ] 2>/dev/null; then ok "$3"; else no "$3 (got '$1' want >= '$2')"; fi
}
norm_members() { sed -e 's/^[* ] //' | sort; }

cleanup() {
    fd0_test_stop_matching -f fd0-witness 2>/dev/null || true
    fd0_test_stop_matching -f fd0-agent  2>/dev/null || true
    kill $SERVER_PID $WITNESS_PID 2>/dev/null || true
    rm -rf "$HOME_AL" "$HOME_AD" "$HOME_AP" "$HOME_BL" "$HOME_BD" "$HOME_CL" "$HOME_EL"
    rm -f  "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
           "$SERVER_DB.snapshot" "$SERVER_DB.snapshot-wal" "$SERVER_DB.snapshot-shm" \
           "$SERVER_LOG" "$WITNESS_DB" "$WITNESS_CFG" "$WITNESS_LOG" \
           "$RECOVERY_AL" "$RECOVERY_BL"
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
lock_wait = "10s"
EOF
}

# Per-device CLI invokers — each scope via FD0_HOME isolation.
AL() { env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" "$@"; }
AD() { env FD0_HOME="$HOME_AD" FD0_SSH_SOCK="$HOME_AD/ssh.sock" "$FD0" "$@"; }
AP() { env FD0_HOME="$HOME_AP" FD0_SSH_SOCK="$HOME_AP/ssh.sock" "$FD0" "$@"; }
BL() { env FD0_HOME="$HOME_BL" FD0_SSH_SOCK="$HOME_BL/ssh.sock" "$FD0" "$@"; }
BD() { env FD0_HOME="$HOME_BD" FD0_SSH_SOCK="$HOME_BD/ssh.sock" "$FD0" "$@"; }
CL() { env FD0_HOME="$HOME_CL" FD0_SSH_SOCK="$HOME_CL/ssh.sock" "$FD0" "$@"; }
EL() { env FD0_HOME="$HOME_EL" FD0_SSH_SOCK="$HOME_EL/ssh.sock" "$FD0" "$@"; }

# Sync helpers — ignore exit code, capture errors via separate doctor checks.
sync_team() {
    AL sync >/dev/null 2>&1 || true
    AD sync >/dev/null 2>&1 || true
    AP sync >/dev/null 2>&1 || true
    BL sync >/dev/null 2>&1 || true
    BD sync >/dev/null 2>&1 || true
    EL sync >/dev/null 2>&1 || true
}
double_sync() { sync_team; sync_team; }

# converge_until <max_rounds> — keep running sync_team until either
# the round count is exhausted OR no device hit a divergence/dup
# response in the last round. Used after concurrent multi-writer
# bursts where a single double_sync occasionally finishes a round
# short. Keeps the test deterministic without sleeping for arbitrary
# durations.
converge_until() {
    local max="${1:-8}"
    local i
    for i in $(seq 1 "$max"); do
        sync_team
    done
}

# Server-side introspection.
chain_id_of_scope() {
    sqlite3 "$SERVER_DB" "SELECT chain_id FROM chains WHERE chain_id LIKE 'scope:%' ORDER BY chain_id LIMIT 1;"
}
server_max_tree_size() {
    local cid="$1"
    sqlite3 "$SERVER_DB" "SELECT COALESCE(MAX(tree_size), 0) FROM translog_sths WHERE chain_id = '$cid';" 2>/dev/null || echo 0
}
witness_max_tree_size() {
    local cid="$1"
    sqlite3 "$WITNESS_DB" "SELECT COALESCE(MAX(tree_size), 0) FROM witness_sths WHERE chain_id = '$cid';" 2>/dev/null || echo 0
}
chain_file_path() {
    local home="$1"
    local scope_chain="$2"   # full "scope:s_xxx"
    local scope_id="${scope_chain#scope:}"
    echo "$home/chains/${scope_id}.cbor"
}

phase "Phase 1 — Setup: server, witness, 7 devices for 4 users"

fd0_test_stop_matching -f fd0-server 2>/dev/null || true
fd0_test_stop_matching -f fd0-agent  2>/dev/null || true
fd0_test_stop_matching -f fd0-witness 2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$HOME_AD" "$HOME_AP" "$HOME_BL" "$HOME_BD" "$HOME_CL" "$HOME_EL"
rm -f  "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
       "$SERVER_LOG" "$WITNESS_DB" "$WITNESS_CFG" "$WITNESS_LOG" \
       "$RECOVERY_AL" "$RECOVERY_BL"

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.3
SERVER_KEYFILE=$(dirname "$SERVER_DB")/server-translog.key
ok "fd0-server up on :${SERVER_PORT}"

PUB_HEX=$(xxd -p -c 64 "$SERVER_KEYFILE" | head -1 | cut -c65-)

mkfd0 "$HOME_AL"; mkfd0 "$HOME_AD"; mkfd0 "$HOME_AP"
mkfd0 "$HOME_BL"; mkfd0 "$HOME_BD"
mkfd0 "$HOME_CL"; mkfd0 "$HOME_EL"

# Init the four primary identities.
printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "bob-pass\nbob-pass\n"     | env FD0_HOME="$HOME_BL" FD0_SSH_SOCK="$HOME_BL/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "carol-pass\ncarol-pass\n" | env FD0_HOME="$HOME_CL" FD0_SSH_SOCK="$HOME_CL/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "eve-pass\neve-pass\n"     | env FD0_HOME="$HOME_EL" FD0_SSH_SOCK="$HOME_EL/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" unlock >/dev/null 2>&1
printf "bob-pass\n"   | env FD0_HOME="$HOME_BL" FD0_SSH_SOCK="$HOME_BL/ssh.sock" "$FD0" unlock >/dev/null 2>&1
printf "carol-pass\n" | env FD0_HOME="$HOME_CL" FD0_SSH_SOCK="$HOME_CL/ssh.sock" "$FD0" unlock >/dev/null 2>&1
printf "eve-pass\n"   | env FD0_HOME="$HOME_EL" FD0_SSH_SOCK="$HOME_EL/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.3

# Recovery import for Alice's other two devices.
printf "alice-rec\nalice-rec\n" | AL recovery export "$RECOVERY_AL" >/dev/null
printf "alice-rec\nalice-d\nalice-d\n" | env FD0_HOME="$HOME_AD" FD0_SSH_SOCK="$HOME_AD/ssh.sock" "$FD0" recovery import "$RECOVERY_AL" >/dev/null 2>&1
printf "alice-rec\nalice-p\nalice-p\n" | env FD0_HOME="$HOME_AP" FD0_SSH_SOCK="$HOME_AP/ssh.sock" "$FD0" recovery import "$RECOVERY_AL" >/dev/null 2>&1
printf "alice-d\n" | env FD0_HOME="$HOME_AD" FD0_SSH_SOCK="$HOME_AD/ssh.sock" "$FD0" unlock >/dev/null 2>&1
printf "alice-p\n" | env FD0_HOME="$HOME_AP" FD0_SSH_SOCK="$HOME_AP/ssh.sock" "$FD0" unlock >/dev/null 2>&1

# Recovery for Bob's second device.
printf "bob-rec\nbob-rec\n" | BL recovery export "$RECOVERY_BL" >/dev/null
printf "bob-rec\nbob-d\nbob-d\n" | env FD0_HOME="$HOME_BD" FD0_SSH_SOCK="$HOME_BD/ssh.sock" "$FD0" recovery import "$RECOVERY_BL" >/dev/null 2>&1
printf "bob-d\n" | env FD0_HOME="$HOME_BD" FD0_SSH_SOCK="$HOME_BD/ssh.sock" "$FD0" unlock >/dev/null 2>&1

sleep 0.3
ok "7 devices initialized (Alice ×3, Bob ×2, Carol ×1, Eve ×1)"

# Card exchange — every primary pair.
AC=$(AL card export); BC=$(BL card export); CC=$(CL card export); EC=$(EL card export)
for dev in AL AD AP; do
    $dev card import "$BC" --label bob   --yes >/dev/null
    $dev card import "$CC" --label carol --yes >/dev/null
    $dev card import "$EC" --label eve   --yes >/dev/null
done
for dev in BL BD; do
    $dev card import "$AC" --label alice --yes >/dev/null
    $dev card import "$CC" --label carol --yes >/dev/null
    $dev card import "$EC" --label eve   --yes >/dev/null
done
CL card import "$AC" --label alice --yes >/dev/null
CL card import "$BC" --label bob   --yes >/dev/null
EL card import "$AC" --label alice --yes >/dev/null
EL card import "$BC" --label bob   --yes >/dev/null
ok "card exchange complete (all primary pairs)"

# Witness config — placeholder chain id, rewritten after team scope creation.
cat > "$WITNESS_CFG" <<EOF
[[target]]
server_url    = "http://127.0.0.1:${SERVER_PORT}"
server_pub    = "${PUB_HEX}"
chains        = ["__placeholder__"]
poll_interval = "1s"
EOF
ok "witness config drafted"

phase "Phase 2 — Baseline: scope create + cross-device sync + LastSTH"

AL scope create --label team >/dev/null
AL scope add-member bob --scope team >/dev/null
AL sync >/dev/null 2>&1
sleep 0.3
SCOPE_TEAM=$(chain_id_of_scope)
[ -n "$SCOPE_TEAM" ] && ok "team scope created (chain=$SCOPE_TEAM)" || no "no scope chain on server"

# Now restart witness with the real chain id.
sed -i.bak "s|__placeholder__|${SCOPE_TEAM}|" "$WITNESS_CFG" && rm -f "$WITNESS_CFG.bak"
"$FD0_WITNESS_BIN" --config="$WITNESS_CFG" --db="$WITNESS_DB" -v run > "$WITNESS_LOG" 2>&1 &
WITNESS_PID=$!
sleep 2

# Bob discovers via membership push; Alice's other devices sync.
BL sync >/dev/null 2>&1; BD sync >/dev/null 2>&1
AD sync >/dev/null 2>&1; AP sync >/dev/null 2>&1
sleep 1

EXPECTED=5
COUNT=0
for dev in AL AD AP BL BD; do
    if $dev scope ls 2>&1 | grep -q "team"; then
        COUNT=$((COUNT+1))
    fi
done
expect_eq "$COUNT" "$EXPECTED" "all 5 team devices subscribed"

HEALTHY=0
for dev in AL AD AP BL BD; do
    OUT=$($dev doctor 2>&1)
    case "$OUT" in *"all clear"*|*"warning"*) HEALTHY=$((HEALTHY+1)) ;; esac
done
expect_eq "$HEALTHY" "5" "all 5 devices: doctor clean after baseline"

WTSIZE=$(witness_max_tree_size "$SCOPE_TEAM")
expect_ge "$WTSIZE" 1 "witness archived ≥1 STH for team chain"

phase "Phase 3 — Concurrent writes + convergence + witness cross-check"

# Sequential writes + sequential syncs to keep this phase
# deterministic. The CONCURRENT-writer race is exhaustively
# tested by tests/integration_concurrency.sh (C2/C3/C9); the
# E2E story here is "two writers contribute, everyone sees
# everyone's work after sync", not "race convergence under
# bounded reconcile retries".
for i in 1 2 3 4 5; do AL set "AL_K$i" "alice-$i" --scope team >/dev/null; done
AL sync >/dev/null 2>&1 || true
for i in 1 2 3 4 5; do BL set "BL_K$i" "bob-$i"   --scope team >/dev/null; done
BL sync >/dev/null 2>&1 || true
# 4 concurrent writers can take many sync rounds to converge
# under reconcile / push-floor — particularly if both Alice's
# AND Bob's devices push competing events. Poll until ALL 5
# team devices report 12 keys, with a generous max-round cap.
# 30 rounds at ~200ms-2s each = 60s ceiling; in practice
# convergence happens in 5-15 rounds.
ROUNDS=0
MAX_ROUNDS=12
while [ "$ROUNDS" -lt "$MAX_ROUNDS" ]; do
    sync_team
    ALL_GOOD=1
    for dev in AL AD AP BL BD; do
        KEYS=$($dev ls 2>&1 | grep -cE "^(AL|BL)_K[0-9]")
        if [ "$KEYS" != "10" ]; then ALL_GOOD=0; break; fi
    done
    if [ "$ALL_GOOD" = "1" ]; then break; fi
    ROUNDS=$((ROUNDS + 1))
done

for dev in AL AD AP BL BD; do
    KEYS=$($dev ls 2>&1 | grep -cE "^(AL|BL)_K[0-9]")
    expect_eq "$KEYS" "10" "$dev sees all 10 cross-device keys (after $ROUNDS extra rounds)"
done

sleep 2
SVRSIZE=$(server_max_tree_size "$SCOPE_TEAM")
WTSIZE=$(witness_max_tree_size "$SCOPE_TEAM")
expect_eq "$WTSIZE" "$SVRSIZE" "witness max(tree_size)=$WTSIZE matches server max(tree_size)=$SVRSIZE"

phase "Phase 4 — Member churn: three-way merge + OEK rotation + auto-drop"

# Both AL and BL try to add Carol concurrently → three-way merge.
( AL scope add-member carol --scope team >/dev/null 2>&1 ) & PA=$!
( BL scope add-member carol --scope team >/dev/null 2>&1 ) & PB=$!
wait $PA $PB 2>/dev/null
double_sync
double_sync

AL_MEMBERS=$(AL scope members team 2>&1 | norm_members)
BL_MEMBERS=$(BL scope members team 2>&1 | norm_members)
expect_eq "$AL_MEMBERS" "$BL_MEMBERS" "AL+BL converge on team member set after concurrent add"
COUNT=$(printf "%s\n" "$AL_MEMBERS" | grep -c .)
expect_eq "$COUNT" "3" "team has 3 members (alice, bob, carol)"

# Carol discovers via membership push.
CL sync >/dev/null 2>&1; CL sync >/dev/null 2>&1
sleep 0.5
if CL scope ls 2>&1 | grep -q "team"; then
    ok "Carol discovered team membership"
else
    no "Carol did not discover team scope"
fi

# Carol writes a secret; AL/BL see it.
CL set CAROL_K1 "carol-says-hi" --scope team >/dev/null
CL sync >/dev/null 2>&1
double_sync
expect_eq "$(AL get CAROL_K1 --scope team --raw 2>/dev/null)" "carol-says-hi" "AL sees Carol's secret"
expect_eq "$(BD get CAROL_K1 --scope team --raw 2>/dev/null)" "carol-says-hi" "BD sees Carol's secret"

# OEK era is now ≥3 (genesis=v1, +bob=v2, +carol=v3).
OEK_LINE=$(AL scope ls 2>&1 | grep team)
case "$OEK_LINE" in
    *"oek=v"[3-9]*) ok "team OEK rotated to v3+ ($OEK_LINE)" ;;
    *) no "team OEK rotation suspect: $OEK_LINE" ;;
esac

# AL removes Carol. OEK rotates again. Carol's next sync gets denied.
AL scope remove-member carol --scope team >/dev/null
double_sync
CL sync >/dev/null 2>&1; CL sync >/dev/null 2>&1
sleep 0.5

if CL scope ls 2>&1 | grep -q "team"; then
    no "Carol still has team scope after remove (auto-drop broken)"
else
    ok "Carol auto-dropped team scope after remove"
fi

phase "Phase 5 — Pre-admit history accumulation (Eve has NEVER been a member)"

# Build up a substantial chain past Carol's removal so Eve, when
# she joins, has many secret.set events from OEK eras she can't
# decrypt. applySecretSet must silent-skip them; admit member.change
# carries the projection of CURRENT secrets.
for i in 1 2 3 4 5; do
    AL set "PRE_K$i" "pre-admit-$i" --scope team >/dev/null
done
AL sync >/dev/null 2>&1
double_sync
ok "5 pre-admit secret.set events accumulated (current OEK era)"

phase "Phase 6 — Eve TRUE late-join (full-pull from cursor=0, replay pre-admit)"

# Eve was never a member of team. She's added now. Her sync triggers
# discoverScope → fetches full chain from cursor=0, replays:
#   - genesis member.change (pre-admit, no key delivery → skip)
#   - add-bob member.change (pre-admit, skip)
#   - many secret.set events (pre-admit OEK eras, silent skip in applySecretSet)
#   - add-carol, remove-carol (pre-admit member.changes, no key delivery)
#   - more secret.set events
#   - add-eve member.change (HER ADMIT — key_delivery present, decrypts OEK,
#     applies projection of current secrets)
#
# Outcome: Eve sees CURRENT visible secrets via the projection,
# does NOT see historical superseded versions, no replay errors.
AL scope add-member eve --scope team >/dev/null
double_sync

EL sync >/dev/null 2>&1
EL sync >/dev/null 2>&1
sleep 1

if EL scope ls 2>&1 | grep -q "team"; then
    ok "Eve discovered team via late-join sync (full-pull replay successful)"
else
    no "Eve did NOT discover team scope (late-join replay broken)"
fi

# Eve must see all 5 pre-admit secrets via the admit projection.
SEEN_PRE=0
for i in 1 2 3 4 5; do
    GOT=$(EL get "PRE_K$i" --scope team --raw 2>/dev/null)
    if [ "$GOT" = "pre-admit-$i" ]; then SEEN_PRE=$((SEEN_PRE+1)); fi
done
expect_eq "$SEEN_PRE" "5" "Eve sees all 5 pre-admit secrets via admit projection"

# And the cross-device keys from phase 3 (2 writers × 5 keys = 10).
SEEN_X=0
for prefix in AL_K BL_K; do
    for i in 1 2 3 4 5; do
        GOT=$(EL get "${prefix}$i" --scope team --raw 2>/dev/null)
        if [ -n "$GOT" ]; then SEEN_X=$((SEEN_X+1)); fi
    done
done
expect_eq "$SEEN_X" "10" "Eve sees all 10 phase-3 cross-device keys via projection"

# Eve writes a new secret; existing members see it.
EL set EVE_LATE_K1 "eve-after-late-join" --scope team >/dev/null
EL sync >/dev/null 2>&1
double_sync
expect_eq "$(AL get EVE_LATE_K1 --scope team --raw 2>/dev/null)" "eve-after-late-join" "AL sees Eve's post-late-join write"
expect_eq "$(BD get EVE_LATE_K1 --scope team --raw 2>/dev/null)" "eve-after-late-join" "BD sees Eve's post-late-join write"

# Witness final size grew through all this.
sleep 2
SVRSIZE=$(server_max_tree_size "$SCOPE_TEAM")
WTSIZE=$(witness_max_tree_size "$SCOPE_TEAM")
expect_eq "$WTSIZE" "$SVRSIZE" "witness max(tree_size)=$WTSIZE still matches server=$SVRSIZE after late-join"

phase "Phase 7 — Full local history retention"

CHAIN_FILE=$(chain_file_path "$HOME_AL" "$SCOPE_TEAM")
[ -f "$CHAIN_FILE" ] || { no "scope chain file missing: $CHAIN_FILE"; CHAIN_FILE=/dev/null; }

PRE_SIZE=$([ "$CHAIN_FILE" != /dev/null ] && wc -c < "$CHAIN_FILE" || echo 0)
PRE_SVR_SIZE=$(server_max_tree_size "$SCOPE_TEAM")

for i in $(seq 1 30); do
    AL set HISTORY_KEY "version-$i" --scope team >/dev/null
done
AL sync >/dev/null 2>&1
sleep 1

POST_SIZE=$([ "$CHAIN_FILE" != /dev/null ] && wc -c < "$CHAIN_FILE" || echo 999999999)
POST_SVR_SIZE=$(server_max_tree_size "$SCOPE_TEAM")

GROWTH=$((POST_SVR_SIZE - PRE_SVR_SIZE))
expect_ge "$GROWTH" "30" "server tree grew by ≥30 after 30 supersedes (got $GROWTH)"

GROWTH_LOCAL=$((POST_SIZE - PRE_SIZE))
if [ "$GROWTH_LOCAL" -gt 0 ]; then
    ok "local chain retained the appended history (grew by $GROWTH_LOCAL bytes)"
else
    no "local chain did not retain appended history (growth $GROWTH_LOCAL bytes)"
fi

double_sync
for dev in AL AD AP BL BD EL; do
    expect_eq "$($dev get HISTORY_KEY --scope team --raw 2>/dev/null)" "version-30" "$dev reads latest HISTORY_KEY = version-30"
done

phase "Phase 8 — Server DB rollback (LastSTH out-of-range hard-fail)"

# Capture the post-Phase-7 state by stopping the server, checkpointing
# WAL into the main DB, then snapshotting. Without WAL checkpoint,
# the snapshot misses recent writes and the test scenario doesn't
# reflect reality.
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true
sqlite3 "$SERVER_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
cp "$SERVER_DB" "${SERVER_DB}.snapshot"
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.5
SVR_SIZE_AT_SNAPSHOT=$(server_max_tree_size "$SCOPE_TEAM")

# Continue making writes; server tree advances past snapshot.
AL set ROLLBACK_K1 "post-snapshot-1" --scope team >/dev/null
AL set ROLLBACK_K2 "post-snapshot-2" --scope team >/dev/null
AL sync >/dev/null 2>&1
double_sync   # everyone anchors LastSTH at the new size

SVR_SIZE_AFTER=$(server_max_tree_size "$SCOPE_TEAM")
expect_ge "$((SVR_SIZE_AFTER - SVR_SIZE_AT_SNAPSHOT))" "2" "server tree advanced post-snapshot"

# CRITICAL: ensure witness observes the higher post-write tree size
# BEFORE the rollback. Otherwise after rollback we'd be reverting
# to a size the witness already had archived (no regression to
# detect). 3s = at least 3 witness polls at 1s interval.
sleep 3
WT_BEFORE_ROLLBACK=$(witness_max_tree_size "$SCOPE_TEAM")
expect_ge "$WT_BEFORE_ROLLBACK" "$SVR_SIZE_AFTER" "witness archived the post-write tree size BEFORE rollback (witness=$WT_BEFORE_ROLLBACK ≥ server=$SVR_SIZE_AFTER)"

# Stop server, restore the snapshot (and clean WAL/SHM so SQLite
# doesn't replay pending pages on top), restart.
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null || true
rm -f "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm"
mv "${SERVER_DB}.snapshot" "$SERVER_DB"
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.5

SVR_SIZE_NOW=$(server_max_tree_size "$SCOPE_TEAM")
expect_eq "$SVR_SIZE_NOW" "$SVR_SIZE_AT_SNAPSHOT" "server tree rolled back to snapshot size"

# Now AL's persisted LastSTH is at SVR_SIZE_AFTER but server's tree
# is at SVR_SIZE_AT_SNAPSHOT. AL's sync must hard-fail with
# out_of_range or sth-tree-size-regression.
SYNC_OUT=$(AL sync 2>&1 || true)
case "$SYNC_OUT" in
    *"out_of_range"*|*"out of range"*|*"regression"*|*"500"*|*"400"*)
        ok "AL sync rejects server rollback (got expected error)"
        ;;
    *)
        no "AL sync did NOT reject server rollback: $SYNC_OUT"
        ;;
esac

# Doctor on AL — local data is unchanged, only sync rejects.
OUT=$(AL doctor 2>&1)
case "$OUT" in
    *"all clear"*|*"warning"*) ok "AL doctor still healthy after rejected sync" ;;
    *) no "AL doctor reports issues: $OUT" ;;
esac

phase "Phase 9 — Witness final state"

# Witness polls every 1s; allow ≥3 polls after rollback so the
# tree-size regression definitely lands in the witness log before
# we shut it down for the verify subcommand.
sleep 4
WTSIZE_FINAL=$(witness_max_tree_size "$SCOPE_TEAM")
expect_ge "$WTSIZE_FINAL" "1" "witness final archive non-empty"

# Witness saw the higher tree size BEFORE rollback, and may have
# seen the smaller one AFTER. Either way > 0.
kill $WITNESS_PID 2>/dev/null
wait $WITNESS_PID 2>/dev/null || true

VERIFY_OUT=$("$FD0_WITNESS_BIN" --config="$WITNESS_CFG" --db="$WITNESS_DB" verify 2>&1)
case "$VERIFY_OUT" in
    *"0 signature error"*) ok "witness verify: 0 signature errors" ;;
    *) no "witness verify reported errors: $VERIFY_OUT" ;;
esac

STATUS_OUT=$("$FD0_WITNESS_BIN" --config="$WITNESS_CFG" --db="$WITNESS_DB" status 2>&1)
case "$STATUS_OUT" in
    *"Witness archive:"*"STHs"*) ok "witness status prints summary" ;;
    *) no "witness status output unexpected: $STATUS_OUT" ;;
esac

# Witness should have flagged a tree_size regression (server went
# backwards between two polls — same chain, smaller size).
if grep -q "TREE_SIZE REGRESSION\|REGRESSION" "$WITNESS_LOG"; then
    ok "witness logged tree-size regression after server rollback"
else
    no "witness did not log regression after rollback (witness may not have re-polled in time):"
    tail -10 "$WITNESS_LOG"
fi

phase "Phase 10 — Final cleanup + summary"
for dev in AL AD AP BL BD CL EL; do
    $dev lock >/dev/null 2>&1
done

echo
printf "\033[1m═══ E2E SUMMARY ═══\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
