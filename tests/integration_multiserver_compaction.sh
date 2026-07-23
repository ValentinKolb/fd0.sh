#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
# Multi-server compaction safety smoke.
#
# Reproduces the reported production failure: with TWO configured
# replicas, local chain compaction (which rewrites the shared chain into
# a non-contiguous form) must NOT run while either replica is behind —
# otherwise the lagging replica can no longer fast-forward the gapped
# chain and is forced into an unrecoverable divergence
# ("rebuilt-push verify: no local event at seq N").
#
# The fix gates compaction in RunSyncAll on ALL replicas converging.
# This test asserts that gate three ways:
#
#   1. Both replicas up + many overwrites → sync converges, compaction
#      DOES fire (all converged), no divergence, replica 2 reads the
#      correct final value.
#   2. Replica 2 down + many overwrites → compaction is SUPPRESSED
#      (no "compacted scope" line), local writes intact.
#   3. Replica 2 back → sync converges cleanly with NO
#      "no local event at seq" / "failed reconcile" — the regression.
#
# Run after `go install ./cmd/...`.

set -uo pipefail
export FD0_AUTO_PIN=1

BASE=/tmp/fd0-multiserver-compaction
FD0=$HOME/go/bin/fd0
FD0_AGENT_BIN=$HOME/go/bin/fd0-agent
FD0_SERVER_BIN=$HOME/go/bin/fd0-server

PORT1=14060
PORT2=14061
URL1=http://localhost:$PORT1
URL2=http://localhost:$PORT2

HOME_BACKUP=$HOME
export FD0_AGENT_BIN

S2_PID=""

cleanup() {
  fd0_test_stop_matching -f "$FD0_SERVER_BIN" 2>/dev/null
  fd0_test_stop_matching -f "$FD0_AGENT_BIN"  2>/dev/null
  sleep 0.3
  export HOME=$HOME_BACKUP
}
trap cleanup EXIT
cleanup
rm -rf "$BASE"
mkdir -p "$BASE/server1" "$BASE/server2" "$BASE/alice-home" "$BASE/bob-home"

PASS=0; FAIL=0
phase() { printf "\n\033[1m═══ %s ═══\033[0m\n" "$*"; }
ok()    { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()    { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

as() { # as <who> <args...>
  local who=$1; shift
  FD0_HOME=$BASE/$who \
  HOME=$BASE/$who-home \
  FD0_SSH_SOCK=$BASE/$who.sock \
    "$FD0" "$@"
}

start_server2() {
  FD0_BIND=:$PORT2 FD0_DB=$BASE/server2/fd0.db FD0_RATELIMIT_OFF=1 \
    "$FD0_SERVER_BIN" > "$BASE/server2.log" 2>&1 &
  S2_PID=$!
  for i in 1 2 3 4 5; do curl -sf $URL2/health >/dev/null && break; sleep 0.3; done
}

# ─────────────────────────────────────────────────────────────
phase "Boot both servers"
FD0_BIND=:$PORT1 FD0_DB=$BASE/server1/fd0.db FD0_RATELIMIT_OFF=1 \
  "$FD0_SERVER_BIN" > "$BASE/server1.log" 2>&1 &
start_server2
curl -sf $URL1/health >/dev/null && ok "server1 up" || no "server1 down"
curl -sf $URL2/health >/dev/null && ok "server2 up" || no "server2 down"

# ─────────────────────────────────────────────────────────────
phase "Init alice (both replicas) + bob (replica 2 only)"
mkdir -p "$BASE/alice" "$BASE/bob"
cat > "$BASE/alice/config.toml" <<EOF
[sync]
servers = ["$URL1", "$URL2"]
on_unlock = false
EOF
cat > "$BASE/bob/config.toml" <<EOF
[sync]
server = "$URL2"
on_unlock = false
EOF

for who in alice bob; do
  printf "%s-pass\n%s-pass\n" "$who" "$who" | as "$who" init > "$BASE/$who-init.log" 2>&1 \
    && ok "$who init" || { no "$who init"; tail "$BASE/$who-init.log"; }
  printf "%s-pass\n" "$who" | as "$who" unlock > "$BASE/$who-unlock.log" 2>&1 \
    && ok "$who unlock" || no "$who unlock"
  as "$who" sync > /dev/null 2>&1 && ok "$who register" || no "$who register"
done

# ─────────────────────────────────────────────────────────────
phase "Share scope: alice adds bob"
as alice scope create --label shared > /dev/null 2>&1 && ok "scope created" || no "scope create"
BOB_CARD=$(as bob card export 2>/dev/null | grep '^fd0://card/')
ALICE_CARD=$(as alice card export 2>/dev/null | grep '^fd0://card/')
[[ -n "$BOB_CARD" && -n "$ALICE_CARD" ]] && ok "cards exported" || no "card export"
as alice card import "$BOB_CARD" --label bob --yes > /dev/null 2>&1 && ok "alice pins bob" || no "pin bob"
as bob   card import "$ALICE_CARD" --label alice --yes > /dev/null 2>&1 && ok "bob pins alice" || no "pin alice"
as alice scope add-member bob --scope shared > /dev/null 2>&1 && ok "bob added" || no "add-member"
as alice sync > /dev/null 2>&1 && ok "alice sync (publish)" || no "alice sync"
as bob   sync > /dev/null 2>&1 && ok "bob sync (discover)" || no "bob sync"

getval() { as "$1" get K --scope shared 2>/dev/null; }
overwrite() { # overwrite <who> <count> <prefix>
  local who=$1 n=$2 pre=$3 i
  for ((i=1;i<=n;i++)); do
    as "$who" set K "$pre-$i-payload-padding-to-make-the-set-event-nontrivial-in-size" --scope shared >/dev/null 2>&1
  done
}

# Run scenario A from a CLEAN converged state (no compaction has run
# yet, local chain is fully contiguous). This is what makes the bite
# deterministic: at the moment of the degraded sync, server1 is up and —
# under the OLD per-server-compaction behavior — WILL compact the shared
# chain even though server2 is behind, gapping it and breaking the later
# replica catch-up. The fix suppresses that compaction.

# ─────────────────────────────────────────────────────────────
phase "1) Replica 2 DOWN from a clean state: overwrite ×60 → compaction must be SUPPRESSED"
kill "$S2_PID" 2>/dev/null; wait "$S2_PID" 2>/dev/null
sleep 0.3
curl -sf $URL2/health >/dev/null 2>&1 && no "server2 still up (should be down)" || ok "server2 down"

overwrite alice 60 b
# Also write SEVERAL DISTINCT live secrets, each overwritten, so the
# recovery reconcile has to rebuild multiple secret.set events (the
# user's failing path was a secret.set rebuild, not a member.change).
for k in K2 K3 K4; do
  as alice set "$k" "$k-old"   --scope shared >/dev/null 2>&1
  as alice set "$k" "$k-final" --scope shared >/dev/null 2>&1
done
as alice sync > "$BASE/alice-sync-lag.log" 2>&1
# One replica failed → aggregate is still ok (>=1 success) but degraded.
# OLD behavior would print "compacted scope" here (server1 up); the gate
# must keep it absent while server2 is behind.
grep -qi "compacted scope" "$BASE/alice-sync-lag.log" \
  && no "compaction fired while replica 2 was behind (DATA-SAFETY REGRESSION)" \
  || ok "compaction suppressed while a replica is behind"
[[ "$(getval alice)" == "b-60-"* ]] && ok "alice newest value intact after degraded sync" || no "alice value lost"

# ─────────────────────────────────────────────────────────────
phase "2) Replica 2 BACK: sync converges cleanly (the regression)"
start_server2
curl -sf $URL2/health >/dev/null && ok "server2 back up" || no "server2 restart failed"
as alice sync > "$BASE/alice-sync-recover.log" 2>&1
RC=$?
grep -qi "no local event at seq\|failed reconcile\|rebuilt-push verify" "$BASE/alice-sync-recover.log" \
  && { no "REGRESSION: lagging replica forced into unrecoverable divergence"; cat "$BASE/alice-sync-recover.log"; } \
  || ok "no unrecoverable divergence on replica catch-up"
[[ $RC -eq 0 ]] && ok "recovery sync exit 0" || { no "recovery sync failed"; cat "$BASE/alice-sync-recover.log"; }
as bob sync > /dev/null 2>&1
[[ "$(getval bob)" == "b-60-"* ]] && ok "bob (replica 2) caught up to newest K" || no "replica 2 did not catch up on K"
for k in K2 K3 K4; do
  [[ "$(as bob get "$k" --scope shared 2>/dev/null)" == "$k-final" ]] \
    && ok "bob converged: $k=$k-final" || no "replica 2 missing rebuilt secret $k"
done

# ─────────────────────────────────────────────────────────────
phase "3) Both replicas up: overwrite ×60 then sync → converged compaction fires"
overwrite alice 60 c
as alice sync > "$BASE/alice-sync-conv.log" 2>&1
RC=$?
[[ $RC -eq 0 ]] && ok "alice sync exit 0 (both replicas)" || { no "alice sync failed"; cat "$BASE/alice-sync-conv.log"; }
grep -qi "compacted scope" "$BASE/alice-sync-conv.log" \
  && ok "compaction fires once all replicas converged" \
  || no "expected compaction after all-converged sync"
grep -qi "no local event at seq\|failed reconcile" "$BASE/alice-sync-conv.log" \
  && no "unexpected reconcile failure in converged sync" \
  || ok "no reconcile failure in converged sync"
[[ "$(getval alice)" == "c-60-"* ]] && ok "alice final value correct" || no "alice value wrong"
as bob sync > /dev/null 2>&1
[[ "$(getval bob)" == "c-60-"* ]] && ok "bob (replica 2) converged to final value" || no "bob did not converge"

# ─────────────────────────────────────────────────────────────
phase "4) Foreign-authored event survives reconcile against a lagging replica (F1)"
# bob writes a secret and syncs to server2 ONLY → server2 gets a tip that
# server1 lacks, and the event is authored by bob (foreign to alice).
as bob set BOBSECRET "bob-only-value" --scope shared >/dev/null 2>&1 && ok "bob set BOBSECRET" || no "bob set"
as bob sync >/dev/null 2>&1 && ok "bob sync (server2 only)" || no "bob sync"
# alice writes her own secret, then syncs BOTH. server1 accepts alice's
# event; server2 diverges (bob's tip) → reconcile pulls bob's secret and
# rebuilds alice's on server2's lineage. alice now holds bob's foreign
# event locally, on a lineage that diverges from server1.
as alice set AK "alice-value" --scope shared >/dev/null 2>&1 && ok "alice set AK" || no "alice set"
as alice sync > "$BASE/alice-f1-first.log" 2>&1
[[ "$(as alice get BOBSECRET --scope shared 2>/dev/null)" == "bob-only-value" ]] \
  && ok "alice pulled bob's foreign secret via server2" || no "alice did not get bob's secret"
# Second sync: alice's server2-lineage tip now diverges from server1.
# The reconcile against the lagging server1 must REFUSE rather than drop
# bob's foreign-authored event (which alice cannot rebuild/re-push).
as alice sync > "$BASE/alice-f1-second.log" 2>&1
grep -qi "authored by other members\|refusing to reconcile" "$BASE/alice-f1-second.log" \
  && ok "reconcile against lagging replica refused (foreign event protected)" \
  || printf "  \033[33m▸\033[0m note: server1 did not diverge this run; survival still asserted below\n"
[[ "$(as alice get BOBSECRET --scope shared 2>/dev/null)" == "bob-only-value" ]] \
  && ok "bob's foreign secret SURVIVED the reconcile (no data loss)" || no "DATA LOSS: bob's foreign secret dropped"
[[ "$(as alice get AK --scope shared 2>/dev/null)" == "alice-value" ]] \
  && ok "alice's own secret intact" || no "alice's own secret lost"

# Final convergence + doctor
as alice doctor > "$BASE/alice-doctor.log" 2>&1 && ok "alice doctor clean" || no "alice doctor"
as bob   doctor > "$BASE/bob-doctor.log"   2>&1 && ok "bob doctor clean"   || no "bob doctor"

# ─────────────────────────────────────────────────────────────
phase "Summary"
echo "    PASS=$PASS  FAIL=$FAIL"
[[ $FAIL -gt 0 ]] && exit 1 || exit 0
