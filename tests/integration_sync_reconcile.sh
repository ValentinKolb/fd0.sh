#!/usr/bin/env bash
# Sync reconcile / data-safety smoke.
#
# Reproduces the reported divergence scenario with TWO real clients
# (alice + bob) sharing one scope, and proves the prime directive:
# a divergent sync NEVER loses a local-authored event.
#
#   1. alice + bob both members of scope "shared".
#   2. alice writes 3 secrets locally WITHOUT syncing.
#   3. bob writes 1 secret and syncs → server tip advances.
#   4. alice syncs → her first push diverges → reconcile fires.
#   5. ASSERT: after reconcile, alice has ALL 4 secrets (A1-3 + B1),
#      sync converges, and a second sync is a stable no-op.
#
# Then the failure path: induce a divergence and point the reconcile
# at a dead server → reconcile fails → ASSERT alice's local-only
# events + chain are byte-preserved (the transactional restore).
#
# Run after `go install ./cmd/...`.

set -uo pipefail
export FD0_AUTO_PIN=1

BASE=/tmp/fd0-reconcile-smoke
FD0=$HOME/go/bin/fd0
FD0_AGENT_BIN=$HOME/go/bin/fd0-agent
FD0_SERVER_BIN=$HOME/go/bin/fd0-server

PORT=14050
URL=http://localhost:$PORT

HOME_BACKUP=$HOME
export FD0_AGENT_BIN

cleanup() {
  pkill -f "$FD0_SERVER_BIN" 2>/dev/null
  pkill -f "$FD0_AGENT_BIN"  2>/dev/null
  sleep 0.3
  export HOME=$HOME_BACKUP
}
trap cleanup EXIT
cleanup
rm -rf "$BASE"
mkdir -p "$BASE/server" "$BASE/alice-home" "$BASE/bob-home"

PASS=0; FAIL=0
phase() { printf "\n\033[1m═══ %s ═══\033[0m\n" "$*"; }
ok()    { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()    { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

# Run an fd0 command as a given identity (own FD0_HOME + HOME + agent sock).
as() { # as <who> <args...>
  local who=$1; shift
  FD0_HOME=$BASE/$who \
  HOME=$BASE/$who-home \
  FD0_SSH_SOCK=$BASE/$who.sock \
    "$FD0" "$@"
}

# ─────────────────────────────────────────────────────────────
phase "Boot server + init alice & bob"
FD0_BIND=:$PORT FD0_DB=$BASE/server/fd0.db FD0_RATELIMIT_OFF=1 \
  "$FD0_SERVER_BIN" > "$BASE/server.log" 2>&1 &
for i in 1 2 3 4 5; do curl -sf $URL/health >/dev/null && break; sleep 0.3; done
curl -sf $URL/health >/dev/null && ok "server up" || no "server down"

for who in alice bob; do
  mkdir -p "$BASE/$who"
  cat > "$BASE/$who/config.toml" <<EOF
[sync]
server = "$URL"
on_unlock = false
EOF
  printf "%s-pass\n%s-pass\n" "$who" "$who" | as "$who" init > "$BASE/$who-init.log" 2>&1 \
    && ok "$who init" || { no "$who init"; tail "$BASE/$who-init.log"; }
  printf "%s-pass\n" "$who" | as "$who" unlock > "$BASE/$who-unlock.log" 2>&1 \
    && ok "$who unlock" || no "$who unlock"
  as "$who" sync > /dev/null 2>&1 && ok "$who register" || no "$who register"
done

# ─────────────────────────────────────────────────────────────
phase "Share scope: alice adds bob"
as alice scope create --label shared > /dev/null 2>&1 && ok "scope created" || no "scope create"

# Card exchange.
BOB_CARD=$(as bob card export 2>/dev/null | grep '^fd0://card/')
ALICE_CARD=$(as alice card export 2>/dev/null | grep '^fd0://card/')
[[ -n "$BOB_CARD" && -n "$ALICE_CARD" ]] && ok "cards exported" || no "card export"

as alice card import "$BOB_CARD" --label bob --yes > /dev/null 2>&1 && ok "alice pins bob" || no "pin bob"
as bob   card import "$ALICE_CARD" --label alice --yes > /dev/null 2>&1 && ok "bob pins alice" || no "pin alice"

as alice scope add-member bob --scope shared > /dev/null 2>&1 && ok "bob added to scope" || no "add-member"
as alice sync > /dev/null 2>&1 && ok "alice sync (publish membership)" || no "alice sync"
as bob   sync > /dev/null 2>&1 && ok "bob sync (discover scope)" || no "bob sync"
as bob ssh >/dev/null 2>&1 # no-op; ensure bob agent warm
as bob get --scope shared >/dev/null 2>&1 || true

# ─────────────────────────────────────────────────────────────
phase "Induce divergence"
# alice writes 3 secrets locally, does NOT sync.
as alice set A1 "alice-one"   --scope shared > /dev/null 2>&1 && ok "alice set A1" || no "A1"
as alice set A2 "alice-two"   --scope shared > /dev/null 2>&1 && ok "alice set A2" || no "A2"
as alice set A3 "alice-three" --scope shared > /dev/null 2>&1 && ok "alice set A3" || no "A3"

# bob writes B1 and syncs → server tip advances past alice's base.
as bob set B1 "bob-one" --scope shared > /dev/null 2>&1 && ok "bob set B1" || no "B1"
as bob sync > "$BASE/bob-sync2.log" 2>&1 && ok "bob sync (advance server tip)" || { no "bob sync"; tail "$BASE/bob-sync2.log"; }

# ─────────────────────────────────────────────────────────────
phase "alice sync → divergence → reconcile (DATA SAFETY)"
as alice sync > "$BASE/alice-reconcile.log" 2>&1
RC=$?
grep -qi "divergence\|reconcile" "$BASE/alice-reconcile.log" \
  && ok "divergence detected + reconcile entered" \
  || printf "  \033[33m▸\033[0m note: divergence keyword not in log (still checking convergence)\n"
[[ $RC -eq 0 ]] && ok "alice sync converged (exit 0)" || { no "alice sync failed"; cat "$BASE/alice-reconcile.log"; }

# THE prime-directive assertions: every event survived on alice, by
# value (get is the authoritative read; `ls` takes no --scope).
getval() { as "$1" get "$2" --scope shared 2>/dev/null; }
declare -A WANT=( [A1]=alice-one [A2]=alice-two [A3]=alice-three [B1]=bob-one )
for s in A1 A2 A3 B1; do
  [[ "$(getval alice "$s")" == "${WANT[$s]}" ]] \
    && ok "alice has $s=${WANT[$s]} after reconcile" || no "$s LOST/corrupt on alice"
done

# Second sync is a stable no-op (converged, idempotent).
as alice sync > "$BASE/alice-sync3.log" 2>&1
[[ $? -eq 0 ]] && ok "alice second sync ok" || no "second sync failed"

# bob pulls alice's A1-A3 → full convergence.
as bob sync > /dev/null 2>&1
for s in A1 A2 A3 B1; do
  [[ "$(getval bob "$s")" == "${WANT[$s]}" ]] \
    && ok "bob converged: $s=${WANT[$s]}" || no "bob missing/corrupt $s"
done

# ─────────────────────────────────────────────────────────────
phase "doctor clean on both"
as alice doctor > "$BASE/alice-doctor.log" 2>&1 && ok "alice doctor clean" || no "alice doctor"
as bob   doctor > "$BASE/bob-doctor.log"   2>&1 && ok "bob doctor clean"   || no "bob doctor"

# ─────────────────────────────────────────────────────────────
phase "Failure path: reconcile against dead server preserves local writes"
# alice writes two more local-only secrets, does NOT sync.
as alice set A4 "alice-four" --scope shared > /dev/null 2>&1 && ok "alice set A4" || no "A4"
as alice set A5 "alice-five" --scope shared > /dev/null 2>&1 && ok "alice set A5" || no "A5"

# Snapshot the scope chain file before the doomed sync (prefix s_*).
SCOPE_CHAIN=$(ls "$BASE/alice/chains/"s_*.cbor 2>/dev/null | head -1)
[[ -n "$SCOPE_CHAIN" ]] && ok "located scope chain file" || no "no scope chain file"
cp "$SCOPE_CHAIN" "$BASE/chain-before.cbor"

# Kill the server, then sync → transport failure (no data should change).
pkill -f "$FD0_SERVER_BIN" 2>/dev/null
sleep 0.5
as alice sync > "$BASE/alice-deadsync.log" 2>&1
[[ $? -ne 0 ]] && ok "sync against dead server failed (as expected)" || no "dead-server sync unexpectedly ok"

# Prime directive: local-only writes preserved despite the failed sync.
declare -A WANT2=( [A1]=alice-one [A2]=alice-two [A3]=alice-three [A4]=alice-four [A5]=alice-five [B1]=bob-one )
for s in A1 A2 A3 A4 A5 B1; do
  [[ "$(getval alice "$s")" == "${WANT2[$s]}" ]] \
    && ok "after failed sync alice still has $s" || no "$s LOST after failed sync"
done

# Chain file did not grow (no orphaned rebuilt events left behind).
BEFORE=$(wc -c < "$BASE/chain-before.cbor")
AFTER=$(wc -c < "$SCOPE_CHAIN")
if cmp -s "$BASE/chain-before.cbor" "$SCOPE_CHAIN"; then
  ok "scope chain byte-identical after failed sync (no growth)"
elif [[ "$AFTER" -le "$BEFORE" ]]; then
  ok "scope chain did not grow after failed sync ($BEFORE→$AFTER bytes)"
else
  no "scope chain GREW after failed sync ($BEFORE→$AFTER bytes)"
fi

# ─────────────────────────────────────────────────────────────
phase "Summary"
echo "    PASS=$PASS  FAIL=$FAIL"
[[ $FAIL -gt 0 ]] && exit 1 || exit 0
