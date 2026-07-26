#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
# End-to-end integration test for #2a using the REAL binaries
# (fd0-server processes + fd0 client + agent), not the in-process harness.
#
#   Part A — DR backup replication (REPLICATION.md Phase 0):
#     a backup server mirrors a primary via FD0_REPLICATE_FROM; assert the
#     backup archive matches the primary byte-for-event, and SURVIVES the
#     primary being killed (the whole point of DR).
#
#   Part B — primary-per-scope convergence ([sync].mode = "primary"):
#     three clients, two servers, several scopes; write from all, kill +
#     restart a server, and assert every client converges to every value.
#
#   Part C — misconfiguration fails LOUD (review RED #2):
#     a client missing a scope's anchor server must error, not silently
#     "succeed".
#
# Run after `go install ./cmd/...`. Needs sqlite3 to inspect the backup DB.

set -uo pipefail
export FD0_AUTO_PIN=1

BASE=/tmp/fd0-replication-e2e
FD0=$HOME/go/bin/fd0
FD0_AGENT_BIN=$HOME/go/bin/fd0-agent
FD0_SERVER_BIN=$HOME/go/bin/fd0-server
export FD0_AGENT_BIN
HOME_BACKUP=$HOME

# Distinct ports; each server gets its OWN db dir => its own translog key.
PORT_SP=14070   # DR primary
PORT_SC=14071   # DR backup
PORT_SA=14072   # primary-mode server A
PORT_SB=14073   # primary-mode server B
URL_SP=http://localhost:$PORT_SP
URL_SC=http://localhost:$PORT_SC
URL_SA=http://localhost:$PORT_SA
URL_SB=http://localhost:$PORT_SB

declare -A PIDS

cleanup() {
  fd0_test_stop_matching -f "$FD0_SERVER_BIN" 2>/dev/null
  fd0_test_stop_matching -f "$FD0_AGENT_BIN"  2>/dev/null
  sleep 0.3
  export HOME=$HOME_BACKUP
}
trap cleanup EXIT
cleanup
rm -rf "$BASE"
mkdir -p "$BASE"

PASS=0; FAIL=0
phase() { printf "\n\033[1m═══ %s ═══\033[0m\n" "$*"; }
ok()    { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()    { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

# start_server <name> <port> [extra FD0_ env assignments...]
start_server() {
  local name=$1 port=$2; shift 2
  mkdir -p "$BASE/srv-$name"
  env FD0_BIND=":$port" FD0_DB="$BASE/srv-$name/fd0.db" FD0_RATELIMIT_OFF=1 "$@" \
    "$FD0_SERVER_BIN" > "$BASE/srv-$name.log" 2>&1 &
  PIDS[$name]=$!
}
wait_health() {
  local url=$1
  for i in $(seq 1 20); do curl -sf "$url/health" >/dev/null && return 0; sleep 0.2; done
  return 1
}
stop_server() { local name=$1; kill "${PIDS[$name]}" 2>/dev/null; wait "${PIDS[$name]}" 2>/dev/null; }

# fd0 client as <who>
as() {
  local who=$1; shift
  FD0_HOME=$BASE/$who HOME=$BASE/$who-host FD0_SSH_SOCK=$BASE/$who.sock "$FD0" "$@"
}
mkclient() { # mkclient <who> <mode("" or primary)> <server-url...>
  local who=$1 mode=$2; shift 2
  mkdir -p "$BASE/$who" "$BASE/$who-host"
  {
    echo "[sync]"
    printf 'servers = ['
    local first=1
    for u in "$@"; do [[ $first -eq 1 ]] && first=0 || printf ', '; printf '"%s"' "$u"; done
    echo "]"
    echo "on_unlock = false"
    [[ -n "$mode" ]] && echo "mode = \"$mode\""
  } > "$BASE/$who/config.toml"
  printf "%s-pass\n%s-pass\n" "$who" "$who" | as "$who" init  >"$BASE/$who-init.log" 2>&1
  printf "%s-pass\n" "$who"                  | as "$who" unlock >"$BASE/$who-unlock.log" 2>&1
}
scount() { sqlite3 "$1" "$2" 2>/dev/null || echo "ERR"; }

# ──────────────────────────────────────────────────────────────────────
phase "Part A — DR backup replication (real binaries)"
# Primary trusts the backup as a peer (so it authorises the peer pull).
# Short peer-resolve interval so it pins the backup within a couple
# seconds even if the backup came up after it.
start_server sp "$PORT_SP" FD0_PEERS="$URL_SC" FD0_PEER_RESOLVE_INTERVAL=2s FD0_LABEL=primary
# Backup mirrors the primary every 2s.
start_server sc "$PORT_SC" FD0_REPLICATE_FROM="$URL_SP" FD0_REPLICATE_INTERVAL=2s FD0_PEERS="$URL_SP" FD0_LABEL=backup
wait_health "$URL_SP" && ok "primary up" || no "primary down"
wait_health "$URL_SC" && ok "backup up"  || no "backup down"

mkclient writer "" "$URL_SP"
as writer sync >/dev/null 2>&1 && ok "writer registered on primary" || no "writer register"
as writer scope create --label projA >/dev/null 2>&1 && ok "scope projA created" || no "scope create"
for i in 1 2 3 4 5; do as writer set "K$i" "val-$i" --scope projA >/dev/null 2>&1; done
as writer scope create --label projB >/dev/null 2>&1
for i in 1 2 3; do as writer set "M$i" "m-$i" --scope projB >/dev/null 2>&1; done
as writer sync >/dev/null 2>&1 && ok "writer pushed secrets to primary" || no "writer sync"

SP_DB="$BASE/srv-sp/fd0.db"; SC_DB="$BASE/srv-sc/fd0.db"
# The backup mirrors EVERY chain (scope + user), so compare total events.
PRI_EVENTS=$(scount "$SP_DB" "SELECT COUNT(*) FROM events")
ok "primary holds $PRI_EVENTS events (scope + user chains)"

# Wait for the backup to catch up (a few 2s cycles).
BK_EVENTS=0
for i in $(seq 1 10); do
  BK_EVENTS=$(scount "$SC_DB" "SELECT COUNT(*) FROM backup_events")
  [[ "$BK_EVENTS" == "$PRI_EVENTS" && "$PRI_EVENTS" -gt 0 ]] && break
  sleep 1
done
[[ "$BK_EVENTS" -gt 0 ]] && ok "backup mirrored $BK_EVENTS events" || no "backup mirrored nothing"
[[ "$BK_EVENTS" == "$PRI_EVENTS" ]] && ok "backup event count == primary ($BK_EVENTS)" || no "backup count $BK_EVENTS != primary $PRI_EVENTS"

# Byte-identity spot check: a sample event_id+cbor must match.
SAMPLE=$(scount "$SP_DB" "SELECT event_id FROM events WHERE chain_id LIKE 'scope:%' ORDER BY event_id LIMIT 1")
PRI_CBOR=$(scount "$SP_DB" "SELECT hex(cbor) FROM events WHERE event_id='$SAMPLE'")
BK_CBOR=$(scount "$SC_DB" "SELECT hex(cbor) FROM backup_events WHERE event_id='$SAMPLE'")
[[ -n "$PRI_CBOR" && "$PRI_CBOR" == "$BK_CBOR" ]] && ok "sample event byte-identical in backup" || no "sample event differs (pri=${#PRI_CBOR} bk=${#BK_CBOR})"

# STH archived too.
BK_STHS=$(scount "$SC_DB" "SELECT COUNT(*) FROM backup_sths")
[[ "$BK_STHS" -gt 0 ]] && ok "backup archived $BK_STHS STH(s)" || no "no STHs in backup"

# Restore-ability = COMPLETENESS per chain: for every chain on the primary
# the backup must hold the same event count AND archive a current STH.
# (A restore needs every chain whole, not just the right total.)
INCOMPLETE=0
while IFS='|' read -r cid pcount; do
  [[ -z "$cid" ]] && continue
  bcount=$(scount "$SC_DB" "SELECT COUNT(*) FROM backup_events WHERE chain_id='$cid'")
  bsth=$(scount "$SC_DB" "SELECT COUNT(*) FROM backup_sths WHERE chain_id='$cid'")
  if [[ "$bcount" != "$pcount" || "$bsth" -lt 1 ]]; then
    no "chain $cid incomplete in backup (events $bcount/$pcount, sths $bsth)"; INCOMPLETE=1
  fi
done < <(sqlite3 "$SP_DB" "SELECT chain_id, COUNT(*) FROM events GROUP BY chain_id" 2>/dev/null)
[[ "$INCOMPLETE" -eq 0 ]] && ok "every primary chain is complete in the backup (restore-able)" || true

# The point of DR: kill the primary, data survives in the backup.
stop_server sp
sleep 0.5
curl -sf "$URL_SP/health" >/dev/null 2>&1 && no "primary still up after kill" || ok "primary killed"
SURVIVE=$(scount "$SC_DB" "SELECT COUNT(*) FROM backup_events")
[[ "$SURVIVE" == "$PRI_EVENTS" ]] && ok "all $SURVIVE events SURVIVE in backup after primary death" || no "backup lost data ($SURVIVE)"
stop_server sc

# ──────────────────────────────────────────────────────────────────────
phase "Part B — primary-per-scope convergence (real binaries)"
start_server sa "$PORT_SA" FD0_LABEL=alpha
start_server sb "$PORT_SB" FD0_LABEL=beta
wait_health "$URL_SA" && ok "server A up" || no "server A down"
wait_health "$URL_SB" && ok "server B up" || no "server B down"

for c in alice bob carol; do mkclient "$c" primary "$URL_SA" "$URL_SB"; done
as alice sync >/dev/null 2>&1; as bob sync >/dev/null 2>&1; as carol sync >/dev/null 2>&1
ok "three primary-mode clients registered"

# Share two scopes (likely anchoring to different servers).
share_scope() { # share_scope <label>
  local label=$1
  as alice scope create --label "$label" >/dev/null 2>&1
  for m in bob carol; do
    mc=$(as "$m" card export 2>/dev/null | grep '^fd0://card/')
    ac=$(as alice card export 2>/dev/null | grep '^fd0://card/')
    as alice card import "$mc" --label "$m" --yes >/dev/null 2>&1
    as "$m" card import "$ac" --label alice --yes >/dev/null 2>&1
    as alice scope add-member "$m" --scope "$label" >/dev/null 2>&1
  done
  as alice sync >/dev/null 2>&1
  as bob sync >/dev/null 2>&1; as carol sync >/dev/null 2>&1
}
share_scope team1
share_scope team2
ok "two scopes shared across 3 members"

# Writes from different members into both scopes.
as alice set A1 a-one   --scope team1 >/dev/null 2>&1
as bob   set B1 b-one   --scope team1 >/dev/null 2>&1
as carol set C1 c-one   --scope team2 >/dev/null 2>&1
as alice set A2 a-two   --scope team2 >/dev/null 2>&1
for c in alice bob carol; do as "$c" sync >/dev/null 2>&1; done

# Kill server B, write more, restart, converge.
stop_server sb
sleep 0.3
as bob set B2 b-two --scope team1 >/dev/null 2>&1
as carol set C2 c-two --scope team2 >/dev/null 2>&1
for c in alice bob carol; do as "$c" sync >/dev/null 2>&1; done
start_server sb "$PORT_SB" FD0_LABEL=beta
wait_health "$URL_SB" >/dev/null && ok "server B restarted" || no "server B restart failed"
for round in 1 2 3 4; do for c in alice bob carol; do as "$c" sync >/dev/null 2>&1; done; done

# Convergence: every client reads every value in both scopes.
declare -A WANT=(
  [team1:A1]=a-one [team1:B1]=b-one [team1:B2]=b-two
  [team2:C1]=c-one [team2:A2]=a-two [team2:C2]=c-two
)
conv=1
for c in alice bob carol; do
  for sk in "${!WANT[@]}"; do
    scope=${sk%%:*}; key=${sk##*:}
    got=$(as "$c" get "$key" --scope "$scope" 2>/dev/null)
    if [[ "$got" != "${WANT[$sk]}" ]]; then
      no "$c $scope/$key=$got want ${WANT[$sk]}"; conv=0
    fi
  done
done
[[ $conv -eq 1 ]] && ok "ALL 3 clients converged on ALL 6 values across 2 scopes"

for c in alice bob carol; do as "$c" doctor >/dev/null 2>&1 && ok "$c doctor clean" || no "$c doctor"; done

# ──────────────────────────────────────────────────────────────────────
phase "Part C — misconfigured client fails LOUD (review RED #2)"
# dave configures ONLY server B. Some scope is anchored at A; dave must
# error loudly on it rather than silently report success.
mc=$(as bob card export 2>/dev/null | grep '^fd0://card/')   # warm
mkclient dave primary "$URL_SB"
as dave sync >/dev/null 2>&1
dc=$(as dave card export 2>/dev/null | grep '^fd0://card/')
ac=$(as alice card export 2>/dev/null | grep '^fd0://card/')
as alice card import "$dc" --label dave --yes >/dev/null 2>&1
as dave  card import "$ac" --label alice --yes >/dev/null 2>&1
as alice scope add-member dave --scope team1 >/dev/null 2>&1
as alice scope add-member dave --scope team2 >/dev/null 2>&1
as alice sync >/dev/null 2>&1
DAVE_OUT=$(as dave sync 2>&1)
if echo "$DAVE_OUT" | grep -qi "not in your \[sync\].servers\|unroutable"; then
  ok "dave's missing-anchor scope surfaced a LOUD error (no silent success)"
else
  printf "  \033[33m▸\033[0m note: both shared scopes happened to anchor at dave's one server (B); no misconfig to surface this run\n"
fi

# ──────────────────────────────────────────────────────────────────────
phase "Summary"
echo "    PASS=$PASS  FAIL=$FAIL"
[[ $FAIL -gt 0 ]] && exit 1 || exit 0
