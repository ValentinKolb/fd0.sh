#!/usr/bin/env bash

# Lifecycle / signal integration tests. These hit the bug class
# that none of our other tests covered: SIGTERM handling, restart-
# after-crash, PID file cleanup, socket orphaning.
#
# Each scenario spawns a real binary, sends real signals, and
# asserts the post-signal state on disk and in process tables.
#
# Run from repo root:
#   bash tests/integration_lifecycle.sh

export FD0_AUTO_PIN=1

set -uo pipefail

SERVER_PORT=14970
SERVER_DB=/tmp/fd0-life-server.db
SERVER_LOG=/tmp/fd0-life-server.log
SERVER_KEY=/tmp/server-translog.key
HOME_AL=$HOME/.fd0-life-al

FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}

PASS=0
FAIL=0
phase() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()    { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()    { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

cleanup() {
    pkill -f fd0-agent  2>/dev/null || true
    kill $SERVER_PID 2>/dev/null || true
    rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_DB-wal" "$SERVER_DB-shm" \
           "$SERVER_LOG" "$SERVER_KEY"
}
trap cleanup EXIT

mkfd0() {
    mkdir -p "$1" && chmod 700 "$1"
    cat > "$1/config.toml" <<EOF
[sync]
server    = "http://127.0.0.1:${SERVER_PORT}"
on_unlock = false
[client]
lock_wait = "10s"
EOF
}

wait_for() {
    local desc="$1" cmd="$2" timeout_s="${3:-5}"
    local i
    for i in $(seq 1 $((timeout_s * 10))); do
        if eval "$cmd" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    no "$desc: timed out after ${timeout_s}s"
    return 1
}

# ---- Setup -----------------------------------------------------------

phase "Setup"
pkill -f fd0-server fd0-agent 2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_LOG" "$SERVER_KEY"

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" \
    --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.5
curl -fs "http://127.0.0.1:${SERVER_PORT}/health" >/dev/null || { no "server failed"; exit 1; }
ok "server up (pid=$SERVER_PID)"

# Bootstrap a client.
mkfd0 "$HOME_AL"
printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" init >/dev/null 2>&1
ok "client init done"

# ---- Scenario 1: agent SIGTERM cleanup -------------------------------

phase "1) Agent SIGTERM removes pid+sock"
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
[ -S "$HOME_AL/agent.sock" ] && ok "agent.sock exists post-unlock" || no "agent.sock missing"
[ -f "$HOME_AL/agent.pid" ] && ok "agent.pid exists post-unlock" || no "agent.pid missing"

AGENT_PID=$(cat "$HOME_AL/agent.pid" 2>/dev/null)
kill -TERM "$AGENT_PID" 2>/dev/null
# Wait up to 3s for clean shutdown.
for i in $(seq 1 30); do
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if kill -0 "$AGENT_PID" 2>/dev/null; then
    no "agent did not exit within 3s of SIGTERM (pid=$AGENT_PID)"
    kill -KILL "$AGENT_PID" 2>/dev/null || true
else
    ok "agent exited cleanly within 3s of SIGTERM"
fi

# Pid file MUST be cleaned up; socket SHOULD be (Unix sockets persist
# the file inode unless the process unlinks).
sleep 0.3
if [ -f "$HOME_AL/agent.pid" ]; then
    no "agent.pid NOT removed after SIGTERM (regression: memguard race)"
else
    ok "agent.pid removed after SIGTERM"
fi
if [ -S "$HOME_AL/agent.sock" ] || [ -e "$HOME_AL/agent.sock" ]; then
    no "agent.sock NOT removed after SIGTERM"
else
    ok "agent.sock removed after SIGTERM"
fi

# ---- Scenario 2: agent restart after SIGKILL -------------------------

phase "2) Agent restart after SIGKILL leaves clean state"
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
AGENT_PID=$(cat "$HOME_AL/agent.pid" 2>/dev/null)
kill -KILL "$AGENT_PID" 2>/dev/null
sleep 0.3
# After SIGKILL, pid+sock are stale (process can't run cleanup).
# Restart MUST detect stale pid + safe-unlink socket and start cleanly.
RESTART_OUT=$(printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock 2>&1)
RC=$?
if [ $RC -eq 0 ]; then
    ok "agent restart after SIGKILL succeeded"
else
    no "agent restart after SIGKILL failed: $(echo "$RESTART_OUT" | head -c 200)"
fi
NEW_PID=$(cat "$HOME_AL/agent.pid" 2>/dev/null)
if [ -n "$NEW_PID" ] && kill -0 "$NEW_PID" 2>/dev/null; then
    ok "new agent listening (pid=$NEW_PID)"
else
    no "no new agent listening after restart"
fi

# Cleanup before next scenario.
kill -TERM "$NEW_PID" 2>/dev/null || true
sleep 0.5

# ---- Scenario 3: agent socket orphan rejection -----------------------

phase "3) Listen() refuses when socket is alive but pid file is stale"
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" "$FD0" unlock >/dev/null 2>&1
sleep 0.3
ALIVE_PID=$(cat "$HOME_AL/agent.pid" 2>/dev/null)
# Manually remove the pid file but leave the agent + socket alive.
rm -f "$HOME_AL/agent.pid"
# Try to spawn a SECOND agent — it MUST refuse because socket
# answers (codex audit fix: probeAgentSocket).
SECOND_OUT=$(env FD0_HOME="$HOME_AL" FD0_AGENT_LOG="/dev/null" "$FD0_AGENT" 2>&1 &
SECOND_PID=$!
sleep 1
kill -TERM $SECOND_PID 2>/dev/null
wait $SECOND_PID 2>/dev/null
true)
# The second agent SHOULD have died with an error message about
# the live socket.
if echo "$SECOND_OUT" | grep -q "another process is listening\|listen.*address already in use"; then
    ok "second agent refused to start while socket is occupied"
else
    no "second agent did NOT refuse — orphan-agent regression"
fi

# Cleanup the live agent.
kill -TERM "$ALIVE_PID" 2>/dev/null || true
sleep 0.3
rm -f "$HOME_AL/agent.pid" "$HOME_AL/agent.sock"

# ---- Scenario 4: server SIGTERM graceful shutdown --------------------

phase "4) Server SIGTERM completes gracefully"
# Send SIGTERM and assert exit within 5s + clean DB state.
kill -TERM $SERVER_PID
for i in $(seq 1 50); do
    if ! kill -0 $SERVER_PID 2>/dev/null; then break; fi
    sleep 0.1
done
if kill -0 $SERVER_PID 2>/dev/null; then
    no "server did not exit within 5s of SIGTERM"
    kill -KILL $SERVER_PID 2>/dev/null
else
    ok "server exited within 5s of SIGTERM"
fi
# WAL should have been checkpointed → no -wal/-shm files remain
# (or they remain empty for SQLite WAL mode; check the DB is
# at least readable).
if sqlite3 "$SERVER_DB" "SELECT COUNT(*) FROM users;" >/dev/null 2>&1; then
    ok "server DB readable after SIGTERM (WAL checkpoint or clean state)"
else
    no "server DB not readable after SIGTERM"
fi

# Restart server for the final scenario.
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" \
    --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.5

# ---- Scenario 5: server SIGTERM mid-request --------------------------

phase "5) Server SIGTERM mid-request: in-flight requests drain"
# Codex test audit (🔴) caught: /health returns in <1ms, so a
# `sleep 0.05` before SIGTERM meant all requests had completed
# before the signal landed and the test was a no-op. Fix: high
# concurrency + no pre-SIGTERM sleep, distinguish curl outcomes
# by exit code:
#   exit 0  → completed (status 200/2xx) → drained gracefully
#   exit 7  → connection refused (server closed listener) → OK
#   exit 52 → empty reply from server → reset mid-stream → BUG
#   exit 56 → recv failure / connection reset → BUG
# Print outcome distribution; test passes iff zero RST-class
# failures.
N_CONCURRENT=100
# Pre-create empty files so a curl that gets killed before
# writing doesn't leave a missing file (which would parse as
# `other=` and skew the count).
for i in $(seq 1 $N_CONCURRENT); do
    : > /tmp/fd0-life-curl-$i.out
done
for i in $(seq 1 $N_CONCURRENT); do
    ( curl -m 10 -s -o /dev/null "http://127.0.0.1:${SERVER_PORT}/health" 2>/dev/null ; echo $? > /tmp/fd0-life-curl-$i.out ) &
done
# Send SIGTERM IMMEDIATELY (no sleep) — race with curl.
kill -TERM $SERVER_PID
wait
sleep 1.0  # give the OS time to flush all curl output buffers
OK=0; REFUSED=0; ABORTED=0; OTHER=0
for i in $(seq 1 $N_CONCURRENT); do
    exit_code=$(cat /tmp/fd0-life-curl-$i.out 2>/dev/null | tr -d '[:space:]')
    case "$exit_code" in
        0) OK=$((OK+1)) ;;
        7) REFUSED=$((REFUSED+1)) ;;     # graceful: server closed listener before connect
        52|56) ABORTED=$((ABORTED+1)) ;;  # mid-stream reset = bug
        *)  OTHER=$((OTHER+1)) ;;
    esac
done
echo "    drain stats: ok=$OK refused=$REFUSED aborted_mid_stream=$ABORTED other=$OTHER (of $N_CONCURRENT)"
# Aborted=mid-stream RST is the real bug. Refused is fine.
# Tolerance: up to 2 of 100 (2%) accepted because the Go HTTP
# Server.Shutdown contract has a known kernel-accept-queue race
# where a connection in the kernel's listen queue but not yet
# accept()'d when the listener closes can be reset by the OS.
# This isn't a server bug we can fix — it's why production
# deployments drain via load balancer, not bare SIGTERM.
ABORTED_TOLERANCE=2
if [ $ABORTED -le $ABORTED_TOLERANCE ] && [ $OK -ge 1 ]; then
    if [ $ABORTED -eq 0 ]; then
        ok "no requests aborted mid-stream; $OK drained, $REFUSED refused, $OTHER misc-fail"
    else
        ok "$ABORTED/$N_CONCURRENT aborted (within $ABORTED_TOLERANCE-tolerance kernel-race window); $OK drained, $REFUSED refused"
    fi
else
    no "graceful drain broken: $ABORTED requests aborted mid-stream (>$ABORTED_TOLERANCE — server tore down established connections)"
fi
rm -f /tmp/fd0-life-curl-*.out

# Restart for cleanup phase.
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" \
    --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 0.3

# ---- Summary ---------------------------------------------------------

echo
printf "\033[1m== LIFECYCLE SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
