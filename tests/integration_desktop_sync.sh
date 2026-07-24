#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

set -euo pipefail

ROOT=${FD0_TEST_ROOT:?}
CLIENT_HOME="$ROOT/desktop-sync-home"
SERVER_DB="$ROOT/server.db"
SERVER_LOG="$ROOT/server.log"
SERVER_PORT=14982
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER_BIN:-$HOME/go/bin/fd0-server}
FD0_DESKTOP_BRIDGE=${FD0_DESKTOP_BRIDGE:-$HOME/go/bin/fd0-desktop-bridge}
SSH_SOCK="$ROOT/desktop-sync-ssh.sock"

cleanup() {
    env FD0_HOME="$CLIENT_HOME" FD0_SSH_SOCK="$SSH_SOCK" "$FD0" agent stop >/dev/null 2>&1 || true
    kill "${SERVER_PID:-}" 2>/dev/null || true
    wait "${SERVER_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$CLIENT_HOME"
chmod 700 "$CLIENT_HOME"
cat > "$CLIENT_HOME/config.toml" <<EOF
[sync]
server = "$SERVER_URL"
on_unlock = false

[client]
lock_wait = "10s"
EOF

"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" --no-ratelimit >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
    curl -fsS "$SERVER_URL/health" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -fsS "$SERVER_URL/health" >/dev/null

client() {
    env \
        FD0_HOME="$CLIENT_HOME" \
        FD0_SSH_SOCK="$SSH_SOCK" \
        FD0_AGENT_BIN="$FD0_AGENT" \
        "$FD0" "$@"
}

bridge() {
    local method=$1 params=${2:-"{}"}
    printf '{"version":1,"id":"test","method":"%s","params":%s}\n' "$method" "$params" |
        env \
            FD0_HOME="$CLIENT_HOME" \
            FD0_SSH_SOCK="$SSH_SOCK" \
            FD0_AGENT_BIN="$FD0_AGENT" \
            FD0_DESKTOP_MODE=system \
            FD0_DESKTOP_VERSION=dev \
            "$FD0_DESKTOP_BRIDGE"
}

printf 'desktop-test-passphrase\ndesktop-test-passphrase\n' | client init >/dev/null
printf 'desktop-test-passphrase\n' | client unlock >/dev/null
client scope create --label Personal >/dev/null

PREP=$(bridge sync.prepare)
export PREP
python3 - <<'PY'
import json, os
r = json.loads(os.environ["PREP"])
assert "error" not in r, r
p = r["result"]
assert p["requiresConfirmation"] is True, p
assert p["alreadyPinned"] is False, p
assert p["hosted"] is False, p
assert p["serverUrl"].startswith("http://127.0.0.1:"), p
assert len(p["serverPub"]) == 64, p
assert p["fingerprint"], p
PY

PIN_PARAMS=$(python3 - <<'PY'
import json, os
p = json.loads(os.environ["PREP"])["result"]
print(json.dumps({"serverUrl": p["serverUrl"], "serverPub": p["serverPub"]}))
PY
)
PIN=$(bridge sync.pin "$PIN_PARAMS")
export PIN
python3 - <<'PY'
import json, os
r = json.loads(os.environ["PIN"])
assert r.get("result", {}).get("ok") is True, r
PY

RUN_PARAMS=$(python3 - <<'PY'
import json, os
p = json.loads(os.environ["PREP"])["result"]
print(json.dumps({"serverUrl": p["serverUrl"]}))
PY
)
RUN=$(bridge sync.run "$RUN_PARAMS")
export RUN
python3 - <<'PY'
import json, os
r = json.loads(os.environ["RUN"])
assert r.get("result", {}).get("ok") is True, r
PY

SECOND=$(bridge sync.prepare)
export SECOND
python3 - <<'PY'
import json, os
p = json.loads(os.environ["SECOND"])["result"]
assert p["alreadyPinned"] is True, p
assert p["requiresConfirmation"] is False, p
PY

client doctor 2>&1 | grep -F "doctor: all clear" >/dev/null
printf 'ok desktop structured first-contact sync\n'
