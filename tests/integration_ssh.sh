#!/usr/bin/env bash
# fd0 ssh end-to-end smoke. Spins up a local fd0-server + fd0-agent +
# fd0 CLI, exercises:
#
#   1. `fd0 key add` generates an ed25519 key in a scope
#   2. `fd0 ssh add` creates a host referencing the key
#   3. `fd0 ssh ls` shows the host
#   4. `fd0 ssh show` renders a sane ssh_config snippet
#   5. `fd0 ssh add ... --with-key` generates host + key in one call
#   6. `fd0 ssh tag` adds and removes tags
#   7. `fd0 ssh rm` tombstones a host
#   8. SSH-agent socket exposed by fd0-agent answers `ssh-add -l`
#   9. ~/.ssh/fd0.conf is rendered with all the right entries
#  10. Missing-Include warning fires when ~/.ssh/config doesn't reference fd0.conf
#
# Designed to run against fresh binaries built from this tree —
# `go install ./cmd/...` once before running.

set -uo pipefail
export FD0_AUTO_PIN=1

BASE=/tmp/fd0-ssh-smoke
FD0=$HOME/go/bin/fd0
FD0_AGENT_BIN=$HOME/go/bin/fd0-agent
FD0_SERVER_BIN=$HOME/go/bin/fd0-server

SERVER_PORT=14048
SERVER_URL=http://localhost:$SERVER_PORT

# Override paths so we don't touch the real ~/.ssh.
export FD0_HOME=$BASE/alice
export FD0_AGENT_BIN
export FD0_SSH_CONFIG_PATH=$BASE/fd0.conf
export FD0_SSH_SOCK=$BASE/ssh.sock
HOME_BACKUP=$HOME
export HOME=$BASE/home

cleanup() {
  pkill -f "$FD0_SERVER_BIN" 2>/dev/null
  pkill -f "$FD0_AGENT_BIN"  2>/dev/null
  sleep 0.3
  export HOME=$HOME_BACKUP
}
trap cleanup EXIT
cleanup
rm -rf "$BASE"
mkdir -p "$BASE/server" "$BASE/alice" "$BASE/home/.ssh"

PASS=0
FAIL=0
phase()    { printf "\n\033[1m═══ %s ═══\033[0m\n" "$*"; }
step()     { printf "  \033[36m▸\033[0m %s\n" "$*"; }
ok()       { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()       { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

# ─────────────────────────────────────────────────────────────
phase "Boot local server"

FD0_BIND=:$SERVER_PORT FD0_DB=$BASE/server/fd0.db FD0_RATELIMIT_OFF=1 \
  "$FD0_SERVER_BIN" > "$BASE/server.log" 2>&1 &
echo $! > "$BASE/server.pid"

for i in 1 2 3 4 5; do
  curl -sf $SERVER_URL/health > /dev/null && break
  sleep 0.3
done
curl -sf $SERVER_URL/health > /dev/null && ok "server up" || no "server unreachable"

# ─────────────────────────────────────────────────────────────
phase "Init + unlock alice"

mkdir -p "$FD0_HOME"
cat > "$FD0_HOME/config.toml" <<EOF
[sync]
server = "$SERVER_URL"
on_unlock = false
EOF

printf "alice-pass\nalice-pass\n" | "$FD0" init > "$BASE/init.log" 2>&1 \
  && ok "alice: init" || no "alice: init failed"
printf "alice-pass\n" | "$FD0" unlock > "$BASE/unlock.log" 2>&1 \
  && ok "alice: unlock" || { no "alice: unlock"; tail "$BASE/unlock.log"; }
"$FD0" sync > "$BASE/sync.log" 2>&1 \
  && ok "alice: sync (register)" || no "sync failed"

# ─────────────────────────────────────────────────────────────
phase "Key add (top-level)"

"$FD0" scope create --label work > /dev/null 2>&1 && ok "scope work" || no "scope create"

"$FD0" key add deploy --scope work > "$BASE/key-add.log" 2>&1 \
  && ok "key add deploy" || { no "key add"; tail "$BASE/key-add.log"; }

grep -q "ssh-ed25519" "$BASE/key-add.log" \
  && ok "pub-key printed in output" || no "no pub-key in output"

"$FD0" key ls --scope work > "$BASE/key-ls.log" 2>&1
grep -q "deploy " "$BASE/key-ls.log" && ok "key ls shows deploy" || { no "key ls missing"; cat "$BASE/key-ls.log"; }

"$FD0" key show deploy --scope work --pub > "$BASE/key-pub.txt" 2>&1
grep -q "^ssh-ed25519 " "$BASE/key-pub.txt" \
  && ok "key show --pub prints authorized_keys line" || no "key show --pub bad"

# ─────────────────────────────────────────────────────────────
phase "Host add (referencing key)"

"$FD0" ssh add prod-db app@db.internal --jump bastion --key deploy \
    --tag prod --tag db --description "Main prod DB" --scope work \
    > "$BASE/ssh-add.log" 2>&1 \
  && ok "ssh add prod-db" || { no "ssh add"; cat "$BASE/ssh-add.log"; }

# Render should have happened automatically.
[[ -f "$FD0_SSH_CONFIG_PATH" ]] \
  && ok "fd0.conf auto-rendered" || no "fd0.conf missing"

grep -q "Host prod-db" "$FD0_SSH_CONFIG_PATH" \
  && ok "fd0.conf contains prod-db" || no "fd0.conf incomplete"

grep -q "ProxyJump bastion" "$FD0_SSH_CONFIG_PATH" \
  && ok "fd0.conf has ProxyJump" || no "ProxyJump missing"

grep -q "IdentityAgent $FD0_SSH_SOCK" "$FD0_SSH_CONFIG_PATH" \
  && ok "fd0.conf has IdentityAgent" || no "IdentityAgent missing"

# Include warning should have fired (we never enabled).
grep -q "doesn't include" "$BASE/ssh-add.log" \
  && ok "include warning emitted" || no "include warning not visible"

# ─────────────────────────────────────────────────────────────
phase "Host add --with-key (host + new key in one shot)"

"$FD0" ssh add staging-web app@stage.internal --with-key \
    --tag staging --description "Staging web" --scope work \
    > "$BASE/ssh-with-key.log" 2>&1 \
  && ok "ssh add --with-key" || { no "ssh add --with-key"; cat "$BASE/ssh-with-key.log"; }

grep -q "generated key \"staging-web\"" "$BASE/ssh-with-key.log" \
  && ok "auto-key generated with host alias" || no "auto-key name wrong"

"$FD0" key ls --scope work > "$BASE/keys2.log" 2>&1
grep -q "^staging-web " "$BASE/keys2.log" \
  && ok "auto-key in key ls" || { no "auto-key missing from key ls"; cat "$BASE/keys2.log"; }

# ─────────────────────────────────────────────────────────────
phase "Tag operations"

"$FD0" ssh tag prod-db --add critical --scope work > /dev/null 2>&1 \
  && ok "tag --add critical" || no "tag add"

"$FD0" ssh show prod-db --scope work > "$BASE/show.log" 2>&1
grep -q "critical" "$BASE/show.log" && ok "show reflects new tag" || no "tag not in show"

"$FD0" ssh tag prod-db --remove db --scope work > /dev/null 2>&1 \
  && ok "tag --remove db" || no "tag remove"

# Tag-filter ls
"$FD0" ssh ls --tag prod > "$BASE/ls-prod.log" 2>&1
grep -q "prod-db " "$BASE/ls-prod.log" \
  && ok "ls --tag filters" || { no "tag filter broken"; cat "$BASE/ls-prod.log"; }

# ─────────────────────────────────────────────────────────────
phase "Picker check (non-TTY → list mode)"

# We can't run the TUI in CI, but `fd0 ssh` with explicit name should
# print the ssh command path. Use --tag to filter to one match so
# the picker doesn't activate. Skip the actual exec.
"$FD0" ssh ls > "$BASE/ls-all.log" 2>&1
[[ $(grep -c "^[A-Za-z]" "$BASE/ls-all.log") -ge 2 ]] \
  && ok "ssh ls shows multiple hosts" || no "ls hosts count"

# ─────────────────────────────────────────────────────────────
phase "Host rm"

"$FD0" ssh rm prod-db --scope work > "$BASE/rm.log" 2>&1 \
  && ok "ssh rm prod-db" || no "ssh rm"

! grep -q "Host prod-db" "$FD0_SSH_CONFIG_PATH" \
  && ok "fd0.conf no longer has prod-db" || no "prod-db still in fd0.conf"

grep -q "Host staging-web" "$FD0_SSH_CONFIG_PATH" \
  && ok "fd0.conf still has staging-web" || no "staging-web vanished"

# ─────────────────────────────────────────────────────────────
phase "SSH-agent socket"

# fd0-agent is already running (spawned by `fd0 unlock`). Its SSH
# socket should be reachable.
if [[ -S "$FD0_SSH_SOCK" ]]; then
  ok "SSH socket exists at $FD0_SSH_SOCK"
else
  no "SSH socket missing"
fi

if command -v ssh-add >/dev/null; then
  out=$(SSH_AUTH_SOCK=$FD0_SSH_SOCK ssh-add -l 2>&1)
  if echo "$out" | grep -q "ED25519"; then
    ok "ssh-add -l shows ed25519 identities"
  else
    step "  ssh-add output: $out"
    no "ssh-add -l didn't list keys"
  fi
else
  step "  ssh-add not installed; skipping protocol check"
fi

# ─────────────────────────────────────────────────────────────
phase "ssh disable / cleanup"

"$FD0" ssh disable > "$BASE/disable.log" 2>&1 \
  && ok "ssh disable completed" || no "ssh disable failed"

# ─────────────────────────────────────────────────────────────
phase "Summary"
echo "    PASS=$PASS  FAIL=$FAIL"
[[ $FAIL -gt 0 ]] && exit 1 || exit 0
