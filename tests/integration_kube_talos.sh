#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation
# fd0 talos + fd0 kube end-to-end smoke.
#
# Doesn't need talosctl on PATH — we cover the codepaths that *don't*
# shell out (add/ls/show/rm/move/sync/import), plus the file-render
# story. The talosctl-dependent paths (`new`, `role-add`,
# `kubeconfig`) are exercised separately when talosctl is available.
#
# Run after `go install ./cmd/...`.

set -uo pipefail
export FD0_AUTO_PIN=1

BASE=/tmp/fd0-talos-smoke
FD0=$HOME/go/bin/fd0
FD0_AGENT_BIN=$HOME/go/bin/fd0-agent
FD0_SERVER_BIN=$HOME/go/bin/fd0-server

SERVER_PORT=14049
SERVER_URL=http://localhost:$SERVER_PORT

export FD0_HOME=$BASE/alice
export FD0_AGENT_BIN
# Redirect every on-disk render to the smoke tree so we don't touch
# the real ~/.talos / ~/.kube.
export FD0_TALOS_CONFIG_PATH=$BASE/talos.conf
export FD0_TALOS_USER_CONFIG=$BASE/user-talosconfig
export FD0_KUBE_CONFIG_PATH=$BASE/kube.conf
export FD0_KUBE_USER_CONFIG=$BASE/user-kubeconfig
export FD0_SSH_SOCK=$BASE/ssh.sock
HOME_BACKUP=$HOME
export HOME=$BASE/home

cleanup() {
  fd0_test_stop_matching -f "$FD0_SERVER_BIN" 2>/dev/null
  fd0_test_stop_matching -f "$FD0_AGENT_BIN"  2>/dev/null
  sleep 0.3
  export HOME=$HOME_BACKUP
}
trap cleanup EXIT
cleanup
rm -rf "$BASE"
mkdir -p "$BASE/server" "$BASE/alice" "$BASE/home"

PASS=0
FAIL=0
phase()    { printf "\n\033[1m═══ %s ═══\033[0m\n" "$*"; }
ok()       { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()       { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

# ─────────────────────────────────────────────────────────────
phase "Boot local server + init alice"

FD0_BIND=:$SERVER_PORT FD0_DB=$BASE/server/fd0.db FD0_RATELIMIT_OFF=1 \
  "$FD0_SERVER_BIN" > "$BASE/server.log" 2>&1 &
for i in 1 2 3 4 5; do curl -sf $SERVER_URL/health >/dev/null && break; sleep 0.3; done
curl -sf $SERVER_URL/health >/dev/null && ok "server up" || no "server down"

mkdir -p "$FD0_HOME"
cat > "$FD0_HOME/config.toml" <<EOF
[sync]
server = "$SERVER_URL"
on_unlock = false
EOF

printf "alice-pass\nalice-pass\n" | "$FD0" init > "$BASE/init.log" 2>&1 \
  && ok "init" || no "init"
printf "alice-pass\n" | "$FD0" unlock > "$BASE/unlock.log" 2>&1 \
  && ok "unlock" || no "unlock"
"$FD0" sync > "$BASE/sync.log" 2>&1 \
  && ok "register sync" || no "register sync"

"$FD0" scope create --label work > /dev/null 2>&1 && ok "scope work" || no "scope work"
"$FD0" scope create --label vault > /dev/null 2>&1 && ok "scope vault" || no "scope vault"

# ─────────────────────────────────────────────────────────────
phase "Talos: import an existing talosconfig via --from-config"

# Fabricate a tiny talosconfig with two contexts.
cat > "$BASE/donor.talosconfig" <<'YAML'
context: prod-1
contexts:
  prod-1:
    endpoints: [10.0.1.10, 10.0.1.11]
    nodes: [10.0.1.10]
    ca: QUFB
    crt: QkJC
    key: Q0ND
  staging:
    endpoints: ["192.168.1.50"]
    ca: RERE
    crt: RUVF
    key: RkZG
YAML

"$FD0" talos add --from-config "$BASE/donor.talosconfig" --scope work --role os:admin \
    > "$BASE/talos-add.log" 2>&1 \
  && ok "talos add --from-config" || { no "talos add"; cat "$BASE/talos-add.log"; }

grep -q "imported \"prod-1\"" "$BASE/talos-add.log" && ok "prod-1 imported" \
  || no "prod-1 not imported"
grep -q "imported \"staging\"" "$BASE/talos-add.log" && ok "staging imported" \
  || no "staging not imported"

# Rendered file ?
[[ -f "$FD0_TALOS_CONFIG_PATH" ]] && ok "talos config rendered" || no "no render"
grep -q "context: " "$FD0_TALOS_CONFIG_PATH" 2>/dev/null \
  || ok "no active context (we didn't pick one)"
grep -q "prod-1:" "$FD0_TALOS_CONFIG_PATH" && ok "prod-1 in rendered YAML" \
  || no "prod-1 missing in render"
grep -q "managed talosconfig" "$FD0_TALOS_CONFIG_PATH" && ok "header marker present" \
  || no "no header marker"

# ─────────────────────────────────────────────────────────────
phase "Talos: list / show / rm / move"

"$FD0" talos ls --scope work > "$BASE/talos-ls.log" 2>&1
grep -q "^prod-1" "$BASE/talos-ls.log" && ok "ls shows prod-1" || no "ls broken"
grep -q "^staging" "$BASE/talos-ls.log" && ok "ls shows staging" || no "ls broken"

"$FD0" talos show prod-1 --scope work > "$BASE/talos-show.log" 2>&1
grep -q "10.0.1.10" "$BASE/talos-show.log" && ok "show prints endpoint" || no "show empty"
grep -q "(hidden)" "$BASE/talos-show.log" && ok "show hides key" || no "key not hidden"

"$FD0" talos move staging --to-scope vault > /dev/null 2>&1 \
  && ok "talos move → vault" || no "talos move"

"$FD0" talos ls --scope vault > "$BASE/talos-vault.log" 2>&1
grep -q "^staging" "$BASE/talos-vault.log" && ok "staging in vault scope" || no "move didn't land"

"$FD0" talos rm prod-1 --scope work > /dev/null 2>&1 \
  && ok "talos rm prod-1" || no "rm"

! grep -q "prod-1:" "$FD0_TALOS_CONFIG_PATH" 2>/dev/null \
  && ok "prod-1 gone from rendered YAML" || no "stale"
grep -q "staging:" "$FD0_TALOS_CONFIG_PATH" 2>/dev/null \
  && ok "staging still present" || no "lost"

# ─────────────────────────────────────────────────────────────
phase "Talos: secrets.yaml DR roundtrip"

# Fabricate a 'secrets.yaml' blob and import it into the vault scope.
printf "fake-secrets-yaml\nrandom-cluster-pki\n" > "$BASE/fake-secrets.yaml"
"$FD0" talos secrets import prod-1 --in "$BASE/fake-secrets.yaml" --scope vault \
    > "$BASE/talos-sec-imp.log" 2>&1 \
  && ok "talos secrets import" || no "secrets import"

"$FD0" talos secrets ls --scope vault > "$BASE/talos-sec-ls.log" 2>&1
grep -q "^prod-1" "$BASE/talos-sec-ls.log" && ok "secrets ls" || no "secrets ls"

"$FD0" talos secrets export prod-1 --out "$BASE/got-secrets.yaml" --scope vault \
    > "$BASE/talos-sec-exp.log" 2>&1 \
  && ok "talos secrets export" || no "secrets export"

diff -q "$BASE/fake-secrets.yaml" "$BASE/got-secrets.yaml" >/dev/null 2>&1 \
  && ok "DR roundtrip bytes-identical" || no "DR drift"

# refuse to overwrite without --force
"$FD0" talos secrets export prod-1 --out "$BASE/got-secrets.yaml" --scope vault \
    > "$BASE/talos-sec-exp2.log" 2>&1
[[ $? -ne 0 ]] && ok "export refuses overwrite without --force" || no "no overwrite guard"
"$FD0" talos secrets export prod-1 --out "$BASE/got-secrets.yaml" --scope vault --force \
    > "$BASE/talos-sec-exp3.log" 2>&1 \
  && ok "export --force overwrites" || no "force path broken"

# ─────────────────────────────────────────────────────────────
phase "Kube: import + render + list"

# A tiny kubeconfig with one cluster + token auth.
cat > "$BASE/donor.kubeconfig" <<'YAML'
apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster:
    server: https://10.0.1.10:6443
    certificate-authority-data: QUFB
users:
- name: prod
  user:
    client-certificate-data: QkJC
    client-key-data: Q0ND
contexts:
- name: prod
  context:
    cluster: prod
    user: prod
    namespace: kube-system
YAML

"$FD0" kube add --from-config "$BASE/donor.kubeconfig" --scope work \
    > "$BASE/kube-add.log" 2>&1 \
  && ok "kube add --from-config" || { no "kube add"; cat "$BASE/kube-add.log"; }

[[ -f "$FD0_KUBE_CONFIG_PATH" ]] && ok "kube config rendered" || no "no render"
grep -q "apiVersion: v1" "$FD0_KUBE_CONFIG_PATH" && ok "valid YAML start" || no "no apiVersion"
grep -q "name: prod" "$FD0_KUBE_CONFIG_PATH" && ok "prod cluster rendered" || no "no cluster"

"$FD0" kube ls > "$BASE/kube-ls.log" 2>&1
grep -q "^prod" "$BASE/kube-ls.log" && ok "kube ls" || no "kube ls"

# Token-auth path: add a second cluster directly via flags.
"$FD0" kube add edge \
    --server https://192.168.50.1:6443 \
    --insecure-skip-tls-verify \
    --token "bearer-xxx" \
    --scope work \
    > "$BASE/kube-add2.log" 2>&1 \
  && ok "kube add token cluster" || no "token add"

grep -q "name: edge" "$FD0_KUBE_CONFIG_PATH" && ok "edge in render" || no "edge missing"
grep -q "token: bearer-xxx" "$FD0_KUBE_CONFIG_PATH" && ok "token in render" || no "token missing"

# ─────────────────────────────────────────────────────────────
phase "Kube: in-house merge (no kubectl needed)"

# Seed the user kubeconfig with a foreign exec-auth cluster fd0 does
# NOT manage — the merge must preserve it (EKS/GKE data-loss guard).
cat > "$FD0_KUBE_USER_CONFIG" <<'YAML'
apiVersion: v1
kind: Config
current-context: eks-prod
clusters:
- name: eks-prod
  cluster:
    server: https://eks.example.com
users:
- name: eks-prod
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
contexts:
- name: eks-prod
  context: {cluster: eks-prod, user: eks-prod}
YAML

# Force kubectl OFF to prove the merge is pure-Go.
FD0_KUBECTL=/nonexistent-kubectl-binary "$FD0" kube sync --merge \
    > "$BASE/kube-sync.log" 2>&1 \
  && ok "kube sync --merge (no kubectl)" || { no "merge failed"; tail "$BASE/kube-sync.log"; }

[[ -f "$FD0_KUBE_USER_CONFIG" ]] && ok "user kubeconfig written" || no "no user file"
grep -q "name: prod" "$FD0_KUBE_USER_CONFIG" 2>/dev/null \
  && ok "merged kubeconfig has fd0 prod cluster" || no "no prod in merged"
grep -q "eks.example.com" "$FD0_KUBE_USER_CONFIG" 2>/dev/null \
  && ok "foreign EKS cluster preserved" || no "EKS cluster DROPPED"
grep -q "command: aws" "$FD0_KUBE_USER_CONFIG" 2>/dev/null \
  && ok "foreign exec-auth preserved" || no "exec-auth DROPPED"
grep -q "current-context: eks-prod" "$FD0_KUBE_USER_CONFIG" 2>/dev/null \
  && ok "user current-context untouched" || no "current-context changed"

# ─────────────────────────────────────────────────────────────
phase "Talos: in-house merge (no talosctl needed)"

# Foreign hand-rolled context the merge must preserve.
cat > "$FD0_TALOS_USER_CONFIG" <<'YAML'
context: hand-rolled
contexts:
  hand-rolled:
    endpoints: ["10.9.9.9"]
    ca: SAND
    crt: SANE
    key: SANF
YAML

FD0_TALOSCTL=/nonexistent-talosctl-binary "$FD0" talos sync --merge \
    > "$BASE/talos-sync.log" 2>&1 \
  && ok "talos sync --merge (no talosctl)" || { no "merge failed"; tail "$BASE/talos-sync.log"; }

grep -q "hand-rolled:" "$FD0_TALOS_USER_CONFIG" 2>/dev/null \
  && ok "foreign talos context preserved" || no "foreign context DROPPED"
grep -q "staging:" "$FD0_TALOS_USER_CONFIG" 2>/dev/null \
  && ok "fd0 staging context merged in" || no "staging not merged"
grep -q "context: hand-rolled" "$FD0_TALOS_USER_CONFIG" 2>/dev/null \
  && ok "user active context untouched" || no "active context changed"

# ─────────────────────────────────────────────────────────────
phase "Lock + Unlock survives talos + kube state"

"$FD0" lock > /dev/null 2>&1 && ok "lock" || no "lock"
printf "alice-pass\n" | "$FD0" unlock > /dev/null 2>&1 \
  && ok "unlock again" || no "unlock"

"$FD0" talos ls --scope vault > "$BASE/relock-talos.log" 2>&1
grep -q "^staging" "$BASE/relock-talos.log" && ok "talos state persisted" \
  || no "talos vanished"
"$FD0" kube ls > "$BASE/relock-kube.log" 2>&1
grep -q "^prod" "$BASE/relock-kube.log" && ok "kube state persisted" || no "kube vanished"

# ─────────────────────────────────────────────────────────────
phase "Summary"
echo "    PASS=$PASS  FAIL=$FAIL"

phase "Regression: --force + duplicate refuse + move-preflight"

# Talos add: duplicate without force must refuse
"$FD0" talos add staging \
    --endpoint 192.168.1.50 \
    --ca QUFB --crt QkJC --key Q0ND \
    --scope vault > "$BASE/r-talos-dup.log" 2>&1
[[ $? -ne 0 ]] && ok "talos add refuses duplicate" || no "talos silently overwrote!"

# Talos move with destination duplicate
"$FD0" scope create --label work2 > /dev/null 2>&1
"$FD0" talos add overlap \
    --endpoint 1.1.1.1 --ca QUFB --crt QkJC --key Q0ND \
    --scope vault > /dev/null 2>&1
"$FD0" talos add overlap \
    --endpoint 2.2.2.2 --ca QUFB --crt QkJC --key Q0ND \
    --scope work2 > /dev/null 2>&1
"$FD0" talos move overlap --scope work2 --to-scope vault > "$BASE/r-talos-mv.log" 2>&1
[[ $? -ne 0 ]] && ok "talos move refuses destination duplicate" \
  || no "talos move silently overwrote destination!"

# Kube move with destination duplicate
"$FD0" kube add edge2 --server https://3.3.3.3:6443 --insecure-skip-tls-verify \
    --token tok --scope work2 > /dev/null 2>&1
"$FD0" kube add edge2 --server https://4.4.4.4:6443 --insecure-skip-tls-verify \
    --token tok --scope work > /dev/null 2>&1
"$FD0" kube move edge2 --scope work2 --to-scope work > "$BASE/r-kube-mv.log" 2>&1
[[ $? -ne 0 ]] && ok "kube move refuses destination duplicate" \
  || no "kube move silently overwrote destination!"

# Load-time validate: render must not contain injection markers
! grep -q "ProxyCommand\|Include /etc" "$FD0_TALOS_CONFIG_PATH" 2>/dev/null \
  && ok "no injection in talos render" || no "INJECTION IN TALOS RENDER"

phase "Summary 2"
echo "    PASS=$PASS  FAIL=$FAIL"

[[ $FAIL -gt 0 ]] && exit 1 || exit 0
