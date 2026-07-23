#!/usr/bin/env bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/integration_isolation.sh"
fd0_test_require_isolation

# fd0-witness COSIGN + CLIENT CROSS-CHECK integration test
# (TRANSLOG.md §8.3 / §10).
#
# Verifies the new v1 features:
#
#   1. fd0-witness exposes /v1/server-info + /v1/sth/...
#   2. Witness cosigns every successfully-verified STH and serves it.
#   3. Client with [[witness]] config + min_cosigns=1 successfully
#      syncs when the cosign matches the server STH.
#   4. Client REJECTS sync when the witness is presented STHs that
#      differ from what the server gives the client (equivocation).
#   5. Client refuses sync when witness is unreachable / lagging
#      and min_cosigns cannot be met (no soft-tolerance knob).
#   6. Client with min_cosigns > configured-witnesses-count is
#      rejected at config load (loud failure, not silent skip).
#
# Run from repo root:
#   bash tests/integration_witness_cosign.sh

export FD0_AUTO_PIN=1

set -uo pipefail

SERVER_PORT=14930
WITNESS_PORT=14931
BASE="$FD0_TEST_ROOT/cosign"
mkdir -p "$BASE"
SERVER_DB="$BASE/server.db"
SERVER_LOG="$BASE/server.log"
SERVER_KEY="$BASE/server-translog.key"  # default = dirname($SERVER_DB)/server-translog.key
HOME_AL=$HOME/.fd0-cosign-al
WITNESS_DB="$BASE/witness.db"
WITNESS_KEY="$BASE/witness.key"
WITNESS_LOG="$BASE/witness.log"
INFO_BODY="$BASE/witness-info.cbor"
LATEST_BODY="$BASE/witness-latest.cbor"

FD0=${FD0:-$HOME/go/bin/fd0}
FD0_AGENT=${FD0_AGENT:-$HOME/go/bin/fd0-agent}
FD0_SERVER_BIN=${FD0_SERVER:-$HOME/go/bin/fd0-server}
FD0_WITNESS_BIN=${FD0_WITNESS:-$HOME/go/bin/fd0-witness}
SERVER_PID=
WITNESS_PID=

PASS=0
FAIL=0
step() { printf "\n\033[1m── %s\033[0m\n" "$*"; }
ok()   { PASS=$((PASS+1)); printf "  \033[32m✓\033[0m %s\n" "$*"; }
no()   { FAIL=$((FAIL+1)); printf "  \033[31m✗\033[0m %s\n" "$*"; }

cleanup() {
    local code=$?
    fd0_test_stop_matching -f "fd0-witness.*${WITNESS_PORT}"  2>/dev/null || true
    fd0_test_stop_matching -f fd0-witness  2>/dev/null || true
    fd0_test_stop_matching -f fd0-agent    2>/dev/null || true
    [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
    if [ "$code" -eq 0 ]; then
        rm -rf "$HOME_AL" "$BASE"
    else
        printf '  preserving witness-cosign failure artifacts at %s\n' "$BASE" >&2
    fi
    return "$code"
}
trap cleanup EXIT

mkfd0() {
    local home="$1" url="$2"
    mkdir -p "$home" && chmod 700 "$home"
    cat > "$home/config.toml" <<EOF
[sync]
server    = "${url}"
on_unlock = false
[client]
lock_wait = "10s"
EOF
}
AL() { env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" "$@"; }

# ---- pubkey extractors ------------------------------------------------

# fd0-server's translog pub is the second 32 bytes of its keyfile
# (Ed25519 standard layout: seed || pub).
extract_server_pub_hex() {
    python3 -c "
import sys
with open('$SERVER_KEY','rb') as f:
    b=f.read()
sys.stdout.write(b[32:64].hex())
"
}

# fd0-witness keyfile is the same layout.
extract_witness_pub_hex() {
    local kf="$1"
    python3 -c "
import sys
with open('$kf','rb') as f:
    b=f.read()
sys.stdout.write(b[32:64].hex())
"
}

start_witness() {
    local db="$1" key="$2" port="$3" log="$4"
    "$FD0_WITNESS_BIN" \
        --db="$db" --key="$key" --bind=":${port}" \
        --server-url="http://127.0.0.1:${SERVER_PORT}" \
        --server-pub="$SRV_PUB_HEX" \
        --poll-interval="1s" --auto-discover=false --chain="$SCOPE_CHAIN" \
        run > "$log" 2>&1 &
    echo $!
}

# ---- setup ------------------------------------------------------------

step "Setup: clean slate"
fd0_test_stop_matching -f fd0-server  2>/dev/null || true
fd0_test_stop_matching -f fd0-agent   2>/dev/null || true
fd0_test_stop_matching -f fd0-witness 2>/dev/null || true
sleep 0.3
rm -rf "$HOME_AL" "$SERVER_DB" "$SERVER_LOG" "$SERVER_KEY" \
       "$WITNESS_DB" "$WITNESS_KEY" "$WITNESS_LOG"

# fd0-server stores its translog keyfile next to the DB (default
# path = dirname(db)/server-translog.key).
"$FD0_SERVER_BIN" --bind=":${SERVER_PORT}" --db="$SERVER_DB" \
    --no-ratelimit > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
SERVER_READY=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if curl -fs "http://127.0.0.1:${SERVER_PORT}/health" >/dev/null 2>&1; then
        SERVER_READY=1
        break
    fi
    sleep 0.25
done
if [ "$SERVER_READY" -ne 1 ]; then
    no "server failed to come up"; exit 1
fi
ok "server up on :${SERVER_PORT}"

SRV_PUB_HEX=$(extract_server_pub_hex)
[ -n "$SRV_PUB_HEX" ] && ok "server translog pub: ${SRV_PUB_HEX:0:16}…" \
    || { no "could not read server pub"; exit 1; }

# Client init + bootstrap a scope.
mkfd0 "$HOME_AL" "http://127.0.0.1:${SERVER_PORT}"
printf "alice-pass\nalice-pass\n" | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" init >/dev/null 2>&1
printf "alice-pass\n" | env FD0_HOME="$HOME_AL" FD0_SSH_SOCK="$HOME_AL/ssh.sock" "$FD0" unlock >/dev/null 2>&1
sleep 0.3

AL scope create --label work >/dev/null
AL set k1 v1 --scope work >/dev/null
AL sync >/dev/null 2>&1
sleep 0.3

# Determine the scope chain ID.
SCOPE_CHAIN=$(sqlite3 "$SERVER_DB" "SELECT chain_id FROM chains WHERE chain_id LIKE 'scope:%' LIMIT 1;")
[ -n "$SCOPE_CHAIN" ] && ok "client bootstrapped scope $SCOPE_CHAIN" \
    || { no "could not find scope chain in server DB"; exit 1; }

# Witness 1.
WITNESS_PID=$(start_witness "$WITNESS_DB" "$WITNESS_KEY" "$WITNESS_PORT" "$WITNESS_LOG")
sleep 1.5  # let witness boot + first poll
W_PUB_HEX=$(extract_witness_pub_hex "$WITNESS_KEY")
[ -n "$W_PUB_HEX" ] && ok "witness1 up + cosign pub: ${W_PUB_HEX:0:16}…" \
    || { no "could not read witness pub"; exit 1; }

# ---- direct HTTP probes against the witness ---------------------------

step "Direct HTTP probes against witness1"

# server-info should return the witness pub.
INFO=$(curl -sf "http://127.0.0.1:${WITNESS_PORT}/v1/server-info" -o "$INFO_BODY" -w "%{http_code}")
if [ "$INFO" = "200" ]; then
    ok "GET /v1/server-info returned 200"
else
    no "GET /v1/server-info returned $INFO"
fi

# server URL -> base64url (no padding) for the path segment.
SRV_B64=$(python3 -c "
import base64,sys
sys.stdout.write(base64.urlsafe_b64encode(b'http://127.0.0.1:${SERVER_PORT}').rstrip(b'=').decode())
")

# Latest STH endpoint.
STATUS=$(curl -s -o "$LATEST_BODY" -w "%{http_code}" \
    "http://127.0.0.1:${WITNESS_PORT}/v1/sth/${SRV_B64}/${SCOPE_CHAIN}")
if [ "$STATUS" = "200" ]; then
    ok "witness has latest STH for scope (200)"
else
    no "GET latest WitnessedSTH returned $STATUS (witness may not have polled yet)"
fi

# Unobserved size → 404.
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${WITNESS_PORT}/v1/sth/${SRV_B64}/${SCOPE_CHAIN}?tree_size=999999")
if [ "$STATUS" = "404" ]; then
    ok "GET unobserved tree_size returns 404 (lag handling)"
else
    no "expected 404, got $STATUS"
fi

# ---- end-to-end client cross-check (happy path) -----------------------

step "Client cross-check: happy path with min_cosigns=1"

# Append [[witness]] block + policy to client config. With the
# absolute-threshold semantics (codex fix #3 hardened), the
# witness MUST have caught up to the current tip before the
# client's sync — otherwise the cross-check fails with
# insufficient cosigns. We achieve that by waiting for the
# witness's archive max(tree_size) to equal the server's.
cat >> "$HOME_AL/config.toml" <<EOF

[[witness]]
url = "http://127.0.0.1:${WITNESS_PORT}"
pub = "${W_PUB_HEX}"

[witness_policy]
min_cosigns = 1
EOF

AL set k2 v2 --scope work >/dev/null
# Push k2 first (no cross-check on local set), then wait for
# witness to observe the resulting STH, then sync to trigger
# the cross-check on the next round.
AL sync >/dev/null 2>&1 || true   # may fail because witness lags; retry below
for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    SVR=$(sqlite3 "$SERVER_DB" "SELECT MAX(tree_size) FROM translog_sths WHERE chain_id='${SCOPE_CHAIN}';")
    WIT=$(sqlite3 "$WITNESS_DB" "SELECT COALESCE(MAX(tree_size),0) FROM witness_sths WHERE chain_id='${SCOPE_CHAIN}' AND witness_signature IS NOT NULL;")
    [ "$SVR" = "$WIT" ] && break
done
SYNC_OUT=$(AL sync 2>&1)
if echo "$SYNC_OUT" | grep -q "✓ sync ok"; then
    ok "client sync succeeded WITH witness cross-check (min_cosigns=1)"
else
    no "client sync FAILED with witness cross-check: $(echo "$SYNC_OUT" | head -c 250)"
fi
GOT=$(AL get k2 --scope work --raw 2>/dev/null)
[ "$GOT" = "v2" ] && ok "value k2 reads back correctly under cross-check" \
    || no "value k2 not readable: $GOT"

# ---- min_cosigns > configured witness count → loud config rejection ---

step "Client cross-check: min_cosigns > witness count → reject loudly"

cp "$HOME_AL/config.toml" "$HOME_AL/config.toml.bak"
sed -i.bak 's/min_cosigns = 1/min_cosigns = 5/' "$HOME_AL/config.toml"
SYNC_OUT=$(AL sync 2>&1 || true)
if echo "$SYNC_OUT" | grep -qi "exceeds configured witness count"; then
    ok "min_cosigns=5 with 1 witness rejected at config load"
else
    no "expected loud config rejection, got: $(echo "$SYNC_OUT" | head -c 250)"
fi
mv "$HOME_AL/config.toml.bak" "$HOME_AL/config.toml"

# ---- equivocation: inject a cosigned STH with different root ---

step "Equivocation: inject a cosigned-but-different-root row"

# The strongest assertion: a witness archive that holds a cosigned
# STH with a DIFFERENT root_hash than what the server gives the
# client at the same tree_size MUST cause the client to reject.
#
# We construct this by writing a Go helper that:
#   1. Reads the witness's keypair from $WITNESS_KEY
#   2. Reads the server's keypair from $SERVER_KEY
#   3. Picks the current tree_size from the witness DB
#   4. Forges a (server-signed) STH at that size with a tampered
#      root, then witness-cosigns it, then INSERTs it into the
#      witness DB at a different root_hash (which is allowed by
#      the schema's 4-key PK).
#   5. Verifies the next AL sync FAILS with "equivocation".
#
# Stop the witness so it doesn't poll over our injection.
kill "$WITNESS_PID" 2>/dev/null || true
sleep 0.3

# Helper lives at cmd/fd0-test-equiv-inject (must be inside the
# module to import internal/translog). Defined inline here only as
# documentation; the real source is at the path below.
: <<'GO'
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/translog"
	_ "modernc.org/sqlite"
)

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: inject_equiv <witness_db> <server_db> <server_key> <witness_key> <server_url>")
		os.Exit(2)
	}
	wDB, srvDB, srvKeyPath, wKeyPath, serverURL := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5]
	srvKey, err := os.ReadFile(srvKeyPath)
	if err != nil { panic(err) }
	wKey, err := os.ReadFile(wKeyPath)
	if err != nil { panic(err) }
	srvPriv := ed25519.PrivateKey(srvKey)
	wPriv := ed25519.PrivateKey(wKey)

	db, err := sql.Open("sqlite", "file:"+wDB+"?_pragma=busy_timeout(5000)")
	if err != nil { panic(err) }
	defer db.Close()

	// Read the SERVER's current tree_size — that's the size the
	// client will be asking the witness about. Forking at the
	// witness's lagging max would just trigger 404+lag.
	srv, err := sql.Open("sqlite", "file:"+srvDB+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil { panic(err) }
	defer srv.Close()
	var chainID string
	var size int64
	err = srv.QueryRowContext(context.Background(),
		`SELECT chain_id, MAX(tree_size) FROM translog_sths
		 WHERE chain_id LIKE 'scope:%' GROUP BY chain_id ORDER BY MAX(tree_size) DESC LIMIT 1`,
	).Scan(&chainID, &size)
	if err != nil { panic(err) }

	// Forge an STH at that exact size with a TAMPERED root.
	tampered := make([]byte, 32)
	for i := range tampered { tampered[i] = 0xEE }
	head := translog.TreeHead{
		ChainID: chainID, TreeSize: uint64(size), RootHash: tampered, Timestamp: 1,
	}
	sth, err := translog.SignSTH(srvPriv, head)
	if err != nil { panic(err) }
	wsth, err := translog.SignWitnessedSTH(wPriv, sth, serverURL)
	if err != nil { panic(err) }

	// fetched_at FAR in the future so future polls don't displace
	// us in LookupAt's "ORDER BY fetched_at DESC" tiebreak (the
	// honest poll would otherwise win and hide the forked row).
	farFuture := time.Now().Add(10 * 365 * 24 * time.Hour).Unix()
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO witness_sths
		 (server_url, chain_id, tree_size, root_hash, timestamp, signature, fetched_at, witness_signature)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		serverURL, chainID, size, tampered, int64(1), sth.Signature, farFuture, wsth.WitnessSig,
	)
	if err != nil { panic(err) }
	fmt.Printf("injected forked STH at chain=%s size=%d root=%x\n", chainID, size, tampered)
}
GO

# Run the helper (lives at cmd/fd0-test-equiv-inject, builds from
# inside the module so it can import internal/translog).
INJECT_OUT=$( cd "$(dirname "$0")/.." && go run ./cmd/fd0-test-equiv-inject \
    "$WITNESS_DB" "$SERVER_DB" "$SERVER_KEY" "$WITNESS_KEY" \
    "http://127.0.0.1:${SERVER_PORT}" 2>&1 )
echo "$INJECT_OUT" | head -5 | sed 's/^/    inject> /'

# Restart witness HTTP server (read-only side; it just serves
# whatever is in the DB now, which includes our injected forked row).
WITNESS_PID=$(start_witness "$WITNESS_DB" "$WITNESS_KEY" "$WITNESS_PORT" "$WITNESS_LOG")
sleep 1

# Note: LookupAt orders by fetched_at DESC, so our injected row
# (newest fetched_at) wins for the size the client is currently at.
SYNC_OUT=$(AL sync 2>&1 || true)
if echo "$SYNC_OUT" | grep -qi "equivocation detected"; then
    ok "client REJECTS sync when witness has cosigned different root at same size"
else
    no "expected equivocation rejection, got: $(echo "$SYNC_OUT" | head -c 300)"
fi

step "Client cross-check: lagging witness → reject (no soft-tolerance knob)"

# Codex fix #3: there is no longer an allow_lag escape hatch. A
# lagging witness is functionally identical to an unreachable
# one — both fail the absolute MinCosigns floor. Demonstrated by
# stopping the witness and writing fresh keys: the next sync
# cannot find a valid cosign at the new tree_size and refuses.
kill "$WITNESS_PID" 2>/dev/null || true
sleep 0.3
AL set k3 v3 --scope work >/dev/null
SYNC_OUT=$(AL sync 2>&1 || true)
if echo "$SYNC_OUT" | grep -qi "insufficient matching cosigns"; then
    ok "client refuses sync when witness is unreachable + cross-check enabled"
else
    no "expected insufficient-cosigns rejection, got: $(echo "$SYNC_OUT" | head -c 250)"
fi

# Restart witness to let it catch up for the closing checks.
WITNESS_PID=$(start_witness "$WITNESS_DB" "$WITNESS_KEY" "$WITNESS_PORT" "$WITNESS_LOG")
sleep 1.5

# ---- witness cosign archive: check that cosigns actually got stored ---

step "Witness archive verification"

COSIGN_ROWS=$(sqlite3 "$WITNESS_DB" "SELECT COUNT(*) FROM witness_sths WHERE witness_signature IS NOT NULL;")
if [ "$COSIGN_ROWS" -ge 1 ]; then
    ok "witness archive has $COSIGN_ROWS row(s) WITH cosign"
else
    no "no cosigned rows in witness archive"
fi

# Witness keypair persisted in DB.
KP_ROW=$(sqlite3 "$WITNESS_DB" "SELECT length(pub) FROM witness_keypair;")
[ "$KP_ROW" = "32" ] && ok "witness_keypair table has 32-byte pub" \
    || no "witness_keypair table missing or wrong size"

# ---- summary ----------------------------------------------------------

AL lock >/dev/null 2>&1 || true
echo
printf "\033[1m== WITNESS-COSIGN SUMMARY ==\033[0m  PASS=%d  FAIL=%d\n" "$PASS" "$FAIL"
exit $FAIL
