// fd0-test-equiv-inject is a TEST-ONLY helper that injects a forged
// "equivocation" row into a witness archive: a server-signed STH at
// the server's CURRENT tree_size with a tampered root_hash, plus a
// matching witness cosign. Used by tests/integration_witness_cosign.sh
// to verify the client's cross-check path actually rejects
// equivocation evidence.
//
// Production deployments must NEVER ship this binary.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"

	"github.com/valentinkolb/fd0.sh/internal/translog"
)

func main() {
	if len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: fd0-test-equiv-inject <witness_db> <server_db> <server_key> <witness_key> <server_url>")
		os.Exit(2)
	}
	wDB, srvDB := os.Args[1], os.Args[2]
	srvKeyPath, wKeyPath := os.Args[3], os.Args[4]
	serverURL := os.Args[5]

	srvKey, err := os.ReadFile(srvKeyPath)
	must(err)
	wKey, err := os.ReadFile(wKeyPath)
	must(err)
	srvPriv := ed25519.PrivateKey(srvKey)
	wPriv := ed25519.PrivateKey(wKey)

	// Read SERVER's current tree_size for the most recent scope chain.
	// That's the size the client will ask the witness about; forking
	// at the witness's lagging max would just trigger 404+lag.
	srv, err := sql.Open("sqlite", "file:"+srvDB+"?mode=ro&_pragma=busy_timeout(5000)")
	must(err)
	defer srv.Close()
	var chainID string
	var size int64
	err = srv.QueryRowContext(context.Background(), `
		SELECT chain_id, MAX(tree_size) FROM translog_sths
		 WHERE chain_id LIKE 'scope:%'
		 GROUP BY chain_id ORDER BY MAX(tree_size) DESC LIMIT 1`,
	).Scan(&chainID, &size)
	must(err)

	// Forge a server-signed STH at that exact size with a tampered
	// root. The signature verifies under the real server pub
	// (because we have the real key), so the cosign verifies, and
	// the client's cross-check sees ROOT MISMATCH at SAME SIZE →
	// equivocation, hard reject.
	tampered := make([]byte, 32)
	for i := range tampered {
		tampered[i] = 0xEE
	}
	head := translog.TreeHead{
		ChainID: chainID, TreeSize: uint64(size), RootHash: tampered, Timestamp: 1,
	}
	sth, err := translog.SignSTH(srvPriv, head)
	must(err)
	wsth, err := translog.SignWitnessedSTH(wPriv, sth, serverURL)
	must(err)

	db, err := sql.Open("sqlite", "file:"+wDB+"?_pragma=busy_timeout(5000)")
	must(err)
	defer db.Close()

	// fetched_at FAR in the future so an honest poll cannot
	// displace us in LookupAt's "ORDER BY fetched_at DESC" tiebreak.
	farFuture := time.Now().Add(10 * 365 * 24 * time.Hour).Unix()
	_, err = db.ExecContext(context.Background(), `
		INSERT INTO witness_sths
		 (server_url, chain_id, tree_size, root_hash, timestamp, signature, fetched_at, witness_signature)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		serverURL, chainID, size, tampered, int64(1), sth.Signature, farFuture, wsth.WitnessSig,
	)
	must(err)
	fmt.Printf("injected forked STH: chain=%s size=%d root=%x\n", chainID, size, tampered[:8])
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "inject:", err)
		os.Exit(1)
	}
}
