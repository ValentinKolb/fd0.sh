package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

func TestOpenMigratesLegacyWitnessArchive(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE witness_sths (
			server_url TEXT NOT NULL,
			chain_id TEXT NOT NULL,
			tree_size INTEGER NOT NULL,
			root_hash BLOB NOT NULL CHECK (length(root_hash) = 32),
			timestamp INTEGER NOT NULL,
			signature BLOB NOT NULL CHECK (length(signature) = 64),
			fetched_at INTEGER NOT NULL,
			PRIMARY KEY (server_url, chain_id, tree_size, root_hash)
		)
	`)
	if err != nil {
		t.Fatal(err)
	}

	const serverURL = "https://legacy.example"
	const chainID = "scope:s_legacywitnessmigration"
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	legacySTH := signedMigrationSTH(t, serverPriv, chainID, 1, 0x11)
	_, err = db.Exec(
		`INSERT INTO witness_sths
		 (server_url, chain_id, tree_size, root_hash, timestamp, signature, fetched_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		serverURL, chainID, 1, legacySTH.Head.RootHash,
		legacySTH.Head.Timestamp, legacySTH.Signature, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(path)
	if err != nil {
		t.Fatalf("open legacy archive: %v", err)
	}
	defer store.Close()

	gotLegacy, err := store.LatestSTH(ctx, serverURL, chainID)
	if err != nil || gotLegacy.Head.TreeSize != 1 {
		t.Fatalf("legacy STH not preserved: size=%d err=%v", gotLegacy.Head.TreeSize, err)
	}
	if _, err := store.LatestVerifiedSTH(ctx, serverURL, chainID); !errors.Is(err, ErrNoSTH) {
		t.Fatalf("legacy row unexpectedly became a verified cosign: %v", err)
	}

	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	currentSTH := signedMigrationSTH(t, serverPriv, chainID, 2, 0x22)
	witnessed, err := translog.SignWitnessedSTH(witnessPriv, currentSTH, serverURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Insert(ctx, serverURL, currentSTH, 2, witnessed.WitnessSig); err != nil {
		t.Fatalf("insert after migration: %v", err)
	}
	gotCurrent, err := store.LatestVerifiedSTH(ctx, serverURL, chainID)
	if err != nil || gotCurrent.Head.TreeSize != 2 {
		t.Fatalf("new cosigned STH unavailable: size=%d err=%v", gotCurrent.Head.TreeSize, err)
	}

	httpServer := httptest.NewServer((&HTTPServer{
		Store:      store,
		WitnessPub: witnessPub,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).Handler())
	defer httpServer.Close()
	resp, err := http.Get(httpServer.URL + "/v1/sth/" + EncodeServerURL(serverURL) + "/" + chainID + "?tree_size=2")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("migrated HTTP lookup status %d: %s", resp.StatusCode, body)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var gotWitnessed translog.WitnessedSTH
	if err := proto.Unmarshal(body, &gotWitnessed); err != nil {
		t.Fatal(err)
	}
	if err := translog.VerifyWitnessedSTH(serverPub, witnessPub, serverURL, chainID, gotWitnessed); err != nil {
		t.Fatalf("verify migrated HTTP response: %v", err)
	}
	httpServer.Close()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("idempotent reopen after migration: %v", err)
	}
	defer reopened.Close()
	if got, err := reopened.LatestVerifiedSTH(ctx, serverURL, chainID); err != nil || got.Head.TreeSize != 2 {
		t.Fatalf("reopened migrated archive lost cosign: size=%d err=%v", got.Head.TreeSize, err)
	}
}

func signedMigrationSTH(t *testing.T, priv ed25519.PrivateKey, chainID string, size uint64, marker byte) translog.STH {
	t.Helper()
	root := make([]byte, 32)
	for i := range root {
		root[i] = marker
	}
	sth, err := translog.SignSTH(priv, translog.TreeHead{
		ChainID: chainID, TreeSize: size, RootHash: root, Timestamp: size,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sth
}
