package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// fakeServer implements just enough of the fd0-server translog
// endpoints for witness tests: GET /v1/sth/{chainId} and
// GET /v1/proof/consistency. The test driver controls what STH /
// proof bytes get returned per call so we can simulate equivocation,
// regression, bad signatures, etc.
type fakeServer struct {
	mux        *http.ServeMux
	srv        *httptest.Server
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	chainID    string
	state      atomic.Pointer[fakeServerState]
}

type fakeServerState struct {
	leaves   [][]byte // leaf hashes appended so far
	currentSTH translog.STH
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeServer{
		mux:     http.NewServeMux(),
		priv:    priv,
		pub:     pub,
		chainID: "scope:s_witnesstesttesttesttesttesttest",
	}
	fs.state.Store(&fakeServerState{})
	fs.mux.HandleFunc("GET /v1/sth/{chainId}", fs.handleSTH)
	fs.mux.HandleFunc("GET /v1/proof/consistency", fs.handleConsistency)
	fs.srv = httptest.NewServer(fs.mux)
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *fakeServer) handleSTH(w http.ResponseWriter, r *http.Request) {
	st := fs.state.Load()
	body, _ := proto.Marshal(st.currentSTH)
	w.Header().Set("Content-Type", "application/cbor")
	_, _ = w.Write(body)
}

func (fs *fakeServer) handleConsistency(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from := mustParseUint(q.Get("from_size"))
	to := mustParseUint(q.Get("to_size"))
	st := fs.state.Load()
	nodes, err := translog.BuildConsistencyProof(st.leaves, from, to)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, _ := proto.Marshal(translog.ConsistencyProof{
		FromSize: from, ToSize: to, Nodes: nodes,
	})
	w.Header().Set("Content-Type", "application/cbor")
	_, _ = w.Write(body)
}

// appendLeaf grows the fake server's tree by one leaf and re-signs
// the STH. Tests call this between PollOnce invocations to simulate
// real server progress.
func (fs *fakeServer) appendLeaf(t *testing.T, content byte) {
	t.Helper()
	st := fs.state.Load()
	newLeaves := append([][]byte(nil), st.leaves...)
	leafBytes := make([]byte, 32)
	for i := range leafBytes {
		leafBytes[i] = content
	}
	newLeaves = append(newLeaves, translog.LeafHash(leafBytes))
	root := translog.MerkleTreeHash(newLeaves)
	sth, err := translog.SignSTH(fs.priv, translog.TreeHead{
		ChainID:   fs.chainID,
		TreeSize:  uint64(len(newLeaves)),
		RootHash:  root,
		Timestamp: 1700000000 + uint64(len(newLeaves)),
	})
	if err != nil {
		t.Fatal(err)
	}
	fs.state.Store(&fakeServerState{leaves: newLeaves, currentSTH: sth})
}

// equivocate replaces the current STH with one signed at the SAME
// tree_size but a DIFFERENT root — what a malicious server would do
// to two different clients. The next witness poll observes the new
// root; the archive then has two distinct roots at the same size.
func (fs *fakeServer) equivocate(t *testing.T) {
	t.Helper()
	st := fs.state.Load()
	if st.currentSTH.Head.TreeSize == 0 {
		t.Fatal("equivocate: tree is empty, cannot fork")
	}
	// Build an alternate "history" with the same number of leaves but
	// a different last leaf. The root differs accordingly.
	altLeaves := append([][]byte(nil), st.leaves[:len(st.leaves)-1]...)
	altLeafBytes := make([]byte, 32)
	for i := range altLeafBytes {
		altLeafBytes[i] = 0xAA
	}
	altLeaves = append(altLeaves, translog.LeafHash(altLeafBytes))
	altRoot := translog.MerkleTreeHash(altLeaves)
	if equalBytesSlice(altRoot, st.currentSTH.Head.RootHash) {
		t.Fatal("equivocate: alt root accidentally matches original")
	}
	altSTH, err := translog.SignSTH(fs.priv, translog.TreeHead{
		ChainID:   st.currentSTH.Head.ChainID,
		TreeSize:  st.currentSTH.Head.TreeSize,
		RootHash:  altRoot,
		Timestamp: st.currentSTH.Head.Timestamp + 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	fs.state.Store(&fakeServerState{leaves: altLeaves, currentSTH: altSTH})
}

func newWitness(t *testing.T, fs *fakeServer) *Witness {
	t.Helper()
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := Config{
		Targets: []Target{{
			ServerURL:    fs.srv.URL,
			ServerPub:    fs.pub,
			Chains:       []string{fs.chainID},
			PollInterval: time.Second,
		}},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w := New(store, cfg, logger)
	if err := w.EnsurePins(context.Background()); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWitnessArchivesFirstSTH(t *testing.T) {
	fs := newFakeServer(t)
	fs.appendLeaf(t, 0x01)
	w := newWitness(t, fs)

	if err := w.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	got, err := w.Store.LatestSTH(context.Background(), fs.srv.URL, fs.chainID)
	if err != nil {
		t.Fatalf("LatestSTH: %v", err)
	}
	if got.Head.TreeSize != 1 {
		t.Fatalf("first STH size: got %d want 1", got.Head.TreeSize)
	}
}

func TestWitnessAdvancesAndVerifiesConsistency(t *testing.T) {
	fs := newFakeServer(t)
	fs.appendLeaf(t, 0x01)
	w := newWitness(t, fs)

	ctx := context.Background()
	if err := w.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	for i := byte(2); i <= 5; i++ {
		fs.appendLeaf(t, i)
		if err := w.PollOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}

	got, err := w.Store.LatestSTH(ctx, fs.srv.URL, fs.chainID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Head.TreeSize != 5 {
		t.Fatalf("after 5 polls, tree_size = %d (want 5)", got.Head.TreeSize)
	}
	total, _ := w.Store.CountAll(ctx)
	if total != 5 {
		t.Fatalf("archive total = %d (want 5)", total)
	}
}

func TestWitnessDetectsSameSizeEquivocation(t *testing.T) {
	fs := newFakeServer(t)
	fs.appendLeaf(t, 0x01)
	w := newWitness(t, fs)

	ctx := context.Background()
	if err := w.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// Server presents a different history at the same size.
	fs.equivocate(t)
	if err := w.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}

	equiv, err := w.Store.DetectEquivocationAt(ctx, fs.srv.URL, fs.chainID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !equiv {
		t.Fatal("witness should have detected same-size equivocation at tree_size=1")
	}
	rows, _ := w.Store.EquivocationsAt(ctx, fs.srv.URL, fs.chainID, 1)
	if len(rows) != 2 {
		t.Fatalf("expected 2 evidence rows, got %d", len(rows))
	}
}

func TestWitnessRejectsBadSignature(t *testing.T) {
	fs := newFakeServer(t)
	fs.appendLeaf(t, 0x01)
	w := newWitness(t, fs)

	ctx := context.Background()
	// Re-pin with the WRONG pubkey to simulate a server-key swap
	// after the witness was deployed. Use a side store so the test
	// doesn't fight ErrPinMismatch.
	dir := t.TempDir()
	badStore, err := Open(filepath.Join(dir, "bad.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer badStore.Close()
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := badStore.PinServer(ctx, fs.srv.URL, otherPub); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Targets: []Target{{
		ServerURL: fs.srv.URL, ServerPub: otherPub,
		Chains: []string{fs.chainID}, PollInterval: time.Second,
	}}}
	bw := New(badStore, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := bw.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// STH should NOT have been archived (signature failed).
	total, _ := badStore.CountAll(ctx)
	if total != 0 {
		t.Fatalf("bad-signature STH must not be archived, archive has %d rows", total)
	}
	_ = w // unused
}

// TestWitnessRejectsChainIDSwap covers the chain-id binding (codex
// C5 #3): a server returning a sig-valid STH whose embedded
// chain_id differs from the one we asked about must be REJECTED.
// Without this check, a server could redirect witness archives
// across chains undetected.
func TestWitnessRejectsChainIDSwap(t *testing.T) {
	fs := newFakeServer(t)
	fs.appendLeaf(t, 0x01)
	w := newWitness(t, fs)

	// Mutate fake server state to swap the STH chain_id.
	st := fs.state.Load()
	swapped := st.currentSTH
	swapped.Head.ChainID = "scope:s_eviltargettargettargettarget"
	resigned, err := translog.SignSTH(fs.priv, swapped.Head)
	if err != nil {
		t.Fatal(err)
	}
	fs.state.Store(&fakeServerState{leaves: st.leaves, currentSTH: resigned})

	if err := w.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	total, _ := w.Store.CountAll(context.Background())
	if total != 0 {
		t.Fatalf("witness archived chain-swapped STH: %d rows (want 0)", total)
	}
}

// TestWitnessArchivesOnConsistencyFetchFailure covers codex C5 #1:
// when /v1/proof/consistency cannot be fetched (network failure, 5xx,
// etc.), the witness MUST still archive the new STH AND record a
// witness_consistency_failures row so the evidence survives a
// witness restart.
//
// Approach: build a custom mux from the start that 500s on
// consistency requests. Reuse the fakeServer signing identity for
// the STH endpoint so signatures verify.
func TestWitnessArchivesOnConsistencyFetchFailure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	chainID := "scope:s_failtestfailtestfailtestfail"

	state := atomic.Pointer[fakeServerState]{}
	state.Store(&fakeServerState{})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sth/{chainId}", func(w http.ResponseWriter, r *http.Request) {
		st := state.Load()
		body, _ := proto.Marshal(st.currentSTH)
		w.Header().Set("Content-Type", "application/cbor")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("GET /v1/proof/consistency", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "intentional 500", http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Helper: append a leaf and re-sign STH against this fake.
	appendLeaf := func(content byte) {
		st := state.Load()
		newLeaves := append([][]byte(nil), st.leaves...)
		lb := make([]byte, 32)
		for i := range lb {
			lb[i] = content
		}
		newLeaves = append(newLeaves, translog.LeafHash(lb))
		root := translog.MerkleTreeHash(newLeaves)
		sth, _ := translog.SignSTH(priv, translog.TreeHead{
			ChainID: chainID, TreeSize: uint64(len(newLeaves)),
			RootHash: root, Timestamp: 1700000000 + uint64(len(newLeaves)),
		})
		state.Store(&fakeServerState{leaves: newLeaves, currentSTH: sth})
	}
	appendLeaf(0x01)

	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := Config{Targets: []Target{{
		ServerURL: srv.URL, ServerPub: pub,
		Chains: []string{chainID}, PollInterval: time.Second,
	}}}
	w := New(store, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	if err := w.EnsurePins(ctx); err != nil {
		t.Fatal(err)
	}

	// First poll: archive the STH at size 1. No prior, so no
	// consistency proof needed.
	if err := w.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	beforeArchive, _ := store.CountAll(ctx)

	// Grow the tree, then poll. Consistency endpoint 500s →
	// witness must archive AND record a failure row.
	appendLeaf(0x02)
	if err := w.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	afterArchive, _ := store.CountAll(ctx)
	if afterArchive <= beforeArchive {
		t.Fatalf("witness must archive STH even on proof-fetch failure (before=%d after=%d)",
			beforeArchive, afterArchive)
	}
	n, err := store.CountConsistencyFailures(ctx, srv.URL, chainID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 consistency-failure row, got %d", n)
	}
}

func TestPinServerRejectsConflictingKey(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := store.PinServer(ctx, "https://x", pub1); err != nil {
		t.Fatal(err)
	}
	// Same key → idempotent.
	if err := store.PinServer(ctx, "https://x", pub1); err != nil {
		t.Fatalf("idempotent re-pin: %v", err)
	}
	// Different key → ErrPinMismatch.
	if err := store.PinServer(ctx, "https://x", pub2); err != ErrPinMismatch {
		t.Fatalf("expected ErrPinMismatch, got %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubHex := hex.EncodeToString(pub)
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"valid", Config{Targets: []Target{{
			ServerURL: "https://x", ServerPubHex: pubHex,
			Chains: []string{"scope:s_test"}, PollInterval: time.Second,
		}}}, false},
		{"no targets", Config{}, true},
		{"empty url", Config{Targets: []Target{{ServerPubHex: pubHex, Chains: []string{"scope:s_x"}}}}, true},
		{"bad pubhex", Config{Targets: []Target{{ServerURL: "https://u", ServerPubHex: "ZZ", Chains: []string{"scope:s_x"}}}}, true},
		{"short pubhex", Config{Targets: []Target{{ServerURL: "https://u", ServerPubHex: "abcd", Chains: []string{"scope:s_x"}}}}, true},
		{"no chains", Config{Targets: []Target{{ServerURL: "https://u", ServerPubHex: pubHex}}}, true},
		{"bad chain prefix", Config{Targets: []Target{{ServerURL: "https://u", ServerPubHex: pubHex, Chains: []string{"witness:foo"}}}}, true},
		{"sub-second interval", Config{Targets: []Target{{ServerURL: "https://u", ServerPubHex: pubHex, Chains: []string{"scope:s_x"}, PollInterval: time.Millisecond}}}, true},
		{"url without scheme", Config{Targets: []Target{{ServerURL: "u", ServerPubHex: pubHex, Chains: []string{"scope:s_x"}}}}, true},
		{"url without host", Config{Targets: []Target{{ServerURL: "https://", ServerPubHex: pubHex, Chains: []string{"scope:s_x"}}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := (&c.cfg).Validate()
			if c.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSaveLoadConfigRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "w.toml")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cfg := Config{Targets: []Target{{
		ServerURL:    "https://example.com",
		ServerPubHex: hex.EncodeToString(pub),
		Chains:       []string{"scope:s_aaaaaaaaaaaaaaaaaaaaaaaaaa"},
		PollInterval: time.Hour,
	}}}
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Targets) != 1 {
		t.Fatalf("loaded %d targets, want 1", len(loaded.Targets))
	}
	if loaded.Targets[0].ServerURL != cfg.Targets[0].ServerURL {
		t.Fatal("ServerURL roundtrip mismatch")
	}
}

func mustParseUint(s string) uint64 {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

func equalBytesSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// avoid "unused" warning when only some helpers are referenced.
var _ = os.WriteFile
