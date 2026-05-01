package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// newTestStore returns a fresh in-memory Store with a generated
// translog key already installed. Tests get isolation per call.
func newTestStore(t *testing.T) (*Store, ed25519.PublicKey) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(tmp)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	if err := s.SetTranslogKey(priv, pub); err != nil {
		t.Fatalf("SetTranslogKey: %v", err)
	}
	return s, pub
}

// fakeEventHash builds a unique 32-byte content hash from `i` so that
// each leaf is distinguishable. Mirrors what `proto.HashPrefix` would
// emit for a real event but without the CBOR overhead.
func fakeEventHash(i uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], i+1)
	h := sha256.Sum256(buf[:])
	return h[:]
}

// appendN appends n leaves to chainID and returns the leaf hashes (in
// order) plus every STH the storage layer signed (one per AppendLeaf).
func appendN(t *testing.T, s *Store, chainID string, n uint64) ([][]byte, []translog.STH) {
	t.Helper()
	ctx := context.Background()
	leaves := make([][]byte, 0, n)
	sths := make([]translog.STH, 0, n)
	for i := uint64(0); i < n; i++ {
		ev := fakeEventHash(i)
		sth, err := s.AppendLeaf(ctx, chainID, ev, 1700000000+i)
		if err != nil {
			t.Fatalf("AppendLeaf #%d: %v", i, err)
		}
		leaves = append(leaves, translog.LeafHash(ev))
		sths = append(sths, sth)
	}
	return leaves, sths
}

// TestAppendLeafReturnsValidSTH checks the basic append → STH flow:
// each AppendLeaf returns a signed STH whose root matches the
// canonical pure-layer MerkleTreeHash over all leaves so far.
func TestAppendLeafReturnsValidSTH(t *testing.T) {
	s, pub := newTestStore(t)
	const n = 17
	leaves, sths := appendN(t, s, "scope:s_test", n)
	for i, sth := range sths {
		// Signature verifies under the installed pubkey AND head is
		// structurally valid (size↔root binding etc.).
		if err := translog.VerifySTH(pub, sth); err != nil {
			t.Fatalf("STH #%d: VerifySTH: %v", i, err)
		}
		// The root the storage layer signed must equal the canonical
		// reference root computed from the leaves so far. This is the
		// cross-validation that catches any drift between the
		// incremental tree and the pure recursive tree.
		want := translog.MerkleTreeHash(leaves[:i+1])
		if !bytes.Equal(sth.Head.RootHash, want) {
			t.Fatalf("STH #%d root drift: got %x want %x (size=%d)",
				i, sth.Head.RootHash, want, sth.Head.TreeSize)
		}
		if sth.Head.TreeSize != uint64(i+1) {
			t.Fatalf("STH #%d size: got %d want %d", i, sth.Head.TreeSize, i+1)
		}
	}
}

// TestCurrentSTHReflectsLatestAppend confirms CurrentSTH returns the
// most recently signed head, not an older one.
func TestCurrentSTHReflectsLatestAppend(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const cid = "scope:s_curtest"
	for i := uint64(0); i < 5; i++ {
		_, err := s.AppendLeaf(ctx, cid, fakeEventHash(i), 1700000000)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.CurrentSTH(ctx, cid)
		if err != nil {
			t.Fatalf("CurrentSTH after #%d: %v", i, err)
		}
		if got.Head.TreeSize != i+1 {
			t.Fatalf("CurrentSTH after #%d: got size %d want %d", i, got.Head.TreeSize, i+1)
		}
	}
}

// TestSTHAtBackfill confirms that every historical STH can be replayed
// by tree_size — required for witnesses that backfill an archive.
func TestSTHAtBackfill(t *testing.T) {
	s, pub := newTestStore(t)
	ctx := context.Background()
	const cid = "scope:s_backfill"
	const n = 10
	_, sths := appendN(t, s, cid, n)
	for size := uint64(1); size <= n; size++ {
		got, err := s.STHAt(ctx, cid, size)
		if err != nil {
			t.Fatalf("STHAt(%d): %v", size, err)
		}
		// Must equal the STH returned by AppendLeaf at that size.
		want := sths[size-1]
		if !bytes.Equal(got.Head.RootHash, want.Head.RootHash) {
			t.Fatalf("STHAt(%d) root mismatch", size)
		}
		if !bytes.Equal(got.Signature, want.Signature) {
			t.Fatalf("STHAt(%d) signature mismatch", size)
		}
		if err := translog.VerifySTH(pub, got); err != nil {
			t.Fatalf("STHAt(%d) verify: %v", size, err)
		}
	}
}

// TestInclusionProofCrossValidation: for every (size, index) pair up
// to size 16, the storage-layer InclusionProofFor must return a path
// that VerifyInclusion accepts AND that equals the pure-layer
// InclusionProof byte-for-byte. Catches any drift between the
// incremental tree and the canonical computation.
func TestInclusionProofCrossValidation(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const cid = "scope:s_incl"
	const maxSize = 16
	leaves, sths := appendN(t, s, cid, maxSize)
	for size := uint64(1); size <= maxSize; size++ {
		for idx := uint64(0); idx < size; idx++ {
			gotPath, err := s.InclusionProofFor(ctx, cid, idx, size)
			if err != nil {
				t.Fatalf("size=%d idx=%d: store proof: %v", size, idx, err)
			}
			wantPath, err := translog.BuildInclusionProof(leaves, idx, size)
			if err != nil {
				t.Fatalf("size=%d idx=%d: pure proof: %v", size, idx, err)
			}
			if len(gotPath) != len(wantPath) {
				t.Fatalf("size=%d idx=%d: path length %d vs %d", size, idx, len(gotPath), len(wantPath))
			}
			for i := range gotPath {
				if !bytes.Equal(gotPath[i], wantPath[i]) {
					t.Fatalf("size=%d idx=%d: path[%d] drift", size, idx, i)
				}
			}
			// Verify against the historical STH at that tree size.
			sth := sths[size-1]
			if err := translog.VerifyInclusion(leaves[idx], idx, size, gotPath, sth.Head.RootHash); err != nil {
				t.Fatalf("size=%d idx=%d: VerifyInclusion: %v", size, idx, err)
			}
		}
	}
}

// TestConsistencyProofCrossValidation: same idea for consistency.
// Every (oldSize, newSize) pair where 1 ≤ old ≤ new ≤ 16 must round-
// trip through the storage layer with a proof identical to the pure
// reference implementation.
func TestConsistencyProofCrossValidation(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const cid = "scope:s_cons"
	const maxSize = 16
	leaves, sths := appendN(t, s, cid, maxSize)
	for newSize := uint64(1); newSize <= maxSize; newSize++ {
		for oldSize := uint64(0); oldSize <= newSize; oldSize++ {
			gotProof, err := s.ConsistencyProofFor(ctx, cid, oldSize, newSize)
			if err != nil {
				t.Fatalf("(%d,%d): store proof: %v", oldSize, newSize, err)
			}
			wantProof, err := translog.BuildConsistencyProof(leaves, oldSize, newSize)
			if err != nil {
				t.Fatalf("(%d,%d): pure proof: %v", oldSize, newSize, err)
			}
			if len(gotProof) != len(wantProof) {
				t.Fatalf("(%d,%d): proof length %d vs %d", oldSize, newSize, len(gotProof), len(wantProof))
			}
			for i := range gotProof {
				if !bytes.Equal(gotProof[i], wantProof[i]) {
					t.Fatalf("(%d,%d): proof[%d] drift", oldSize, newSize, i)
				}
			}
			oldRoot := translog.EmptyRoot()
			if oldSize > 0 {
				oldRoot = sths[oldSize-1].Head.RootHash
			}
			newRoot := translog.EmptyRoot()
			if newSize > 0 {
				newRoot = sths[newSize-1].Head.RootHash
			}
			if err := translog.VerifyConsistency(oldSize, newSize, gotProof, oldRoot, newRoot); err != nil {
				t.Fatalf("(%d,%d): VerifyConsistency: %v", oldSize, newSize, err)
			}
		}
	}
}

// TestProofOutOfRange covers the input-validation paths.
func TestProofOutOfRange(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const cid = "scope:s_range"
	appendN(t, s, cid, 5)

	// Index >= treeSize.
	if _, err := s.InclusionProofFor(ctx, cid, 5, 5); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("idx==size should be out of range, got %v", err)
	}
	// treeSize > current.
	if _, err := s.InclusionProofFor(ctx, cid, 0, 6); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("size>current should be out of range, got %v", err)
	}
	// Consistency: oldSize > newSize.
	if _, err := s.ConsistencyProofFor(ctx, cid, 4, 2); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("oldSize>newSize should be out of range, got %v", err)
	}
	// Consistency: newSize > current.
	if _, err := s.ConsistencyProofFor(ctx, cid, 2, 6); !errors.Is(err, ErrIndexOutOfRange) {
		t.Fatalf("newSize>current should be out of range, got %v", err)
	}
}

// TestAppendLeafWithoutKey: AppendLeaf without an installed key must
// surface ErrTranslogKeyMissing — this is a configuration bug, not a
// per-request fault.
func TestAppendLeafWithoutKey(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "nokey.db")
	s, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.AppendLeaf(context.Background(), "scope:s_x", fakeEventHash(0), 1)
	if !errors.Is(err, ErrTranslogKeyMissing) {
		t.Fatalf("expected ErrTranslogKeyMissing, got %v", err)
	}
}

// TestSetTranslogKeyIdempotent: re-installing the same key is fine;
// installing a DIFFERENT key on top is rejected. Catches a hot-reload
// path that would silently swap the key (rotation must go through the
// operational ceremony, not a runtime call).
func TestSetTranslogKeyIdempotent(t *testing.T) {
	s, _ := newTestStore(t)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)

	// Re-install with the SAME priv pulled out of the store.
	if err := s.SetTranslogKey(s.translogPriv, s.translogPub); err != nil {
		t.Fatalf("idempotent re-install must succeed: %v", err)
	}
	// Install with a DIFFERENT key must fail.
	if err := s.SetTranslogKey(priv2, pub2); err == nil {
		t.Fatal("installing a different key must be rejected")
	}
}

// TestStressLargeTree exercises 1000 appends to surface any per-leaf
// overhead or off-by-one that only manifests past tiny trees. Verifies
// that the final root matches the canonical reference, every 73rd
// inclusion proof matches byte-for-byte, and a few canonical
// consistency proofs round-trip end-to-end.
//
// The byte-for-byte equality with the pure-layer reference catches the
// "internally consistent but globally wrong" failure mode codex flagged:
// a corrupted incremental tree that still self-verifies because every
// inclusion proof against its own root would pass.
func TestStressLargeTree(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const cid = "scope:s_stress"
	const n = 1000
	leaves, sths := appendN(t, s, cid, n)
	finalRoot := sths[n-1].Head.RootHash

	// Cross-validation: storage-layer final root MUST equal the
	// canonical pure-layer reference root.
	wantRoot := translog.MerkleTreeHash(leaves)
	if !bytes.Equal(finalRoot, wantRoot) {
		t.Fatalf("final root drift at n=%d: got %x want %x", n, finalRoot, wantRoot)
	}

	for i := uint64(0); i < n; i += 73 {
		path, err := s.InclusionProofFor(ctx, cid, i, n)
		if err != nil {
			t.Fatalf("size=%d idx=%d: store proof: %v", n, i, err)
		}
		// Cross-validation: storage-layer path MUST equal the pure-layer
		// reference path byte-for-byte.
		wantPath, err := translog.BuildInclusionProof(leaves, i, n)
		if err != nil {
			t.Fatalf("size=%d idx=%d: pure proof: %v", n, i, err)
		}
		if len(path) != len(wantPath) {
			t.Fatalf("size=%d idx=%d: path length drift", n, i)
		}
		for j := range path {
			if !bytes.Equal(path[j], wantPath[j]) {
				t.Fatalf("size=%d idx=%d: path[%d] drift", n, i, j)
			}
		}
		if err := translog.VerifyInclusion(leaves[i], i, n, path, finalRoot); err != nil {
			t.Fatalf("size=%d idx=%d: verify: %v", n, i, err)
		}
	}
	for _, oldSize := range []uint64{1, 2, 3, 99, 500, 999} {
		oldRoot := sths[oldSize-1].Head.RootHash
		proof, err := s.ConsistencyProofFor(ctx, cid, oldSize, n)
		if err != nil {
			t.Fatalf("(%d,%d): %v", oldSize, n, err)
		}
		// Cross-validation: storage-layer consistency proof equals pure.
		wantProof, err := translog.BuildConsistencyProof(leaves, oldSize, n)
		if err != nil {
			t.Fatalf("(%d,%d): pure proof: %v", oldSize, n, err)
		}
		if len(proof) != len(wantProof) {
			t.Fatalf("(%d,%d): proof length drift", oldSize, n)
		}
		for j := range proof {
			if !bytes.Equal(proof[j], wantProof[j]) {
				t.Fatalf("(%d,%d): proof[%d] drift", oldSize, n, j)
			}
		}
		if err := translog.VerifyConsistency(oldSize, n, proof, oldRoot, finalRoot); err != nil {
			t.Fatalf("(%d,%d): verify: %v", oldSize, n, err)
		}
	}
}

// TestAppendWithTranslogAtomic is the regression for codex's P0 finding:
// the production path bundles event append + translog leaf append in
// ONE transaction. If the event side fails (e.g., divergence) the
// translog must NOT see the leaf — otherwise the next AppendWithTranslog
// would index the actual next event one slot too high, with the original
// "phantom" leaf permanently shadowing it.
func TestAppendWithTranslogAtomic(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const cid = "scope:s_atomic"

	// Genesis event lands cleanly via AppendWithTranslog.
	gen := AppendOpts{
		ChainID:     cid,
		Seq:         0,
		Genesis:     true,
		NewTipHash:  bytes.Repeat([]byte{0x01}, 32),
		NewMetadata: nil,
		Event: Event{
			ChainID:  cid,
			Seq:      0,
			EventID:  "e_atomic_genesis",
			PrevHash: nil,
			Kind:     "member.change",
			CBOR:     []byte("genesis-cbor"),
		},
	}
	sth, err := s.AppendWithTranslog(ctx, gen, fakeEventHash(0), 1700000000)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	if sth.Head.TreeSize != 1 {
		t.Fatalf("genesis size: got %d want 1", sth.Head.TreeSize)
	}

	// Now try to append a successor with WRONG prev_hash → must fail
	// with ErrDivergence AND must not advance the translog.
	bad := AppendOpts{
		ChainID:    cid,
		Seq:        1,
		NewTipHash: bytes.Repeat([]byte{0x02}, 32),
		Event: Event{
			ChainID:  cid,
			Seq:      1,
			EventID:  "e_atomic_bad",
			PrevHash: bytes.Repeat([]byte{0xFF}, 32), // wrong
			Kind:     "secret.set",
			CBOR:     []byte("bad-cbor"),
		},
	}
	_, err = s.AppendWithTranslog(ctx, bad, fakeEventHash(1), 1700000001)
	if !errors.Is(err, ErrDivergence) {
		t.Fatalf("bad append: want ErrDivergence got %v", err)
	}
	// Tree must STILL be size 1; if the leaf had landed despite the
	// event-side rollback we'd see size 2 here.
	cur, err := s.CurrentSTH(ctx, cid)
	if err != nil {
		t.Fatalf("CurrentSTH after failed bad: %v", err)
	}
	if cur.Head.TreeSize != 1 {
		t.Fatalf("translog leaked across rollback: tree_size=%d, want 1", cur.Head.TreeSize)
	}

	// Now append a CORRECT successor; tree must reach size 2 with the
	// real event_hash, not whatever fakeEventHash(1) was.
	ok := AppendOpts{
		ChainID:    cid,
		Seq:        1,
		NewTipHash: bytes.Repeat([]byte{0x03}, 32),
		Event: Event{
			ChainID:  cid,
			Seq:      1,
			EventID:  "e_atomic_ok",
			PrevHash: bytes.Repeat([]byte{0x01}, 32), // matches genesis tip
			Kind:     "secret.set",
			CBOR:     []byte("ok-cbor"),
		},
	}
	sth2, err := s.AppendWithTranslog(ctx, ok, fakeEventHash(99), 1700000002)
	if err != nil {
		t.Fatalf("ok append: %v", err)
	}
	if sth2.Head.TreeSize != 2 {
		t.Fatalf("ok size: got %d want 2", sth2.Head.TreeSize)
	}
}

// TestSignServerInfo covers the C3-prep hook: HTTP layer never holds
// the priv key, only asks the Store to mint a self-signed publication
// record. Fails cleanly if no key is installed.
func TestSignServerInfo(t *testing.T) {
	s, pub := newTestStore(t)
	info, err := s.SignServerInfo(1700000000)
	if err != nil {
		t.Fatalf("SignServerInfo: %v", err)
	}
	if !bytes.Equal(info.ServerPub, pub) {
		t.Fatal("SignServerInfo embedded wrong pubkey")
	}
	if err := translog.VerifyServerInfo(info); err != nil {
		t.Fatalf("VerifyServerInfo: %v", err)
	}

	// Without a key, must error.
	tmp := filepath.Join(t.TempDir(), "nokey.db")
	s2, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.SignServerInfo(1700000000); !errors.Is(err, ErrTranslogKeyMissing) {
		t.Fatalf("expected ErrTranslogKeyMissing, got %v", err)
	}
}

// TestSetTranslogKeyCopies verifies that SetTranslogKey defensively
// copies the supplied slices — caller mutating their priv buffer
// after install must NOT corrupt the Store's signing key.
func TestSetTranslogKeyCopies(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "copy.db")
	s, err := Open(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetTranslogKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	// Mutate the caller's buffer.
	for i := range priv {
		priv[i] = 0xFF
	}
	for i := range pub {
		pub[i] = 0xFF
	}
	// Sign something and verify with the originally-derived pub on the
	// store (we can't get it back here easily, so use SignServerInfo
	// → embedded pub → verify chain).
	info, err := s.SignServerInfo(1)
	if err != nil {
		t.Fatalf("post-mutation sign failed (key wasn't copied): %v", err)
	}
	if err := translog.VerifyServerInfo(info); err != nil {
		t.Fatalf("post-mutation verify failed (key wasn't copied): %v", err)
	}
}

// TestLoadOrCreateTranslogKey covers the 5×2 startup matrix.
func TestLoadOrCreateTranslogKey(t *testing.T) {
	ctx := context.Background()

	t.Run("fresh boot generates and persists", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "fresh.db")
		keyPath := filepath.Join(dir, "key")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		var warnSeen string
		priv, pub, err := LoadOrCreateTranslogKey(ctx, s, keyPath, func(m string) { warnSeen = m })
		if err != nil {
			t.Fatalf("fresh boot: %v", err)
		}
		if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
			t.Fatal("returned keys have wrong length")
		}
		// Keyfile must exist with mode 0600.
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("keyfile not written: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("keyfile mode: got %o want 0600", info.Mode().Perm())
		}
		// DB must have the cached pub.
		dbPub, has, err := loadDBPub(ctx, s)
		if err != nil || !has || !bytes.Equal(dbPub, pub) {
			t.Fatalf("DB persistence broken: has=%v err=%v", has, err)
		}
		if warnSeen == "" {
			t.Fatal("WARN log expected on fresh generation")
		}
	})

	t.Run("warm boot loads from file and matches DB", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "warm.db")
		keyPath := filepath.Join(dir, "key")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		// First boot: generate.
		priv1, pub1, err := LoadOrCreateTranslogKey(ctx, s, keyPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()

		// Reopen DB; second boot must match.
		s2, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s2.Close()
		priv2, pub2, err := LoadOrCreateTranslogKey(ctx, s2, keyPath, nil)
		if err != nil {
			t.Fatalf("warm boot: %v", err)
		}
		if !bytes.Equal(priv1, priv2) || !bytes.Equal(pub1, pub2) {
			t.Fatal("warm-boot keys must match first-boot keys")
		}
	})

	t.Run("keyfile mismatch is FATAL", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "mm.db")
		keyPath := filepath.Join(dir, "key")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		// First boot: generate key A.
		_, _, err = LoadOrCreateTranslogKey(ctx, s, keyPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()

		// Replace the keyfile with key B.
		_, privB, _ := ed25519.GenerateKey(rand.Reader)
		if err := writeKeyFileAtomic(keyPath, privB); err != nil {
			t.Fatal(err)
		}

		// Reopen DB: must FATAL.
		s2, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s2.Close()
		_, _, err = LoadOrCreateTranslogKey(ctx, s2, keyPath, nil)
		if err == nil {
			t.Fatal("keyfile/DB mismatch must be fatal")
		}
	})

	t.Run("missing keyfile with cached DB pub is FATAL", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "miss.db")
		keyPath := filepath.Join(dir, "key")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		// First boot generates the keyfile and persists pub.
		_, _, err = LoadOrCreateTranslogKey(ctx, s, keyPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()

		// Operator deletes the keyfile (lost key).
		if err := os.Remove(keyPath); err != nil {
			t.Fatal(err)
		}

		// Reopen: DB still has the old pub; loading must FATAL.
		s2, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s2.Close()
		_, _, err = LoadOrCreateTranslogKey(ctx, s2, keyPath, nil)
		if err == nil {
			t.Fatal("missing keyfile with cached pub must be fatal")
		}
	})

	t.Run("operator-supplied keyfile, empty DB persists pub", func(t *testing.T) {
		// Operator-provisioned deployment: drop a 64-byte keyfile in
		// place BEFORE first server boot. The startup matrix expects
		// "yes/no" → load keyfile, derive pub, persist to DB.
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "operator.db")
		keyPath := filepath.Join(dir, "key")
		_, opPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, opPriv, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		var warnSeen string
		_, pub, err := LoadOrCreateTranslogKey(ctx, s, keyPath, func(m string) { warnSeen = m })
		if err != nil {
			t.Fatalf("operator boot: %v", err)
		}
		if warnSeen != "" {
			t.Fatal("WARN log must NOT fire on operator-supplied key")
		}
		// DB must now have the pub cached.
		dbPub, has, err := loadDBPub(ctx, s)
		if err != nil || !has || !bytes.Equal(dbPub, pub) {
			t.Fatalf("operator path: DB persistence broken: has=%v err=%v", has, err)
		}
	})

	t.Run("inconsistent seed||pub keyfile is FATAL", func(t *testing.T) {
		// Codex flag: an operator (or attacker) writes a 64-byte key
		// where the appended pub does NOT match what the seed
		// derives. Go's ed25519 Sign uses the seed; Verify uses the
		// pub. They'd disagree silently. Refuse to start.
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "inc.db")
		keyPath := filepath.Join(dir, "key")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()

		_, privA, _ := ed25519.GenerateKey(rand.Reader)
		_, privB, _ := ed25519.GenerateKey(rand.Reader)
		// Splice: seed of A, pub of B → 64 bytes but inconsistent.
		bad := make([]byte, ed25519.PrivateKeySize)
		copy(bad[:32], privA[:32])         // seed of A
		copy(bad[32:], privB[32:])         // pub of B
		if err := os.WriteFile(keyPath, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err = LoadOrCreateTranslogKey(ctx, s, keyPath, nil)
		if err == nil {
			t.Fatal("inconsistent seed||pub must be rejected")
		}
	})

	t.Run("malformed keyfile is FATAL", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "mal.db")
		keyPath := filepath.Join(dir, "key")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		// Write garbage bytes (wrong length).
		if err := os.WriteFile(keyPath, []byte("not-a-key"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err = LoadOrCreateTranslogKey(ctx, s, keyPath, nil)
		if err == nil {
			t.Fatal("malformed keyfile must be fatal")
		}
	})

	t.Run("empty path is rejected", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "empty.db")
		s, err := Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if _, _, err := LoadOrCreateTranslogKey(ctx, s, "", nil); err == nil {
			t.Fatal("empty path must be rejected")
		}
	})
}
