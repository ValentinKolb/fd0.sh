package translog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// fixedHash is a 32-byte hash built from a one-byte tag — used to build
// distinguishable leaf inputs in tests without allocating real events.
func fixedHash(tag byte) []byte {
	out := make([]byte, HashSize)
	for i := range out {
		out[i] = tag
	}
	return out
}

func leafHashes(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = LeafHash(fixedHash(byte(i + 1)))
	}
	return out
}

// TestDomainSeparation locks down the invariant that LeafHash, NodeHash,
// and EmptyRoot produce pairwise distinct outputs even when given inputs
// that could otherwise collide. A regression here means a domain
// separator was reused or dropped — both are protocol breaks.
func TestDomainSeparation(t *testing.T) {
	zero := make([]byte, HashSize)
	leaf := LeafHash(zero)
	node := NodeHash(zero, zero)
	empty := EmptyRoot()
	if bytes.Equal(leaf, node) {
		t.Fatal("LeafHash and NodeHash collide on zero inputs")
	}
	if bytes.Equal(leaf, empty) {
		t.Fatal("LeafHash and EmptyRoot collide")
	}
	if bytes.Equal(node, empty) {
		t.Fatal("NodeHash and EmptyRoot collide")
	}
	// Domain string must literally appear inside the SHA-256 input —
	// guarded structurally by the constant lookup, but a test catches
	// a future "let's drop the prefix" refactor.
	for _, name := range []string{
		proto.DomainTranslogLeaf,
		proto.DomainTranslogNode,
		proto.DomainTranslogEmpty,
	} {
		if !strings.HasPrefix(name, "fd0-translog-") {
			t.Fatalf("translog domain %q must use the fd0-translog- prefix", name)
		}
	}
}

// TestEmptyRootStable pins the empty-tree root bytes. If the empty
// domain string ever changes, every existing client's first STH would
// no longer verify. This test is a structural alarm.
func TestEmptyRootStable(t *testing.T) {
	got := hex.EncodeToString(EmptyRoot())
	// Recompute manually: SHA-256("fd0-translog-empty-v1").
	want := "cdc74ad52ac8cd7dd9a8663e68f06cb4fbb6b6eae36490b52b03d102bb61285a"
	if got != want {
		t.Fatalf("empty root drift: got %s want %s — bumping the empty\n"+
			"domain breaks every persisted LastSTH at tree_size 0", got, want)
	}
}

// TestMerkleTreeHashSizes covers the recursive split rule for a few
// hand-checkable sizes. The expected roots are not magic constants —
// they are computed at test time from NodeHash composition, so the test
// validates the SHAPE more than the absolute bytes.
func TestMerkleTreeHashSizes(t *testing.T) {
	leaves := leafHashes(7)

	// Single leaf: root == leaf.
	if !bytes.Equal(MerkleTreeHash(leaves[:1]), leaves[0]) {
		t.Fatal("size-1 tree root must equal the lone leaf")
	}

	// Two leaves: root == NodeHash(L0, L1).
	want2 := NodeHash(leaves[0], leaves[1])
	if !bytes.Equal(MerkleTreeHash(leaves[:2]), want2) {
		t.Fatal("size-2 tree root mismatch")
	}

	// Three leaves: split at k=2 → NodeHash(NodeHash(L0,L1), L2).
	want3 := NodeHash(NodeHash(leaves[0], leaves[1]), leaves[2])
	if !bytes.Equal(MerkleTreeHash(leaves[:3]), want3) {
		t.Fatal("size-3 tree root mismatch (split at k=2)")
	}

	// Five leaves: k=4 → NodeHash(left4, L4).
	left4 := NodeHash(
		NodeHash(leaves[0], leaves[1]),
		NodeHash(leaves[2], leaves[3]),
	)
	want5 := NodeHash(left4, leaves[4])
	if !bytes.Equal(MerkleTreeHash(leaves[:5]), want5) {
		t.Fatal("size-5 tree root mismatch (split at k=4)")
	}

	// Seven leaves: k=4 → NodeHash(left4, right3) where right3 itself
	// splits at k=2. Pulls together every code path.
	right3 := NodeHash(NodeHash(leaves[4], leaves[5]), leaves[6])
	want7 := NodeHash(left4, right3)
	if !bytes.Equal(MerkleTreeHash(leaves[:7]), want7) {
		t.Fatal("size-7 tree root mismatch (recursive splits)")
	}

	// Empty.
	if !bytes.Equal(MerkleTreeHash(nil), EmptyRoot()) {
		t.Fatal("empty input must yield EmptyRoot()")
	}
}

// TestInclusionRoundTripExhaustive enumerates every (leaf, size) pair up
// to size 8 and verifies that the proof produced by InclusionProof is
// accepted by VerifyInclusion against the canonical root. If the path
// construction ever drifts from the verifier's split rule, this catches
// it for tiny trees where humans can also reason about it.
func TestInclusionRoundTripExhaustive(t *testing.T) {
	const maxSize = 8
	leaves := leafHashes(maxSize)
	for size := uint64(1); size <= maxSize; size++ {
		root := MerkleTreeHash(leaves[:size])
		for idx := uint64(0); idx < size; idx++ {
			path, err := BuildInclusionProof(leaves, idx, size)
			if err != nil {
				t.Fatalf("size=%d idx=%d: build proof: %v", size, idx, err)
			}
			if err := VerifyInclusion(leaves[idx], idx, size, path, root); err != nil {
				t.Fatalf("size=%d idx=%d: verify failed: %v", size, idx, err)
			}
		}
	}
}

// TestInclusionTamperRejection corrupts each component of a known-good
// inclusion proof and confirms VerifyInclusion rejects. Exhaustive over
// the components: leaf, every path element, root, index.
func TestInclusionTamperRejection(t *testing.T) {
	leaves := leafHashes(7)
	root := MerkleTreeHash(leaves)
	const idx = uint64(3)
	path, _ := BuildInclusionProof(leaves, idx, 7)

	// Baseline must verify.
	if err := VerifyInclusion(leaves[idx], idx, 7, path, root); err != nil {
		t.Fatalf("baseline verification failed: %v", err)
	}

	// Tamper with the leaf.
	tampered := append([]byte(nil), leaves[idx]...)
	tampered[0] ^= 0x01
	if err := VerifyInclusion(tampered, idx, 7, path, root); err == nil {
		t.Fatal("tampered leaf must fail")
	}

	// Tamper with each path element.
	for i := range path {
		bad := make([][]byte, len(path))
		copy(bad, path)
		bad[i] = append([]byte(nil), path[i]...)
		bad[i][0] ^= 0x01
		if err := VerifyInclusion(leaves[idx], idx, 7, bad, root); err == nil {
			t.Fatalf("tampered path[%d] must fail", i)
		}
	}

	// Tamper with the root.
	badRoot := append([]byte(nil), root...)
	badRoot[0] ^= 0x01
	if err := VerifyInclusion(leaves[idx], idx, 7, path, badRoot); err == nil {
		t.Fatal("tampered root must fail")
	}

	// Wrong index.
	if err := VerifyInclusion(leaves[idx], idx+1, 7, path, root); err == nil {
		t.Fatal("wrong index must fail")
	}

	// Index ≥ size.
	if err := VerifyInclusion(leaves[idx], 7, 7, path, root); err == nil {
		t.Fatal("index == size must fail")
	}
}

// TestConsistencyRoundTripExhaustive verifies every (oldSize, newSize)
// pair where 0 ≤ oldSize ≤ newSize ≤ 8 produces a proof that
// VerifyConsistency accepts.
func TestConsistencyRoundTripExhaustive(t *testing.T) {
	const maxSize = 8
	leaves := leafHashes(maxSize)
	for newSize := uint64(0); newSize <= maxSize; newSize++ {
		newRoot := MerkleTreeHash(leaves[:newSize])
		for oldSize := uint64(0); oldSize <= newSize; oldSize++ {
			oldRoot := MerkleTreeHash(leaves[:oldSize])
			proof, err := BuildConsistencyProof(leaves, oldSize, newSize)
			if err != nil {
				t.Fatalf("(%d,%d): build: %v", oldSize, newSize, err)
			}
			if err := VerifyConsistency(oldSize, newSize, proof, oldRoot, newRoot); err != nil {
				t.Fatalf("(%d,%d): verify: %v", oldSize, newSize, err)
			}
		}
	}
}

// TestConsistencyEmptyAndEqual covers the two short-circuit paths: any
// tree is consistent with the empty tree (no proof needed); a tree is
// consistent with itself (empty proof + matching roots).
func TestConsistencyEmptyAndEqual(t *testing.T) {
	leaves := leafHashes(5)
	root := MerkleTreeHash(leaves)

	// Empty old → any new.
	if err := VerifyConsistency(0, 5, nil, EmptyRoot(), root); err != nil {
		t.Fatal("empty old, non-empty new with empty proof must verify:", err)
	}

	// Equal sizes, equal roots → empty proof verifies.
	if err := VerifyConsistency(5, 5, nil, root, root); err != nil {
		t.Fatal("equal sizes with empty proof must verify:", err)
	}

	// Equal sizes, mismatched roots → fail.
	other := append([]byte(nil), root...)
	other[0] ^= 0x01
	if err := VerifyConsistency(5, 5, nil, other, root); err == nil {
		t.Fatal("equal sizes with mismatched roots must fail")
	}
}

// TestConsistencyRegressionRejected: a server that publishes an STH at
// tree_size A and later returns an STH at size B < A is committing
// equivocation. Reject before any proof verification.
func TestConsistencyRegressionRejected(t *testing.T) {
	leaves := leafHashes(7)
	rootBig := MerkleTreeHash(leaves[:7])
	rootSmall := MerkleTreeHash(leaves[:3])
	if err := VerifyConsistency(7, 3, nil, rootBig, rootSmall); err == nil {
		t.Fatal("oldSize > newSize must be rejected")
	}
}

// TestConsistencyTamperRejection corrupts each component of a valid
// consistency proof and confirms rejection.
func TestConsistencyTamperRejection(t *testing.T) {
	leaves := leafHashes(8)
	const oldSize, newSize = uint64(3), uint64(8)
	oldRoot := MerkleTreeHash(leaves[:oldSize])
	newRoot := MerkleTreeHash(leaves[:newSize])
	proof, _ := BuildConsistencyProof(leaves, oldSize, newSize)

	if err := VerifyConsistency(oldSize, newSize, proof, oldRoot, newRoot); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	// Tamper proof element.
	for i := range proof {
		bad := make([][]byte, len(proof))
		copy(bad, proof)
		bad[i] = append([]byte(nil), proof[i]...)
		bad[i][0] ^= 0x01
		if err := VerifyConsistency(oldSize, newSize, bad, oldRoot, newRoot); err == nil {
			t.Fatalf("tampered proof[%d] must fail", i)
		}
	}

	// Tamper old root.
	bad := append([]byte(nil), oldRoot...)
	bad[0] ^= 0x01
	if err := VerifyConsistency(oldSize, newSize, proof, bad, newRoot); err == nil {
		t.Fatal("tampered oldRoot must fail")
	}

	// Tamper new root.
	bad = append([]byte(nil), newRoot...)
	bad[0] ^= 0x01
	if err := VerifyConsistency(oldSize, newSize, proof, oldRoot, bad); err == nil {
		t.Fatal("tampered newRoot must fail")
	}
}

// TestVerifyInclusionShortProofForgedRoot is the regression for the
// HIGH bug codex flagged: at index=0 the leaf-index bit-walk reaches
// fn=0 immediately, so a `fn != 0` final check would let a server forge
// (size=N, root=leaf0) with an empty proof. Final check must be
// `sn != 0`. Catches any drift back to fn-only checking.
func TestVerifyInclusionShortProofForgedRoot(t *testing.T) {
	leaves := leafHashes(3)
	// Server signs (size=3, root=leaves[0]) and offers an empty proof
	// for leaf 0. A correct verifier sees that size=3 implies a
	// 2-element path is required and rejects.
	err := VerifyInclusion(leaves[0], 0, 3, nil, leaves[0])
	if err == nil {
		t.Fatal("size=3, index=0, empty path against forged root=leaf0 must be rejected")
	}
	// Companion: size=4 against root=leaf2 with empty path.
	leaves4 := leafHashes(4)
	if err := VerifyInclusion(leaves4[2], 2, 4, nil, leaves4[2]); err == nil {
		t.Fatal("size=4, index=2, empty path against root=leaf2 must be rejected")
	}
}

// TestVerifyConsistencyShortProofForgedRoot is the regression for the
// other HIGH codex bug: oldSize=1 newSize=2 with empty proof and
// oldRoot==newRoot must NOT verify. Catches drift back to the broken
// "consume rest" hack that bypassed the height-check.
func TestVerifyConsistencyShortProofForgedRoot(t *testing.T) {
	leaves := leafHashes(2)
	root1 := MerkleTreeHash(leaves[:1])
	// Server signs (oldSize=1, oldRoot=R) and (newSize=2, newRoot=R)
	// and offers an empty proof. Verifier must reject — newSize=2 needs
	// a 1-hash proof to walk to the new root.
	if err := VerifyConsistency(1, 2, nil, root1, root1); err == nil {
		t.Fatal("oldSize=1 newSize=2 empty proof oldRoot==newRoot must be rejected")
	}
	// Companion: oldSize=2 newSize=4 with empty proof must fail.
	root2 := MerkleTreeHash(leaves)
	if err := VerifyConsistency(2, 4, nil, root2, root2); err == nil {
		t.Fatal("oldSize=2 newSize=4 empty proof must be rejected")
	}
}

// TestVerifyConsistencyEmptySizeNonEmptyRoot binds tree_size=0 to
// EmptyRoot — a server signing (size=0, root=garbage) cannot pass.
func TestVerifyConsistencyEmptySizeNonEmptyRoot(t *testing.T) {
	bogus := fixedHash(0xCC)
	good := MerkleTreeHash(leafHashes(3))
	if err := VerifyConsistency(0, 3, nil, bogus, good); err == nil {
		t.Fatal("oldSize=0 with non-empty oldRoot must be rejected (size/root binding)")
	}
}

// TestVerifyConsistencyZeroToZero covers the (0,0) corner: oldRoot must
// be EmptyRoot, newRoot must be EmptyRoot, proof must be empty.
// Specifically: (0, 0, nil, EmptyRoot, garbage) used to slip through
// because the oldSize==0 short-circuit returned before evaluating the
// new head — codex caught it.
func TestVerifyConsistencyZeroToZero(t *testing.T) {
	emptyR := EmptyRoot()
	garbage := fixedHash(0xDD)
	if err := VerifyConsistency(0, 0, nil, emptyR, emptyR); err != nil {
		t.Fatalf("baseline (0,0,emptyR,emptyR) must verify: %v", err)
	}
	if err := VerifyConsistency(0, 0, nil, emptyR, garbage); err == nil {
		t.Fatal("(0,0) with non-empty newRoot must be rejected")
	}
	if err := VerifyConsistency(0, 0, nil, garbage, emptyR); err == nil {
		t.Fatal("(0,0) with non-empty oldRoot must be rejected")
	}
}

// TestVerifyConsistencyNonZeroNewSizeEmptyNewRoot covers the other
// arm of the size/root binding: at oldSize=0 the server still must not
// be able to sign (newSize > 0, newRoot = EmptyRoot()) and have us
// accept it. This case bypasses the main verifier loop entirely (we
// short-circuit at oldSize=0), so the binding has to be enforced
// inline in that branch.
func TestVerifyConsistencyNonZeroNewSizeEmptyNewRoot(t *testing.T) {
	emptyR := EmptyRoot()
	if err := VerifyConsistency(0, 5, nil, emptyR, emptyR); err == nil {
		t.Fatal("(0,5) with newRoot==EmptyRoot must be rejected — head is malformed")
	}
}

// TestValidateTreeHead covers the structural invariants the verifier
// enforces independent of the signature: size/root binding both
// directions, length, and the >2^63 ceiling.
func TestValidateTreeHead(t *testing.T) {
	emptyR := EmptyRoot()
	good := fixedHash(0xAB)

	cases := []struct {
		name string
		head TreeHead
		ok   bool
	}{
		{"empty tree", TreeHead{TreeSize: 0, RootHash: emptyR}, true},
		{"non-empty tree", TreeHead{TreeSize: 5, RootHash: good}, true},
		{"size=0 with non-empty root", TreeHead{TreeSize: 0, RootHash: good}, false},
		{"size=5 with empty root", TreeHead{TreeSize: 5, RootHash: emptyR}, false},
		{"short root", TreeHead{TreeSize: 5, RootHash: good[:31]}, false},
		{"oversized root", TreeHead{TreeSize: 5, RootHash: append(good, 0)}, false},
		{"size at max-allowed (2^63 - 1)", TreeHead{TreeSize: (1 << 63) - 1, RootHash: good}, true},
		{"size at limit (2^63)", TreeHead{TreeSize: 1 << 63, RootHash: good}, false},
		{"size at limit + 1", TreeHead{TreeSize: 1<<63 + 1, RootHash: good}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateTreeHead(c.head)
			if c.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

// TestVerifySTHRejectsMalformedHead confirms that VerifySTH bundles the
// structural checks — a server that signs an internally-inconsistent
// head (e.g., size=0 with non-empty root) should be rejected even with
// a valid signature.
func TestVerifySTHRejectsMalformedHead(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad := TreeHead{
		ChainID:   "scope:s_test",
		TreeSize:  0,
		RootHash:  fixedHash(0xDD), // size=0 but non-empty root: malformed
		Timestamp: 1,
	}
	sth, err := SignSTH(priv, bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySTH(pub, sth); err == nil {
		t.Fatal("VerifySTH must reject malformed head even with valid signature")
	}
}

// TestVerifyInclusionExtraElement: a forged proof with one extra
// element on top causes the recomputed root to differ — verifier
// rejects. Codex didn't flag this explicitly but it's the same family
// of attack as short-proof acceptance.
func TestVerifyInclusionExtraElement(t *testing.T) {
	leaves := leafHashes(4)
	root := MerkleTreeHash(leaves)
	path, _ := BuildInclusionProof(leaves, 1, 4)
	bad := append(append([][]byte(nil), path...), fixedHash(0xEE))
	if err := VerifyInclusion(leaves[1], 1, 4, bad, root); err == nil {
		t.Fatal("inclusion proof with extra element must be rejected")
	}
}

// TestVerifyInclusionPermutedPath: swap two adjacent path elements;
// recomputed root changes; verifier rejects. Defends against any
// canonicalisation regression where the prover and verifier silently
// agree on the wrong order.
func TestVerifyInclusionPermutedPath(t *testing.T) {
	leaves := leafHashes(8)
	root := MerkleTreeHash(leaves)
	path, _ := BuildInclusionProof(leaves, 3, 8) // length-3 path
	if len(path) < 2 {
		t.Skip("need a path with ≥ 2 elements to permute")
	}
	bad := make([][]byte, len(path))
	copy(bad, path)
	bad[0], bad[1] = bad[1], bad[0]
	if err := VerifyInclusion(leaves[3], 3, 8, bad, root); err == nil {
		t.Fatal("inclusion proof with permuted path must be rejected")
	}
}

// TestVerifyConsistencyExtraElement: extra element at the end of a
// valid consistency proof breaks the new-root reconstruction.
func TestVerifyConsistencyExtraElement(t *testing.T) {
	leaves := leafHashes(8)
	const oldSize, newSize = uint64(3), uint64(8)
	oldRoot := MerkleTreeHash(leaves[:oldSize])
	newRoot := MerkleTreeHash(leaves[:newSize])
	proof, _ := BuildConsistencyProof(leaves, oldSize, newSize)
	bad := append(append([][]byte(nil), proof...), fixedHash(0xEE))
	if err := VerifyConsistency(oldSize, newSize, bad, oldRoot, newRoot); err == nil {
		t.Fatal("consistency proof with extra element must be rejected")
	}
}

// TestVerifyConsistencyShortProofAtBoundary: at every (oldSize,newSize)
// pair where 1 ≤ oldSize < newSize ≤ 8, truncate the valid proof by one
// element and confirm rejection. Catches a regression where the verifier
// would silently terminate before exhausting the height.
func TestVerifyConsistencyShortProofAtBoundary(t *testing.T) {
	const maxSize = 8
	leaves := leafHashes(maxSize)
	for newSize := uint64(2); newSize <= maxSize; newSize++ {
		for oldSize := uint64(1); oldSize < newSize; oldSize++ {
			proof, _ := BuildConsistencyProof(leaves, oldSize, newSize)
			if len(proof) == 0 {
				continue
			}
			short := proof[:len(proof)-1]
			oldRoot := MerkleTreeHash(leaves[:oldSize])
			newRoot := MerkleTreeHash(leaves[:newSize])
			err := VerifyConsistency(oldSize, newSize, short, oldRoot, newRoot)
			if err == nil {
				t.Fatalf("(%d,%d): truncated proof must be rejected", oldSize, newSize)
			}
		}
	}
}

// TestVerifyInclusionShortProofAtBoundary: same family as above but for
// inclusion. Covers every (size, index) pair up to size=16, truncated
// by one element.
func TestVerifyInclusionShortProofAtBoundary(t *testing.T) {
	const maxSize = 16
	leaves := leafHashes(maxSize)
	for size := uint64(2); size <= maxSize; size++ {
		root := MerkleTreeHash(leaves[:size])
		for idx := uint64(0); idx < size; idx++ {
			proof, _ := BuildInclusionProof(leaves, idx, size)
			if len(proof) == 0 {
				continue
			}
			short := proof[:len(proof)-1]
			err := VerifyInclusion(leaves[idx], idx, size, short, root)
			if err == nil {
				t.Fatalf("size=%d idx=%d: truncated proof must be rejected", size, idx)
			}
		}
	}
}

// TestStressLargeTree exercises the prover and verifier against a
// 1000-leaf tree to catch any O(n²) blow-up or off-by-one that only
// surfaces past size=8. Verifies a representative spread of indices
// (every 73rd leaf — coprime with 1000 so we get good coverage).
func TestStressLargeTree(t *testing.T) {
	const n = 1000
	leaves := leafHashes(n)
	root := MerkleTreeHash(leaves)
	for i := uint64(0); i < n; i += 73 {
		path, err := BuildInclusionProof(leaves, i, n)
		if err != nil {
			t.Fatalf("size=%d idx=%d: build proof: %v", n, i, err)
		}
		if err := VerifyInclusion(leaves[i], i, n, path, root); err != nil {
			t.Fatalf("size=%d idx=%d: verify: %v", n, i, err)
		}
	}
	// And consistency against a few historical sizes.
	for _, oldSize := range []uint64{1, 2, 3, 99, 500, 999} {
		oldRoot := MerkleTreeHash(leaves[:oldSize])
		proof, err := BuildConsistencyProof(leaves, oldSize, n)
		if err != nil {
			t.Fatalf("(%d,%d): build: %v", oldSize, n, err)
		}
		if err := VerifyConsistency(oldSize, n, proof, oldRoot, root); err != nil {
			t.Fatalf("(%d,%d): verify: %v", oldSize, n, err)
		}
	}
}

// TestEquivocationDifferentSizes simulates the threat model in
// TRANSLOG.md §8.1 step 3: two STHs at different sizes whose histories
// are NOT prefix-related. A correct consistency proof must not exist;
// the verifier must reject any forged proof.
//
// Build two distinct trees that share NO leaves at all. Try to forge a
// consistency proof from one to the other; verifier rejects.
func TestEquivocationDifferentSizes(t *testing.T) {
	histA := leafHashes(5)                 // leaves tagged 1..5
	histB := make([][]byte, 6)             // leaves tagged 11..16 — disjoint
	for i := range histB {
		histB[i] = LeafHash(fixedHash(byte(i + 11)))
	}
	rootA := MerkleTreeHash(histA)
	rootB := MerkleTreeHash(histB)

	// A "proof" that uses histB to derive a path — the verifier does not
	// know either history; it only sees roots and proof bytes. The forged
	// proof will rebuild rootB but not rootA, so verification fails.
	forgedProof, _ := BuildConsistencyProof(histB, 5, 6) // pretend hist A is hist B[:5]
	err := VerifyConsistency(5, 6, forgedProof, rootA, rootB)
	if err == nil {
		t.Fatal("equivocation forging passed verification — verifier broken")
	}
}

// TestSTHSignVerify covers the basic signing flow and rejection of
// signatures by a different key.
func TestSTHSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	head := TreeHead{
		ChainID:   "scope:s_test",
		TreeSize:  42,
		RootHash:  fixedHash(0xAA),
		Timestamp: 1700000000,
	}
	sth, err := SignSTH(priv, head)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySTH(pub, sth); err != nil {
		t.Fatalf("good STH should verify: %v", err)
	}
	// Wrong pubkey must fail.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifySTH(otherPub, sth); err == nil {
		t.Fatal("STH must not verify under wrong pubkey")
	}
	// Tampered head must fail.
	tampered := sth
	tampered.Head.TreeSize++
	if err := VerifySTH(pub, tampered); err == nil {
		t.Fatal("tampered head must not verify")
	}
	// Tampered signature must fail.
	tampered = sth
	tampered.Signature = append([]byte(nil), sth.Signature...)
	tampered.Signature[0] ^= 0x01
	if err := VerifySTH(pub, tampered); err == nil {
		t.Fatal("tampered signature must not verify")
	}
}

// TestSTHSignedInputDomainPrefix locks down the structural property
// that the SignedInput starts with the STH domain string. Catches a
// future "drop the prefix" refactor.
func TestSTHSignedInputDomainPrefix(t *testing.T) {
	head := TreeHead{ChainID: "x", TreeSize: 0, RootHash: EmptyRoot(), Timestamp: 1}
	si, err := head.SignedInput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(si, []byte(proto.DomainTranslogSTH)) {
		t.Fatalf("STH SignedInput must start with %q", proto.DomainTranslogSTH)
	}
}

// TestServerInfoSignVerify covers the self-signed pubkey-publication
// record. Includes domain-mismatch rejection, which prevents replaying
// a STH signature blob as a server-info record (or vice-versa).
func TestServerInfoSignVerify(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	info, err := SignServerInfo(priv, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyServerInfo(info); err != nil {
		t.Fatalf("good ServerInfo should verify: %v", err)
	}
	// Wrong domain must fail.
	bad := info
	bad.Domain = "fd0-translog-sth-v1" // wrong domain — STH not server-info
	if err := VerifyServerInfo(bad); err == nil {
		t.Fatal("ServerInfo with wrong domain must not verify")
	}
	// Tampered pubkey must fail (signature was over the original).
	bad = info
	bad.ServerPub = append([]byte(nil), info.ServerPub...)
	bad.ServerPub[0] ^= 0x01
	if err := VerifyServerInfo(bad); err == nil {
		t.Fatal("ServerInfo with tampered pubkey must not verify")
	}
	// Tampered signature must fail.
	bad = info
	bad.Signature = append([]byte(nil), info.Signature...)
	bad.Signature[0] ^= 0x01
	if err := VerifyServerInfo(bad); err == nil {
		t.Fatal("ServerInfo with tampered signature must not verify")
	}
}

// TestLeafHashOfPrevInput verifies that the convenience wrapper composes
// SHA-256 with LeafHash correctly — i.e., LeafHashOfPrevInput(x) ==
// LeafHash(SHA-256(x)). A drift here would make server and client
// disagree on what hash anchors the leaf.
func TestLeafHashOfPrevInput(t *testing.T) {
	body := []byte("any canonical event body bytes")
	inner := sha256.Sum256(body)
	want := LeafHash(inner[:])
	got := LeafHashOfPrevInput(body)
	if !bytes.Equal(got, want) {
		t.Fatalf("LeafHashOfPrevInput composition drift: got %x want %x", got, want)
	}
}
