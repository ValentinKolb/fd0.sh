// Inclusion and consistency proofs per RFC 6962 §2.1.1 and §2.1.2.
//
// All four functions here (compute and verify, for both proof kinds)
// share two split-rule invariants:
//
//  1. The tree of n > 1 leaves splits at k = largestPowerOfTwoLessThan(n);
//     the left subtree holds k leaves, the right subtree holds n-k.
//  2. A leaf at index i with i < k lives in the left subtree; otherwise
//     in the right subtree (with index i-k).
//
// These rules drive the path construction recursively; the verifier is
// the same recursion run in reverse to reconstruct the root.

package translog

// InclusionProof returns the audit path for the leaf at `index` in a
// tree of `size` leaves, given the full leaf-hash list. Each element of
// the returned slice is one sibling hash, in leaf-to-root order.
//
// Returns ErrIndexOutOfRange if index ≥ size or size > len(leaves).
//
// O(log size) hashes returned; O(size) total work — used by tests and by
// the storage layer's full-tree fallback path. The hot server path
// computes proofs incrementally from cached subtree hashes.
func BuildInclusionProof(leaves [][]byte, index, size uint64) ([][]byte, error) {
	if index >= size || size > uint64(len(leaves)) {
		return nil, ErrIndexOutOfRange
	}
	return inclusionPath(leaves[:size], index), nil
}

func inclusionPath(leaves [][]byte, index uint64) [][]byte {
	n := uint64(len(leaves))
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if index < k {
		// Target is in left subtree; sibling is the right subtree's root.
		sub := inclusionPath(leaves[:k], index)
		return append(sub, MerkleTreeHash(leaves[k:]))
	}
	// Target is in right subtree; sibling is the left subtree's root.
	sub := inclusionPath(leaves[k:], index-k)
	return append(sub, MerkleTreeHash(leaves[:k]))
}

// VerifyInclusion checks that `leafHash` is the leaf at `index` in a tree
// of `size` leaves whose root is `root`, given the leaf-to-root sibling
// path `path`. Returns nil on success, ErrInclusionProofInvalid otherwise.
//
// Implements the RFC 6962 §2.1.1.2 verifier verbatim — track (fn, sn)
// where fn is the leaf index and sn = size-1, both shifted right at each
// path step. Two cases per level: either current node is a "right child
// or rightmost lone child" (combine sibling-on-left), or it is a
// strictly-left child with a right sibling (combine sibling-on-right).
// The "lone child climbs up unchanged" path covers RFC 6962 trees where
// the rightmost subtree is incomplete (e.g., size=3 has L2 alone at
// the rightmost position, promoted past one level without a sibling).
func VerifyInclusion(leafHash []byte, index, size uint64, path [][]byte, root []byte) error {
	if size > maxTreeSize {
		return ErrInclusionProofInvalid
	}
	if index >= size || len(leafHash) != HashSize || len(root) != HashSize {
		return ErrInclusionProofInvalid
	}
	for _, sib := range path {
		if len(sib) != HashSize {
			return ErrInclusionProofInvalid
		}
	}
	fn, sn := index, size-1
	r := append([]byte(nil), leafHash...)
	for _, p := range path {
		// RFC 9162 §2.1.4.2 step 2: fail before consuming any element
		// once we've already walked to the top. Catches over-long
		// proofs structurally rather than via root mismatch — the
		// difference is observability, not correctness, but a clearer
		// error surfaces refactor drift faster.
		if sn == 0 {
			return ErrInclusionProofInvalid
		}
		if fn == sn || (fn&1) == 1 {
			// Current node is a right child (fn odd) or the rightmost
			// lone child (fn == sn). Sibling is on the left.
			r = NodeHash(p, r)
			// "Climb past" any subsequent lone-child levels — we're
			// effectively the left child of a higher ancestor.
			if (fn & 1) == 0 {
				for (fn&1) == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			// Strictly-left child with a right sibling.
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	// CRITICAL: final check is `sn == 0`, not `fn == 0`. A short proof
	// against a forged root (e.g., size=3, index=0, empty path, root=leaf0)
	// would otherwise pass — fn happens to be 0 from the start at index=0,
	// but sn carries the height-information we needed to fully consume.
	// Server is adversarial and chooses (size, root); the verifier must
	// not assume root is canonical for size.
	if sn != 0 || !equalHash(r, root) {
		return ErrInclusionProofInvalid
	}
	return nil
}

// ConsistencyProof returns the proof that a tree of `oldSize` leaves is
// a strict prefix of a tree of `newSize` leaves, given the full leaf
// list of the new tree. Per RFC 6962 §2.1.2.
//
// Special cases:
//   - oldSize == 0: any tree is consistent with the empty tree; returns
//     an empty proof. Verifier still validates the new root matches.
//   - oldSize == newSize: the trees are equal; returns an empty proof.
//   - oldSize > newSize or newSize > len(leaves): ErrIndexOutOfRange.
func BuildConsistencyProof(leaves [][]byte, oldSize, newSize uint64) ([][]byte, error) {
	if oldSize > newSize || newSize > uint64(len(leaves)) {
		return nil, ErrIndexOutOfRange
	}
	if oldSize == 0 || oldSize == newSize {
		return nil, nil
	}
	return subproof(leaves[:newSize], oldSize, true), nil
}

// subproof is the RFC 6962 §2.1.2 SUBPROOF recursion. The `b` flag
// distinguishes the initial call (b=true: the old root is at the boundary
// of the old tree, no need to include it) from recursive calls (b=false:
// the boundary moves into a subtree, so the subtree's root may need to
// be added to the proof).
func subproof(leaves [][]byte, m uint64, b bool) [][]byte {
	n := uint64(len(leaves))
	if m == n {
		if b {
			return nil
		}
		return [][]byte{MerkleTreeHash(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		// The old tree is entirely in the left subtree. Recurse left;
		// append the right subtree's full root as the consistency
		// witness for the new portion.
		sub := subproof(leaves[:k], m, b)
		return append(sub, MerkleTreeHash(leaves[k:]))
	}
	// The old tree spans into the right subtree. Recurse right with
	// m-k as the new boundary; prepend the left subtree's full root
	// (which is unchanged in both old and new trees).
	sub := subproof(leaves[k:], m-k, false)
	return append(sub, MerkleTreeHash(leaves[:k]))
}

// VerifyConsistency checks that a server claiming to have grown its tree
// from (oldRoot at oldSize) to (newRoot at newSize) is telling a
// consistent story. Implements RFC 6962 §2.1.2.2 verbatim.
//
// Special-case shortcuts mirror the prover:
//   - oldSize > newSize: tree-size regression; ErrSizeRegression.
//   - oldSize == 0: trivially consistent against EMPTY old root only;
//     empty proof required. A non-EmptyRoot oldRoot at size=0 is a
//     malformed STH and we refuse it here so callers don't have to
//     repeat the check.
//   - oldSize == newSize: requires oldRoot == newRoot and an empty
//     proof.
//   - newSize == 0 with oldSize == 0: empty/empty case, fall through.
//
// Algorithm: iterate over every proof element, tracking (fr, sr) =
// (old subtree hash, new subtree hash) and (fn, sn) = (old boundary
// index, new top index). Final check `sn == 0` enforces that the proof
// length matched the tree height — short proofs against forged STHs
// (e.g., oldSize=1 newSize=2 empty proof oldRoot==newRoot) would
// otherwise pass.
func VerifyConsistency(oldSize, newSize uint64, proof [][]byte, oldRoot, newRoot []byte) error {
	if oldSize > newSize {
		return ErrSizeRegression
	}
	if newSize > maxTreeSize {
		return ErrConsistencyProofInvalid
	}
	if len(oldRoot) != HashSize || len(newRoot) != HashSize {
		return ErrConsistencyProofInvalid
	}
	// Bind size=0 to the canonical empty root. Without this a server
	// could sign (size=0, root=anything) and the verifier would accept.
	emptyR := EmptyRoot()
	if oldSize == 0 {
		if !equalHash(oldRoot, emptyR) {
			return ErrConsistencyProofInvalid
		}
		if len(proof) != 0 {
			return ErrConsistencyProofInvalid
		}
		// At oldSize=0 the only constraint we CAN enforce on the new
		// head is the size↔root binding. (Consistency itself is moot —
		// the empty tree is a prefix of every tree, with or without
		// reproducible root.)
		if newSize == 0 && !equalHash(newRoot, emptyR) {
			return ErrConsistencyProofInvalid
		}
		if newSize > 0 && equalHash(newRoot, emptyR) {
			return ErrConsistencyProofInvalid
		}
		return nil
	}
	if oldSize == newSize {
		if len(proof) != 0 || !equalHash(oldRoot, newRoot) {
			return ErrConsistencyProofInvalid
		}
		return nil
	}
	for _, h := range proof {
		if len(h) != HashSize {
			return ErrConsistencyProofInvalid
		}
	}

	// RFC 6962 §2.1.2.2 step 1: if oldSize is an exact power of two,
	// the prover would not include oldRoot in the proof (it equals the
	// first reconstruction hash anyway). Prepend it for uniform loop
	// processing below.
	work := proof
	if isPowerOfTwo(oldSize) {
		work = append([][]byte{oldRoot}, proof...)
	}
	if len(work) == 0 {
		return ErrConsistencyProofInvalid
	}

	fn, sn := oldSize-1, newSize-1
	// Step 2: shift past clean right-edge levels — at those levels the
	// boundary node IS its subtree's root, no sibling needed.
	for (fn & 1) == 1 {
		fn >>= 1
		sn >>= 1
	}

	fr := append([]byte(nil), work[0]...)
	sr := append([]byte(nil), work[0]...)
	for _, p := range work[1:] {
		// RFC 9162 §2.1.4.2 structural early-fail: refuse over-long
		// proofs explicitly rather than relying on root-mismatch at
		// the end. Same correctness, clearer error path.
		if sn == 0 {
			return ErrConsistencyProofInvalid
		}
		if (fn & 1) == 1 || fn == sn {
			// Boundary is on the right side of its parent (or the
			// rightmost lone child). Sibling p is on the left; both
			// subtrees take the same step (left subtree is fully
			// shared up to this boundary level).
			fr = NodeHash(p, fr)
			sr = NodeHash(p, sr)
			// "Climb past" any subsequent lone-child levels — both
			// hashes become the left child of a higher ancestor with
			// no sibling consumed.
			for (fn&1) == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			// Boundary is on the left side; only the new tree extends
			// to the right. Old hash unchanged.
			sr = NodeHash(sr, p)
		}
		fn >>= 1
		sn >>= 1
	}
	// CRITICAL final check: sn == 0 ensures we consumed exactly enough
	// proof elements to walk to the new tree's root. A short proof would
	// leave sn > 0 — exactly the malformed-STH attack we have to reject.
	if sn != 0 || !equalHash(fr, oldRoot) || !equalHash(sr, newRoot) {
		return ErrConsistencyProofInvalid
	}
	return nil
}

// isPowerOfTwo returns true iff n is a positive power of two.
func isPowerOfTwo(n uint64) bool { return n > 0 && (n&(n-1)) == 0 }

// equalHash is a constant-time-ish equality. Hashes here are public, so
// constant time is not strictly required, but using a single helper
// avoids a bytes.Equal vs. hand-rolled-loop inconsistency.
func equalHash(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
