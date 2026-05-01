package translog

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// FuzzInclusion exercises the prover/verifier pair across pseudo-random
// (size, index, bit-flip) triples. The fuzzer drives:
//
//   - VALID: a freshly generated proof must verify.
//   - INVALID: any single-bit flip in the path, the leaf, the root, or
//     the index/size envelope must cause the verifier to reject.
//
// Run with: go test ./internal/translog/ -fuzz=FuzzInclusion -fuzztime=30s
//
// Without `-fuzz`, this seeds the corpus and exercises a deterministic
// subset, so the test stays cheap in CI and the regression coverage is
// permanent.
func FuzzInclusion(f *testing.F) {
	// Seed: small, hand-picked triples that hit the awkward shapes.
	f.Add(uint16(1), uint16(0), uint8(0))
	f.Add(uint16(2), uint16(1), uint8(0))
	f.Add(uint16(3), uint16(0), uint8(0))
	f.Add(uint16(3), uint16(2), uint8(0))
	f.Add(uint16(7), uint16(3), uint8(7))
	f.Add(uint16(8), uint16(5), uint8(13))
	f.Add(uint16(64), uint16(31), uint8(42))
	f.Add(uint16(255), uint16(199), uint8(99))

	f.Fuzz(func(t *testing.T, sizeRaw, indexRaw uint16, tamperRaw uint8) {
		// Bound size to a tractable range so the fuzz loop is fast.
		size := uint64(sizeRaw)%512 + 1
		index := uint64(indexRaw) % size

		leaves := makeLeaves(size)
		root := MerkleTreeHash(leaves)
		proof, err := BuildInclusionProof(leaves, index, size)
		if err != nil {
			t.Fatalf("size=%d idx=%d: build: %v", size, index, err)
		}

		// Positive: must verify.
		if err := VerifyInclusion(leaves[index], index, size, proof, root); err != nil {
			t.Fatalf("size=%d idx=%d: positive verify: %v", size, index, err)
		}

		// Negative: choose a tamper target by tamperRaw mod 4. We always
		// flip a single byte, so the modification is minimal.
		//
		// We do NOT test "wrong size with same root" — RFC 6962 verifiers
		// cannot reject that on their own (the server's signed STH binds
		// size↔root; the verifier only checks "leaf at index in SOME tree
		// of this shape"). That binding is enforced separately by
		// ValidateTreeHead + signature verification.
		switch tamperRaw % 4 {
		case 0:
			// Tamper leaf.
			bad := flipFirstByte(leaves[index])
			if err := VerifyInclusion(bad, index, size, proof, root); err == nil {
				t.Fatalf("size=%d idx=%d: tampered leaf must fail", size, index)
			}
		case 1:
			// Tamper root.
			bad := flipFirstByte(root)
			if err := VerifyInclusion(leaves[index], index, size, proof, bad); err == nil {
				t.Fatalf("size=%d idx=%d: tampered root must fail", size, index)
			}
		case 2:
			// Tamper a path element (if path is non-empty).
			if len(proof) == 0 {
				return
			}
			bad := make([][]byte, len(proof))
			copy(bad, proof)
			whichRaw := uint64(tamperRaw)
			which := whichRaw % uint64(len(proof))
			bad[which] = flipFirstByte(proof[which])
			if err := VerifyInclusion(leaves[index], index, size, bad, root); err == nil {
				t.Fatalf("size=%d idx=%d: tampered path[%d] must fail", size, index, which)
			}
		case 3:
			// Truncate proof — must reject (the sn==0 check catches it).
			if len(proof) == 0 {
				return
			}
			short := proof[:len(proof)-1]
			if err := VerifyInclusion(leaves[index], index, size, short, root); err == nil {
				t.Fatalf("size=%d idx=%d: truncated proof must fail", size, index)
			}
		}
	})
}

// FuzzConsistency drives prover/verifier across pseudo-random
// (oldSize, newSize, tamper) triples. Same shape as FuzzInclusion.
func FuzzConsistency(f *testing.F) {
	f.Add(uint16(0), uint16(1), uint8(0))
	f.Add(uint16(1), uint16(2), uint8(0))
	f.Add(uint16(1), uint16(3), uint8(0))
	f.Add(uint16(3), uint16(8), uint8(7))
	f.Add(uint16(7), uint16(13), uint8(42))
	f.Add(uint16(64), uint16(128), uint8(99))
	f.Add(uint16(255), uint16(256), uint8(13))

	f.Fuzz(func(t *testing.T, oldRaw, newRaw uint16, tamperRaw uint8) {
		newSize := uint64(newRaw)%512 + 1
		oldSize := uint64(oldRaw) % (newSize + 1) // 0 ≤ old ≤ new

		leaves := makeLeaves(newSize)
		oldRoot := MerkleTreeHash(leaves[:oldSize])
		newRoot := MerkleTreeHash(leaves[:newSize])
		proof, err := BuildConsistencyProof(leaves, oldSize, newSize)
		if err != nil {
			t.Fatalf("(%d,%d): build: %v", oldSize, newSize, err)
		}

		// Positive.
		if err := VerifyConsistency(oldSize, newSize, proof, oldRoot, newRoot); err != nil {
			t.Fatalf("(%d,%d): positive verify: %v", oldSize, newSize, err)
		}

		switch tamperRaw % 5 {
		case 0:
			// Tamper oldRoot. Skipped at oldSize=0 because the verifier
			// short-circuits there (empty old tree, no oldRoot
			// reconstruction to check).
			if oldSize == 0 {
				return
			}
			bad := flipFirstByte(oldRoot)
			if err := VerifyConsistency(oldSize, newSize, proof, bad, newRoot); err == nil {
				t.Fatalf("(%d,%d): tampered oldRoot must fail", oldSize, newSize)
			}
		case 1:
			// Tamper newRoot. Skipped at oldSize=0 — RFC 6962 says any
			// tree is consistent with the empty tree, so there is no
			// proof and no newRoot reconstruction. The size↔root binding
			// for the new head is enforced separately via
			// ValidateTreeHead + STH signature, not via consistency.
			if oldSize == 0 {
				return
			}
			bad := flipFirstByte(newRoot)
			if err := VerifyConsistency(oldSize, newSize, proof, oldRoot, bad); err == nil {
				t.Fatalf("(%d,%d): tampered newRoot must fail", oldSize, newSize)
			}
		case 2:
			if len(proof) == 0 {
				return
			}
			bad := make([][]byte, len(proof))
			copy(bad, proof)
			which := uint64(tamperRaw) % uint64(len(proof))
			bad[which] = flipFirstByte(proof[which])
			if err := VerifyConsistency(oldSize, newSize, bad, oldRoot, newRoot); err == nil {
				t.Fatalf("(%d,%d): tampered proof[%d] must fail", oldSize, newSize, which)
			}
		case 3:
			// Truncate proof.
			if len(proof) == 0 {
				return
			}
			short := proof[:len(proof)-1]
			if err := VerifyConsistency(oldSize, newSize, short, oldRoot, newRoot); err == nil {
				t.Fatalf("(%d,%d): truncated proof must fail", oldSize, newSize)
			}
		case 4:
			// Extra element.
			extra := append(append([][]byte(nil), proof...), fixedHash(0xEE))
			if err := VerifyConsistency(oldSize, newSize, extra, oldRoot, newRoot); err == nil {
				t.Fatalf("(%d,%d): extra-element proof must fail", oldSize, newSize)
			}
		}
	})
}

// makeLeaves builds n distinct LeafHash values from sequential 8-byte
// little-endian counters. Distinct counters → distinct leaf inputs →
// distinct (with overwhelming probability) leaf hashes.
func makeLeaves(n uint64) [][]byte {
	out := make([][]byte, n)
	for i := uint64(0); i < n; i++ {
		var buf [HashSize]byte
		binary.LittleEndian.PutUint64(buf[:], i+1)
		// Hash the counter once to fill all 32 bytes — we want
		// distinguishable inputs, not a structured pattern.
		h := sha256.Sum256(buf[:])
		out[i] = LeafHash(h[:])
	}
	return out
}

// flipFirstByte returns a copy of `in` with the first byte's low bit
// toggled — minimal, deterministic mutation.
func flipFirstByte(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	if len(out) > 0 {
		out[0] ^= 0x01
	}
	return out
}
