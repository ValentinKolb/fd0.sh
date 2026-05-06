package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"path/filepath"
	"testing"

	stded25519 "crypto/ed25519"
)

// bench_test.go — performance baselines for the server's translog.
// Run with `go test -bench=. -benchmem ./internal/server/store`.
//
// Goal: build a stable picture of how translog cost grows with
// chain depth — AppendLeaf is the inner loop on every push, and
// the storage backend is SQLite with an incremental Merkle tree.
// The questions:
//   - Is per-append cost flat or does it climb sub-linearly with N?
//   - At what N does the SQLite/index overhead dominate vs
//     constant crypto cost?
//   - Where does proof generation sit?
//
// We don't optimise during this pass — the point is "we know the
// numbers". A regression in a future commit shows up as a
// percentage delta.

// freshStore opens a SQLite store at a tempdir + installs a
// translog signing key. Keep allocations off the hot path.
func freshStore(b *testing.B) (*Store, stded25519.PublicKey) {
	b.Helper()
	tmp := filepath.Join(b.TempDir(), "bench.db")
	s, err := Open(tmp)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.Cleanup(func() { s.Close() })
	pub, priv, err := stded25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	if err := s.SetTranslogKey(priv, pub); err != nil {
		b.Fatal(err)
	}
	return s, pub
}

// hashedLeaf builds a unique 32-byte hash from i. Deterministic
// per index so the bench is reproducible across runs.
func hashedLeaf(i uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], i)
	h := sha256.Sum256(buf[:])
	return h[:]
}

// BenchmarkAppendLeafCold measures cost on a fresh chain (small N).
// This is the "first push to a new scope" path.
func BenchmarkAppendLeafCold(b *testing.B) {
	s, _ := freshStore(b)
	ctx := context.Background()
	const cid = "scope:s_bench_cold_aaaaaaaaaaaaaa"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.AppendLeaf(ctx, cid, hashedLeaf(uint64(i)), 1700000000); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAppendLeafWarmN measures steady-state cost at three
// chain depths. The setup adds N-1 leaves OUTSIDE the timed loop;
// the timer starts at the steady-state append.
func BenchmarkAppendLeafWarm1k(b *testing.B)   { benchAppendWarm(b, 1_000) }
func BenchmarkAppendLeafWarm10k(b *testing.B)  { benchAppendWarm(b, 10_000) }
func BenchmarkAppendLeafWarm100k(b *testing.B) { benchAppendWarm(b, 100_000) }

func benchAppendWarm(b *testing.B, preFill int) {
	s, _ := freshStore(b)
	ctx := context.Background()
	const cid = "scope:s_bench_warm_aaaaaaaaaaaaaa"
	for i := 0; i < preFill; i++ {
		if _, err := s.AppendLeaf(ctx, cid, hashedLeaf(uint64(i)), 1700000000); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.AppendLeaf(ctx, cid, hashedLeaf(uint64(preFill+i)), 1700000000); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkInclusionProofWarm measures how long it takes to
// reconstruct an inclusion proof at chain depth N. The path
// length is O(log N) but each step is a row lookup + SHA-256.
func BenchmarkInclusionProofWarm1k(b *testing.B)   { benchInclusionWarm(b, 1_000) }
func BenchmarkInclusionProofWarm10k(b *testing.B)  { benchInclusionWarm(b, 10_000) }
func BenchmarkInclusionProofWarm100k(b *testing.B) { benchInclusionWarm(b, 100_000) }

func benchInclusionWarm(b *testing.B, preFill int) {
	s, _ := freshStore(b)
	ctx := context.Background()
	const cid = "scope:s_bench_incl_aaaaaaaaaaaaaa"
	for i := 0; i < preFill; i++ {
		if _, err := s.AppendLeaf(ctx, cid, hashedLeaf(uint64(i)), 1700000000); err != nil {
			b.Fatal(err)
		}
	}
	size := uint64(preFill)
	target := size - 1 // most-recent leaf — typical pull-side query
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.InclusionProofFor(ctx, cid, target, size); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConsistencyProofWarm measures consistency-proof cost
// from oldSize to newSize. The path is the merge-set of old + new
// frontier nodes, so cost grows with O(log N).
func BenchmarkConsistencyProofWarm1k(b *testing.B)   { benchConsistencyWarm(b, 1_000) }
func BenchmarkConsistencyProofWarm10k(b *testing.B)  { benchConsistencyWarm(b, 10_000) }
func BenchmarkConsistencyProofWarm100k(b *testing.B) { benchConsistencyWarm(b, 100_000) }

func benchConsistencyWarm(b *testing.B, preFill int) {
	s, _ := freshStore(b)
	ctx := context.Background()
	const cid = "scope:s_bench_cons_aaaaaaaaaaaaaa"
	for i := 0; i < preFill; i++ {
		if _, err := s.AppendLeaf(ctx, cid, hashedLeaf(uint64(i)), 1700000000); err != nil {
			b.Fatal(err)
		}
	}
	size := uint64(preFill)
	mid := size / 2
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.ConsistencyProofFor(ctx, cid, mid, size); err != nil {
			b.Fatal(err)
		}
	}
}
