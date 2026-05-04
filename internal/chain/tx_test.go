package chain

import (
	"bytes"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// Wave E property test: random failure injection at every step
// of an AppendTx batch proves the file ends up either fully
// committed (all bytes present) or fully rolled back (preSize
// bytes), never partial.
//
// The injector chooses an iteration N from 1..len(events) at
// random and either commits (success path) or skips Commit and
// calls Cleanup (failure path) at iteration N. After the tx,
// the file size MUST equal one of the two valid endpoints.

func TestAppendTxBeginCommitRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.cbor")
	// Pre-existing data in the file — Cleanup must NOT touch it.
	pre := bytes.Repeat([]byte{0xAA}, 64)
	if err := os.WriteFile(path, pre, 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if tx.PreSize() != int64(len(pre)) {
		t.Fatalf("PreSize: want %d, got %d", len(pre), tx.PreSize())
	}
	for i := 0; i < 4; i++ {
		if err := tx.AppendRaw(bytes.Repeat([]byte{byte(0x10 + i)}, 16)); err != nil {
			t.Fatalf("AppendRaw[%d]: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// File grew by exactly 4*16 = 64 bytes past preSize.
	st, _ := os.Stat(path)
	if st.Size() != int64(len(pre)+64) {
		t.Fatalf("Commit size: want %d, got %d", len(pre)+64, st.Size())
	}
	// Defer-Cleanup-after-Commit must be a no-op. File size
	// stays at len(pre)+64; no truncate.
	if err := tx.Cleanup(); err != nil {
		t.Fatalf("Cleanup-after-Commit: want nil, got %v", err)
	}
	stAfter, _ := os.Stat(path)
	if stAfter.Size() != int64(len(pre)+64) {
		t.Fatalf("Cleanup-after-Commit size drift: want %d, got %d", len(pre)+64, stAfter.Size())
	}
}

func TestAppendTxBeginCleanupRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.cbor")
	pre := bytes.Repeat([]byte{0xAA}, 64)
	if err := os.WriteFile(path, pre, 0o600); err != nil {
		t.Fatal(err)
	}
	tx, err := BeginAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := tx.AppendRaw(bytes.Repeat([]byte{0x55}, 16)); err != nil {
			t.Fatal(err)
		}
	}
	// Skip Commit; call Cleanup directly. Bytes appended via
	// AppendRaw must be truncated.
	if err := tx.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	gotBytes, _ := os.ReadFile(path)
	if !bytes.Equal(gotBytes, pre) {
		t.Fatalf("Cleanup did not restore preSize bytes: got %x", gotBytes)
	}
	// Idempotent — second Cleanup is a no-op.
	if err := tx.Cleanup(); err != nil {
		t.Fatalf("second Cleanup: want nil, got %v", err)
	}
}

func TestAppendTxAppendAfterCloseRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.cbor")
	tx, err := BeginAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := tx.AppendRaw([]byte{0x01}); !errors.Is(err, ErrTxClosed) {
		t.Fatalf("AppendRaw after Commit: want ErrTxClosed, got %v", err)
	}

	tx2, _ := BeginAppend(path)
	_ = tx2.Cleanup()
	if err := tx2.AppendRaw([]byte{0x01}); !errors.Is(err, ErrTxClosed) {
		t.Fatalf("AppendRaw after Cleanup: want ErrTxClosed, got %v", err)
	}
}

func TestAppendTxDoubleCommitRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.cbor")
	tx, err := BeginAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("second Commit should error")
	}
	tx2, _ := BeginAppend(path)
	_ = tx2.Cleanup()
	if err := tx2.Commit(); err == nil {
		t.Fatal("Commit after Cleanup should error")
	}
}

// TestAppendTxPropertyRandomFailure: for many random seeds, run
// a sequence of AppendRaw + maybe-fail + Cleanup-or-Commit. Two
// invariants:
//   I1. Final file size ∈ {preSize, preSize + Σ(committed event lens)}.
//   I2. Multiple Cleanup calls converge to preSize regardless of
//       interleavings (idempotency).
func TestAppendTxPropertyRandomFailure(t *testing.T) {
	const iters = 200
	for run := 0; run < iters; run++ {
		seed := int64(0x1000 + run)
		t.Run("", func(t *testing.T) {
			r := rand.New(rand.NewSource(seed))
			dir := t.TempDir()
			path := filepath.Join(dir, "scope.cbor")
			// Random pre-data length 0..128.
			preLen := r.Intn(129)
			pre := make([]byte, preLen)
			r.Read(pre)
			if preLen > 0 {
				if err := os.WriteFile(path, pre, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := BeginAppend(path)
			if err != nil {
				t.Fatalf("seed=%#x: BeginAppend: %v", seed, err)
			}
			// Random number of appends 0..16, random sizes 1..32.
			n := r.Intn(17)
			totalAppended := 0
			for i := 0; i < n; i++ {
				sz := 1 + r.Intn(32)
				buf := make([]byte, sz)
				r.Read(buf)
				if err := tx.AppendRaw(buf); err != nil {
					t.Fatalf("seed=%#x: AppendRaw[%d]: %v", seed, i, err)
				}
				totalAppended += sz
			}
			// Coin-flip: commit (success) or cleanup (rollback).
			commit := r.Intn(2) == 0
			var wantSize int64
			if commit {
				if err := tx.Commit(); err != nil {
					t.Fatalf("seed=%#x: Commit: %v", seed, err)
				}
				wantSize = int64(preLen + totalAppended)
			} else {
				if err := tx.Cleanup(); err != nil {
					t.Fatalf("seed=%#x: Cleanup: %v", seed, err)
				}
				wantSize = int64(preLen)
			}
			st, err := os.Stat(path)
			if err != nil && !os.IsNotExist(err) {
				t.Fatalf("seed=%#x: stat: %v", seed, err)
			}
			var gotSize int64
			if err == nil {
				gotSize = st.Size()
			}
			// I1: file size must equal exactly one of the two endpoints.
			if gotSize != wantSize {
				t.Fatalf("seed=%#x: I1 violated — wantSize=%d, gotSize=%d (commit=%v, n=%d)",
					seed, wantSize, gotSize, commit, n)
			}
			// I2: subsequent Cleanup is idempotent.
			//     - if we already Committed, Cleanup is a no-op.
			//     - if we already Cleaned up, Cleanup is a no-op.
			if err := tx.Cleanup(); err != nil {
				t.Fatalf("seed=%#x: idempotent Cleanup: %v", seed, err)
			}
			st2, err := os.Stat(path)
			if err != nil && !os.IsNotExist(err) {
				t.Fatalf("seed=%#x: stat 2: %v", seed, err)
			}
			var gotSize2 int64
			if err == nil {
				gotSize2 = st2.Size()
			}
			if gotSize2 != wantSize {
				t.Fatalf("seed=%#x: I2 violated — second Cleanup changed size (was %d, now %d)",
					seed, gotSize, gotSize2)
			}
		})
	}
}

// TestAppendTxNonexistentFileRollsBackToZero: BeginAppend on a
// missing file captures preSize=0; Cleanup truncates back to 0
// even though Append created the file. Caller is responsible for
// os.Remove if the file should not exist post-rollback.
func TestAppendTxNonexistentFileRollsBackToZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.cbor")
	tx, err := BeginAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	if tx.PreSize() != 0 {
		t.Fatalf("PreSize on missing file: want 0, got %d", tx.PreSize())
	}
	if err := tx.AppendRaw([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tx.Cleanup(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file disappeared on Cleanup: %v", err)
	}
	if st.Size() != 0 {
		t.Fatalf("Cleanup size: want 0, got %d", st.Size())
	}
}
