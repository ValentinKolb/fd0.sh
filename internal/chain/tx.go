package chain

// Wave E: append-with-rollback transaction.
//
// Motivation: cli/sync.go used to grow a per-event AppendRaw loop
// surrounded by manual `os.Truncate(path, preSize)` rollback calls
// at three separate failure sites. Past audits (codex review
// rounds for sync.go:319/355/366/382) flagged the same class of
// bug repeatedly:
//
//   1. silent rollback failure — `_ = os.Truncate(...)` dropped
//      truncate errors so a half-extended file could survive
//      a "rolled back" return path
//   2. forgotten rollback path — a new error branch added later
//      could ship without remembering the truncate dance
//   3. partial AppendRaw mid-batch — fsynced events that the
//      caller's logic later rejected, leaving "successful so
//      far" bytes on disk
//
// AppendTx makes the rollback uniform: BeginAppend snapshots the
// pre-tx file size; Append flushes per-event (matching the
// existing fsync-after-each-write semantics callers rely on);
// Cleanup is `defer`-friendly and idempotent — it truncates back
// to the snapshot if Commit hasn't been called. Truncate
// failures surface as errors rather than silent drops.
//
// The transaction is intentionally NOT a buffered write — buffering
// would mean a single large write at Commit time, but every prior
// caller relies on per-event fsync (so a process crash mid-batch
// doesn't leave the on-disk file in a state that confuses
// readers). Per-event flush + truncate-on-Cleanup gives the same
// crash safety + the new uniform rollback story.

import (
	"errors"
	"fmt"
	"os"
)

// AppendTx tracks an in-flight batch append against a chain file.
// Begin snapshots the file size; Append writes events; Commit
// finalises (no-op flush, the per-event fsync already happened);
// Cleanup is the rollback. A typical pattern:
//
//	tx, err := chain.BeginAppend(path)
//	if err != nil { return err }
//	defer tx.Cleanup()
//	for _, ev := range events {
//	    if err := tx.AppendEvent(ev); err != nil { return err }
//	}
//	// ... validation ...
//	return tx.Commit()
//
// If the function returns before Commit (early-error or panic),
// the deferred Cleanup truncates back to preSize. After a
// successful Commit, Cleanup is a no-op so a defer'd Cleanup
// stays correct on either path.
type AppendTx struct {
	path    string
	preSize int64
	// closed transitions to true after either Commit or Cleanup.
	// Subsequent Append calls return ErrTxClosed.
	closed bool
	// committed is true iff Commit was called successfully.
	// Cleanup is a no-op in this state.
	committed bool
}

// ErrTxClosed is returned by Append after Commit or Cleanup.
var ErrTxClosed = errors.New("chain: AppendTx is closed")

// BeginAppend opens a transaction against `path`. The file's
// current size is captured as the rollback target. If the file
// does not exist, preSize is 0 and Cleanup will truncate the
// possibly-just-created file back to 0 bytes (callers that want
// the file to vanish entirely on rollback should `os.Remove`
// after Cleanup).
func BeginAppend(path string) (*AppendTx, error) {
	sz, err := txFileSize(path)
	if err != nil {
		return nil, err
	}
	return &AppendTx{path: path, preSize: sz}, nil
}

// AppendRaw appends a pre-encoded CBOR event. Mirrors the
// package-level chain.AppendRaw — same fsync-after-write
// semantics so a crash mid-batch leaves a partial-event-truncated
// file (which readers handle) plus the unflushed events lost
// (which the next sync round fetches again).
func (t *AppendTx) AppendRaw(raw []byte) error {
	if t.closed {
		return ErrTxClosed
	}
	return AppendRaw(t.path, raw)
}

// Commit finalises the transaction. Subsequent Cleanup calls are
// no-ops; subsequent Append calls return ErrTxClosed. Returns an
// error if Commit was already called or the transaction was
// rolled back via Cleanup. Per-event AppendRaw already fsynced;
// Commit carries no additional disk I/O.
func (t *AppendTx) Commit() error {
	if t.committed {
		return errors.New("chain: AppendTx already committed")
	}
	if t.closed {
		return errors.New("chain: AppendTx already rolled back")
	}
	t.committed = true
	t.closed = true
	return nil
}

// Cleanup truncates the file back to its pre-transaction size if
// Commit hasn't been called. Idempotent — safe to call multiple
// times and safe to defer alongside an explicit Cleanup on an
// error path. A truncate failure surfaces as an error so callers
// can detect a corrupt-on-disk chain (vs the old `_ =
// os.Truncate(...)` silent-drop pattern that several past audit
// rounds flagged).
//
// Cleanup is a no-op after Commit, which is the property that
// makes `defer tx.Cleanup()` correct under both success and
// failure paths.
func (t *AppendTx) Cleanup() error {
	if t.committed || t.closed {
		return nil // already finalised; idempotent no-op
	}
	t.closed = true
	// Edge case: BeginAppend captured preSize=0 because the file
	// didn't exist; no Append created it either (the inner loop
	// errored or was empty). Truncate-on-nonexistent fails with
	// ENOENT, but there's nothing to roll back — treat as success.
	if t.preSize == 0 {
		if _, err := os.Stat(t.path); os.IsNotExist(err) {
			return nil
		}
	}
	if err := os.Truncate(t.path, t.preSize); err != nil {
		return fmt.Errorf("chain: AppendTx rollback truncate to %d bytes failed (chain may be corrupt on disk): %w",
			t.preSize, err)
	}
	return nil
}

// PreSize returns the file size captured at BeginAppend. Useful
// for tests that want to assert "Cleanup truncated to exactly
// this many bytes".
func (t *AppendTx) PreSize() int64 { return t.preSize }

// txFileSize is a tx-local copy of cli.fileSize so chain doesn't
// import cli.
func txFileSize(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return st.Size(), nil
}
