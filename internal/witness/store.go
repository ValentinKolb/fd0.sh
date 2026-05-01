// Package witness implements the passive STH archiver from
// TRANSLOG.md §8. It periodically polls one or more fd0-server
// instances for current signed tree heads, verifies them against the
// operator-pinned server pubkey, archives them in a local SQLite, and
// flags equivocation when the same (server, chain, tree_size) shows
// up with two different root_hash values.
//
// The witness deliberately holds no secrets and joins no scopes — it
// only consumes public commitments. Multiple independent witnesses
// observing the same server can be cross-correlated by their
// archives to detect divergent histories that no single client would
// ever notice on its own.
package witness

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/valentinkolb/fd0.sh/internal/translog"
)

//go:embed schema.sql
var schemaSQL string

// Store is the SQLite-backed STH archive. One row per (server_url,
// chain_id, tree_size, root_hash) — the four-tuple lets two STHs at
// the same tree_size with DIFFERENT roots coexist as equivocation
// evidence. A query for ">1 row at the same (server_url, chain_id,
// tree_size)" surfaces the equivocation.
type Store struct {
	db *sql.DB
}

// Open initialises the witness database file and applies the schema.
// Multiple witness processes against the same DB are NOT supported
// (single SQLite writer). Operators wanting redundancy should run
// independent witnesses against independent DB files.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(on)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the underlying DB.
func (s *Store) Close() error { return s.db.Close() }

// PinServer records the operator-supplied (server_url, server_pub)
// binding. Idempotent for the same pubkey. Returns ErrPinMismatch if
// the URL already has a different pubkey pinned — operators must
// explicitly UnpinServer first to rotate (operational ceremony, not a
// runtime convenience).
func (s *Store) PinServer(ctx context.Context, serverURL string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("witness.PinServer: pub must be 32 bytes")
	}
	row := s.db.QueryRowContext(ctx, `SELECT server_pub FROM witness_pins WHERE server_url = ?`, serverURL)
	var existing []byte
	err := row.Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO witness_pins (server_url, server_pub, pinned_at) VALUES (?, ?, ?)`,
			serverURL, []byte(pub), time.Now().Unix(),
		)
		return err
	}
	if err != nil {
		return err
	}
	if !equalBytes(existing, pub) {
		return ErrPinMismatch
	}
	return nil
}

// PinnedPub returns the previously-pinned pubkey for serverURL or
// ErrNotPinned if absent.
func (s *Store) PinnedPub(ctx context.Context, serverURL string) (ed25519.PublicKey, error) {
	var pub []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT server_pub FROM witness_pins WHERE server_url = ?`, serverURL,
	).Scan(&pub)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotPinned
	}
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("witness: pinned pub has wrong length %d", len(pub))
	}
	return ed25519.PublicKey(pub), nil
}

// LatestSTH returns the highest-tree_size STH archived for
// (server_url, chain_id), or ErrNoSTH if the witness has never
// observed this chain.
//
// "Highest by tree_size" rather than "most recently fetched" so the
// consistency-proof anchor matches the prover's notion of progress.
// Two same-size rows with different roots both appear in storage;
// LatestSTH returns one of them — the equivocation discriminator
// runs separately via DetectEquivocationAt.
func (s *Store) LatestSTH(ctx context.Context, serverURL, chainID string) (translog.STH, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tree_size, root_hash, timestamp, signature
		   FROM witness_sths
		  WHERE server_url = ? AND chain_id = ?
		  ORDER BY tree_size DESC LIMIT 1`,
		serverURL, chainID,
	)
	var (
		size int64
		root []byte
		ts   int64
		sig  []byte
	)
	err := row.Scan(&size, &root, &ts, &sig)
	if errors.Is(err, sql.ErrNoRows) {
		return translog.STH{}, ErrNoSTH
	}
	if err != nil {
		return translog.STH{}, err
	}
	return translog.STH{
		Head: translog.TreeHead{
			ChainID:   chainID,
			TreeSize:  uint64(size),
			RootHash:  root,
			Timestamp: uint64(ts),
		},
		Signature: sig,
	}, nil
}

// ArchiveResult tells the caller what happened on a given Insert call.
//
//	Stored == true                   : new (size, root) row inserted.
//	Stored == false                  : row already existed; no equivocation.
//	EquivocationDetected == true     : another row exists at the same
//	                                   tree_size with a DIFFERENT root —
//	                                   the most damning artifact a
//	                                   witness can produce.
type ArchiveResult struct {
	Stored               bool
	EquivocationDetected bool
}

// Insert archives an STH. Idempotent: re-inserting the same
// (server_url, chain_id, tree_size, root_hash) tuple is a no-op (no
// error). After insert, queries the table for any other row at the
// same tree_size with a different root and reports equivocation.
//
// Caller is expected to have ALREADY verified sth.Signature against
// the pinned pubkey; Insert does not re-verify (the storage layer is
// crypto-blind, the polling layer is crypto-aware).
func (s *Store) Insert(ctx context.Context, serverURL string, sth translog.STH, fetchedAt int64) (ArchiveResult, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO witness_sths (server_url, chain_id, tree_size, root_hash, timestamp, signature, fetched_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		serverURL, sth.Head.ChainID, int64(sth.Head.TreeSize), sth.Head.RootHash,
		int64(sth.Head.Timestamp), sth.Signature, fetchedAt,
	)
	if err != nil {
		return ArchiveResult{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return ArchiveResult{}, err
	}
	stored := rows > 0
	equiv, err := s.DetectEquivocationAt(ctx, serverURL, sth.Head.ChainID, sth.Head.TreeSize)
	if err != nil {
		return ArchiveResult{Stored: stored}, err
	}
	return ArchiveResult{Stored: stored, EquivocationDetected: equiv}, nil
}

// DetectEquivocationAt returns true iff witness_sths has two or more
// distinct root_hash values for (serverURL, chainID, treeSize). Used
// internally by Insert and by `fd0-witness verify` to scan the
// archive for historical equivocations.
func (s *Store) DetectEquivocationAt(ctx context.Context, serverURL, chainID string, treeSize uint64) (bool, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT root_hash)
		   FROM witness_sths
		  WHERE server_url = ? AND chain_id = ? AND tree_size = ?`,
		serverURL, chainID, int64(treeSize),
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 1, nil
}

// EquivocationsAt returns every (root_hash, signature, fetched_at)
// tuple for (serverURL, chainID, treeSize). Called when
// DetectEquivocationAt fires so the witness can emit each STH as
// evidence in the log.
func (s *Store) EquivocationsAt(ctx context.Context, serverURL, chainID string, treeSize uint64) ([]ArchivedSTH, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT root_hash, timestamp, signature, fetched_at
		   FROM witness_sths
		  WHERE server_url = ? AND chain_id = ? AND tree_size = ?
		  ORDER BY fetched_at`,
		serverURL, chainID, int64(treeSize),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ArchivedSTH
	for rows.Next() {
		var a ArchivedSTH
		var ts, fa int64
		if err := rows.Scan(&a.RootHash, &ts, &a.Signature, &fa); err != nil {
			return nil, err
		}
		a.Timestamp = uint64(ts)
		a.FetchedAt = fa
		out = append(out, a)
	}
	return out, rows.Err()
}

// ArchivedSTH is one row of the witness archive.
type ArchivedSTH struct {
	RootHash  []byte
	Timestamp uint64
	Signature []byte
	FetchedAt int64
}

// CountAll returns the total number of archived STHs across all
// (server, chain) pairs. Used by `fd0-witness status`.
func (s *Store) CountAll(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM witness_sths`).Scan(&n)
	return n, err
}

// SummaryRow is one (server_url, chain_id, max_tree_size) tuple from
// the archive. `fd0-witness status` prints these.
type SummaryRow struct {
	ServerURL              string
	ChainID                string
	MaxTreeSize            uint64
	RowCount               int64
	HasEquivAt             bool  // any tree_size on this chain has multiple roots
	ConsistencyFailureCount int64 // rows in witness_consistency_failures for this chain
}

// Summary returns a per-(server, chain) overview. Useful for status.
func (s *Store) Summary(ctx context.Context) ([]SummaryRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server_url, chain_id, MAX(tree_size), COUNT(*)
		   FROM witness_sths
		  GROUP BY server_url, chain_id
		  ORDER BY server_url, chain_id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SummaryRow
	for rows.Next() {
		var sr SummaryRow
		var max int64
		if err := rows.Scan(&sr.ServerURL, &sr.ChainID, &max, &sr.RowCount); err != nil {
			return nil, err
		}
		sr.MaxTreeSize = uint64(max)
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Annotate each row with same-size equivocation flag AND the
	// count of consistency-proof failures (different-size forks +
	// fetch failures). Done as separate queries per row to keep the
	// SQL portable and the row count low.
	for i := range out {
		var equiv int64
		err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM (
			    SELECT 1 FROM witness_sths
			    WHERE server_url = ? AND chain_id = ?
			    GROUP BY tree_size
			    HAVING COUNT(DISTINCT root_hash) > 1
			 )`, out[i].ServerURL, out[i].ChainID,
		).Scan(&equiv)
		if err != nil {
			return out, err
		}
		out[i].HasEquivAt = equiv > 0
		out[i].ConsistencyFailureCount, err = s.CountConsistencyFailures(ctx, out[i].ServerURL, out[i].ChainID)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// RecordConsistencyFailure persists a row to witness_consistency_failures.
// `reason` is "fetch_failed" (proof endpoint refused / network) or
// "verify_failed" (proof bytes did not validate).
func (s *Store) RecordConsistencyFailure(ctx context.Context, serverURL, chainID string, fromSize uint64, fromRoot []byte, toSize uint64, toRoot []byte, reason string, fetchedAt int64) error {
	if len(fromRoot) != 32 || len(toRoot) != 32 {
		return errors.New("witness: from_root/to_root must be 32 bytes")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO witness_consistency_failures
		 (server_url, chain_id, from_size, from_root, to_size, to_root, reason, fetched_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		serverURL, chainID, int64(fromSize), fromRoot, int64(toSize), toRoot, reason, fetchedAt,
	)
	return err
}

// CountConsistencyFailures returns the number of consistency-proof
// failure rows for (server, chain). Used by Summary so status/verify
// can show "this chain has N failed consistency checks".
func (s *Store) CountConsistencyFailures(ctx context.Context, serverURL, chainID string) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM witness_consistency_failures WHERE server_url = ? AND chain_id = ?`,
		serverURL, chainID,
	).Scan(&n)
	return n, err
}

// Sentinels.
var (
	ErrNotPinned   = errors.New("witness: server not pinned")
	ErrNoSTH       = errors.New("witness: no STH archived for this chain yet")
	ErrPinMismatch = errors.New("witness: server already pinned with a different pubkey — operator must unpin first to rotate")
)

func equalBytes(a, b []byte) bool {
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
