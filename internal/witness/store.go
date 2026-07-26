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
	if err := ensureWitnessSignatureColumn(context.Background(), db); err != nil {
		db.Close()
		return nil, fmt.Errorf("witness schema migration: %w", err)
	}
	store := &Store{db: db}
	if err := store.ensureSummaryIndex(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("witness summary index: %w", err)
	}
	return store, nil
}

func ensureWitnessSignatureColumn(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(witness_sths)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var (
			cid       int
			name      string
			columnTyp string
			notNull   int
			defaultV  any
			primary   int
		)
		if err := rows.Scan(&cid, &name, &columnTyp, &notNull, &defaultV, &primary); err != nil {
			return err
		}
		if name == "witness_signature" {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = db.ExecContext(ctx, `
		ALTER TABLE witness_sths
		ADD COLUMN witness_signature BLOB
		CHECK (witness_signature IS NULL OR length(witness_signature) = 64)
	`)
	return err
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
// observed this chain. Includes rows archived without a cosign
// (e.g., legacy archives, post-consistency-fail evidence rows).
// For the consistency-proof trust anchor inside the poll loop,
// use LatestVerifiedSTH instead.
//
// "Highest by tree_size" rather than "most recently fetched" so the
// consistency-proof anchor matches the prover's notion of progress.
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
// `witnessSig` is the witness's own cosign over the STH (may be nil
// for back-compat with archives migrated from earlier v1 builds).
//
// Caller is expected to have ALREADY verified sth.Signature against
// the pinned pubkey; Insert does not re-verify (the storage layer is
// crypto-blind, the polling layer is crypto-aware).
//
// THREAT: T40 (witness archive equivocation evidence — emits HTTP 409
//
//	via the polling layer when a divergent root is seen
//	at the same tree_size).
func (s *Store) Insert(ctx context.Context, serverURL string, sth translog.STH, fetchedAt int64, witnessSig []byte) (ArchiveResult, error) {
	if witnessSig != nil && len(witnessSig) != ed25519.SignatureSize {
		return ArchiveResult{}, fmt.Errorf("witness.Insert: witnessSig must be %d bytes or nil", ed25519.SignatureSize)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO witness_sths (server_url, chain_id, tree_size, root_hash, timestamp, signature, fetched_at, witness_signature)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		serverURL, sth.Head.ChainID, int64(sth.Head.TreeSize), sth.Head.RootHash,
		int64(sth.Head.Timestamp), sth.Signature, fetchedAt, witnessSig,
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

// LatestVerifiedSTH is LatestSTH but filters to rows that carry a
// witness cosign. Used by the poll loop as the trust anchor for
// the next consistency proof — without filtering, a previous
// consistency-fail evidence row (cosign withheld per codex audit
// witness.go:255) would become the prior, and the next poll could
// verify post-fork growth and cosign it, laundering an
// inconsistent history past the last verified STH.
func (s *Store) LatestVerifiedSTH(ctx context.Context, serverURL, chainID string) (translog.STH, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tree_size, root_hash, timestamp, signature
		   FROM witness_sths
		  WHERE server_url = ? AND chain_id = ? AND witness_signature IS NOT NULL
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

// LookupAt returns the cosigned STH archived at exactly
// (server, chain, tree_size). If the archive holds MULTIPLE distinct
// roots at that size — the smoking gun of same-size equivocation —
// LookupAt returns ErrEquivocationAtSize so the HTTP layer surfaces
// a 409 instead of silently picking one branch (codex fix #2).
// Without this, the API could mask the divergent root and feed the
// branch that matches the malicious server back to the client.
//
// Used by the witness's HTTP handler when a client asks
// `GET /v1/sth/<server>/<chain>?tree_size=N`.
func (s *Store) LookupAt(ctx context.Context, serverURL, chainID string, treeSize uint64) (translog.STH, []byte, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT root_hash, timestamp, signature, witness_signature
		   FROM witness_sths
		  WHERE server_url = ? AND chain_id = ? AND tree_size = ?
		  ORDER BY fetched_at DESC`,
		serverURL, chainID, int64(treeSize),
	)
	if err != nil {
		return translog.STH{}, nil, err
	}
	defer rows.Close()
	type row struct {
		root []byte
		ts   int64
		sig  []byte
		wsig []byte
	}
	var collected []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.root, &r.ts, &r.sig, &r.wsig); err != nil {
			return translog.STH{}, nil, err
		}
		collected = append(collected, r)
	}
	if err := rows.Err(); err != nil {
		return translog.STH{}, nil, err
	}
	if len(collected) == 0 {
		return translog.STH{}, nil, ErrNoSTH
	}
	// Multi-root detection: if any two rows at this size have
	// different root hashes, the witness is holding equivocation
	// evidence and MUST NOT serve a cosigned branch (it would let
	// a colluding server match either branch the client sees).
	for i := 1; i < len(collected); i++ {
		if !equalBytes(collected[i].root, collected[0].root) {
			return translog.STH{}, nil, ErrEquivocationAtSize
		}
	}
	r := collected[0]
	return translog.STH{
		Head: translog.TreeHead{
			ChainID:   chainID,
			TreeSize:  uint64(treeSize),
			RootHash:  r.root,
			Timestamp: uint64(r.ts),
		},
		Signature: r.sig,
	}, r.wsig, nil
}

// LatestSTHWithCosign is LatestSTH + the cosign over that row.
// Used by the witness HTTP handler for the "no tree_size given"
// (latest) query path.
//
// Same-size equivocation at the LATEST size is also surfaced as
// ErrEquivocationAtSize: returning either branch would mask the
// archive's own contradictory state.
func (s *Store) LatestSTHWithCosign(ctx context.Context, serverURL, chainID string) (translog.STH, []byte, error) {
	var maxSize sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(tree_size) FROM witness_sths
		   WHERE server_url = ? AND chain_id = ?`,
		serverURL, chainID,
	).Scan(&maxSize)
	if err != nil {
		return translog.STH{}, nil, err
	}
	if !maxSize.Valid {
		return translog.STH{}, nil, ErrNoSTH
	}
	return s.LookupAt(ctx, serverURL, chainID, uint64(maxSize.Int64))
}

// HighestTreeSize returns the highest tree_size the witness has
// archived for (serverURL, chainID), or (0, false, nil) if the
// witness has never observed this chain. Used by the C4 freshness
// probe — clients consult this BEFORE accepting a server-supplied
// STH at tree_size N to make sure the witness hasn't observed
// N+k for some k > 0 (the "first-fetch checkpoint rollback"
// case from THREATS.md T41).
//
// THREAT: T41 (first-fetch checkpoint rollback — fresh client
//
//	with no prior STH cannot consistency-prove; the
//	witness's highest-observed tree_size for the
//	chain is the cross-check anchor).
func (s *Store) HighestTreeSize(ctx context.Context, serverURL, chainID string) (uint64, bool, error) {
	var maxSize sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT MAX(tree_size) FROM witness_sths
		  WHERE server_url = ? AND chain_id = ?`,
		serverURL, chainID,
	).Scan(&maxSize)
	if err != nil {
		return 0, false, err
	}
	if !maxSize.Valid {
		return 0, false, nil
	}
	return uint64(maxSize.Int64), true, nil
}

// DetectChainEquivocation returns true iff witness_sths has any
// (serverURL, chainID) row pair with the same tree_size and
// distinct root_hash. Unlike DetectEquivocationAt (which is
// tree_size-specific), this scans the WHOLE chain history. Used
// by the C5 chain-level probe — clients refuse ANY cosign on a
// chain the witness has ever seen equivocate, even if the current
// tree_size is past the equivocation point.
//
// THREAT: T35 (server equivocation across clients — historical
//
//	multi-roots remain evidence indefinitely).
func (s *Store) DetectChainEquivocation(ctx context.Context, serverURL, chainID string) (bool, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*)
		   FROM (
		     SELECT tree_size FROM witness_sths
		      WHERE server_url = ? AND chain_id = ?
		      GROUP BY tree_size HAVING COUNT(DISTINCT root_hash) > 1
		   )`,
		serverURL, chainID,
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
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
	ServerURL               string
	ChainID                 string
	MaxTreeSize             uint64
	RowCount                int64
	HasEquivAt              bool  // any tree_size on this chain has multiple roots
	ConsistencyFailureCount int64 // rows in witness_consistency_failures for this chain
}

func (s *Store) ensureSummaryIndex(ctx context.Context) error {
	var version string
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM witness_schema_state WHERE key = 'summary_version'`,
	).Scan(&version)
	if err == nil && version == "1" {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM witness_chain_summary`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO witness_chain_summary (
			server_url, chain_id, max_tree_size, row_count,
			has_equiv, consistency_failure_count
		)
		SELECT s.server_url,
		       s.chain_id,
		       MAX(s.tree_size),
		       COUNT(*),
		       EXISTS(
		         SELECT 1
		           FROM witness_sths e
		          WHERE e.server_url = s.server_url AND e.chain_id = s.chain_id
		          GROUP BY e.tree_size
		         HAVING COUNT(DISTINCT e.root_hash) > 1
		       ),
		       (
		         SELECT COUNT(*)
		           FROM witness_consistency_failures f
		          WHERE f.server_url = s.server_url AND f.chain_id = s.chain_id
		       )
		  FROM witness_sths s
		 GROUP BY s.server_url, s.chain_id
	`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO witness_schema_state (key, value)
		VALUES ('summary_version', '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`); err != nil {
		return err
	}
	return tx.Commit()
}

const (
	maxStatusSummaryRows   = 10_000
	maxObservedSummaryRows = 1_024
	maxSummaryPageRows     = 1_024
)

var ErrSummaryLimit = errors.New("witness summary exceeds row limit")

// Summary returns a per-(server, chain) overview. Useful for status.
func (s *Store) Summary(ctx context.Context) ([]SummaryRow, error) {
	return s.summary(ctx, "", maxStatusSummaryRows)
}

// SummaryForServer bounds the public observed endpoint to one server.
func (s *Store) SummaryForServer(ctx context.Context, serverURL string) ([]SummaryRow, error) {
	return s.summary(ctx, serverURL, maxObservedSummaryRows)
}

// CountSummary returns the number of materialized (server, chain) rows.
func (s *Store) CountSummary(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM witness_chain_summary`).Scan(&n)
	return n, err
}

// SummaryPage returns a bounded ordered page for archive status and verify
// commands. Pass the returned cursor pair to the next call.
func (s *Store) SummaryPage(
	ctx context.Context,
	afterServer string,
	afterChain string,
	limit int,
) ([]SummaryRow, string, string, error) {
	if limit <= 0 || limit > maxSummaryPageRows {
		limit = maxSummaryPageRows
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT server_url, chain_id, max_tree_size, row_count,
		       has_equiv, consistency_failure_count
		  FROM witness_chain_summary
		 WHERE server_url > ?
		    OR (server_url = ? AND chain_id > ?)
		 ORDER BY server_url, chain_id
		 LIMIT ?`,
		afterServer, afterServer, afterChain, limit+1,
	)
	if err != nil {
		return nil, "", "", err
	}
	defer rows.Close()
	out, err := scanSummaryRows(rows)
	if err != nil {
		return nil, "", "", err
	}
	nextServer := ""
	nextChain := ""
	if len(out) > limit {
		out = out[:limit]
		nextServer = out[len(out)-1].ServerURL
		nextChain = out[len(out)-1].ChainID
	}
	return out, nextServer, nextChain, nil
}

func (s *Store) summary(ctx context.Context, serverURL string, limit int) ([]SummaryRow, error) {
	where := ""
	args := []any{}
	if serverURL != "" {
		where = "WHERE server_url = ?"
		args = append(args, serverURL)
	}
	args = append(args, limit+1)
	query := `SELECT server_url, chain_id, max_tree_size, row_count,
	                has_equiv, consistency_failure_count
	           FROM witness_chain_summary
	           ` + where + `
	          ORDER BY server_url, chain_id
	          LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanSummaryRows(rows)
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, ErrSummaryLimit
	}
	return out, nil
}

func scanSummaryRows(rows *sql.Rows) ([]SummaryRow, error) {
	var out []SummaryRow
	for rows.Next() {
		var sr SummaryRow
		var max int64
		if err := rows.Scan(
			&sr.ServerURL,
			&sr.ChainID,
			&max,
			&sr.RowCount,
			&sr.HasEquivAt,
			&sr.ConsistencyFailureCount,
		); err != nil {
			return nil, err
		}
		sr.MaxTreeSize = uint64(max)
		out = append(out, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
	ErrNotPinned          = errors.New("witness: server not pinned")
	ErrNoSTH              = errors.New("witness: no STH archived for this chain yet")
	ErrPinMismatch        = errors.New("witness: server already pinned with a different pubkey — operator must unpin first to rotate")
	ErrEquivocationAtSize = errors.New("witness: archive holds multiple distinct roots at this tree_size — equivocation evidence")
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
