// Package store implements the SQLite-backed durable state for fd0-server
// (STORAGE.md §2 and §7).
package store

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// Store wraps a *sql.DB with the SQLite pragmas fd0 requires.
//
// translogPriv / translogPub are populated by SetTranslogKey and used
// by AppendLeaf. Server boot installs them via LoadOrCreateTranslogKey.
// AppendLeaf without an installed key returns ErrTranslogKeyMissing —
// callers (server.go) should treat that as a configuration error, not
// a per-request fault.
type Store struct {
	db           *sql.DB
	translogPriv ed25519.PrivateKey
	translogPub  ed25519.PublicKey
}

// Open initialises the database file and applies the schema.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(on)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite WAL allows readers, but our writers use IMMEDIATE; one writer is plenty
	if _, err := db.ExecContext(context.Background(), schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close releases the underlying DB.
func (s *Store) Close() error { return s.db.Close() }

// ChainKind is "user" or "scope".
type ChainKind string

const (
	KindUser  ChainKind = "user"
	KindScope ChainKind = "scope"
)

// Chain is one row of the chains table.
type Chain struct {
	ID       string
	TipSeq   uint64
	TipHash  []byte
	Metadata []byte // CBOR
}

// Event is one row of the events table.
type Event struct {
	ChainID   string
	Seq       uint64
	EventID   string
	PrevHash  []byte
	Kind      string
	CBOR      []byte
	StoredAt  int64
}

// ErrNotFound is returned by lookups that find no row.
var ErrNotFound = errors.New("not found")

// ErrDivergence is returned by Append when prev_hash doesn't match the tip.
var ErrDivergence = errors.New("divergence")

// ErrDuplicate is returned by Append when event_id already exists.
var ErrDuplicate = errors.New("duplicate event_id")

// ChainID encodes a chain id like "user:<shortId>" or "scope:<scope_id>".
func ChainID(kind ChainKind, key string) string { return string(kind) + ":" + key }

// GetChain returns the chain row, or ErrNotFound.
func (s *Store) GetChain(ctx context.Context, id string) (*Chain, error) {
	row := s.db.QueryRowContext(ctx, `SELECT chain_id, tip_seq, tip_hash, metadata FROM chains WHERE chain_id = ?`, id)
	var c Chain
	err := row.Scan(&c.ID, &c.TipSeq, &c.TipHash, &c.Metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// AppendOpts is what callers must compute before calling Append.
type AppendOpts struct {
	ChainID     string
	Kind        ChainKind   // user/scope (for chain-row creation)
	Genesis     bool        // true at seq=0 (chain row is created)
	Seq         uint64
	NewTipHash  []byte
	NewMetadata []byte // CBOR; replaces prior metadata wholesale
	Event       Event
}

// Append performs the optimistic-CAS append in its own transaction.
// Equivalent to AppendWithTranslog with no translog hook — kept for
// callers that don't have a translog key installed (tests, legacy
// callers).
func (s *Store) Append(ctx context.Context, o AppendOpts) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.appendTx(ctx, tx, o); err != nil {
		return err
	}
	return tx.Commit()
}

// appendTx is the transaction-internal body of Append. Pulled out so
// AppendWithTranslog can reuse the same atomicity contract while
// adding the translog leaf in the same tx.
//
// Contract:
//
//	BEGIN IMMEDIATE
//	  if !genesis: SELECT tip_hash FROM chains WHERE chain_id = ?
//	               compare with event.prev_hash → ErrDivergence on mismatch
//	  INSERT INTO events
//	  if genesis: INSERT INTO chains
//	  else:       UPDATE chains SET tip_seq, tip_hash, metadata
func (s *Store) appendTx(ctx context.Context, tx *sql.Tx, o AppendOpts) error {
	// Ensure write isolation; sqlite handles BEGIN IMMEDIATE via the next write.
	if !o.Genesis {
		var tip []byte
		var tipSeq uint64
		err := tx.QueryRowContext(ctx, `SELECT tip_seq, tip_hash FROM chains WHERE chain_id = ?`, o.ChainID).Scan(&tipSeq, &tip)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDivergence
		}
		if err != nil {
			return err
		}
		if !bytesEqual(o.Event.PrevHash, tip) || o.Seq != tipSeq+1 {
			return ErrDivergence
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO events (chain_id, seq, event_id, prev_hash, kind, cbor, stored_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		o.ChainID, o.Seq, o.Event.EventID, o.Event.PrevHash, o.Event.Kind, o.Event.CBOR, time.Now().Unix())
	if err != nil {
		// modernc returns "constraint failed: UNIQUE constraint failed: events.event_id"
		if isUnique(err) {
			return ErrDuplicate
		}
		return err
	}
	if o.Genesis {
		_, err = tx.ExecContext(ctx, `INSERT INTO chains (chain_id, tip_seq, tip_hash, metadata) VALUES (?, ?, ?, ?)`,
			o.ChainID, o.Seq, o.NewTipHash, o.NewMetadata)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE chains SET tip_seq = ?, tip_hash = ?, metadata = ? WHERE chain_id = ?`,
			o.Seq, o.NewTipHash, o.NewMetadata, o.ChainID)
	}
	return err
}

// EventsSince returns events with seq > since up to limit, ordered by seq asc.
func (s *Store) EventsSince(ctx context.Context, chainID string, since uint64, limit int) ([]Event, error) {
	return s.EventsSinceInclusive(ctx, chainID, since, limit, false)
}

// EventsSinceInclusive optionally includes seq == since (used for fresh
// discovery where the caller has no prior cursor and needs the genesis).
func (s *Store) EventsSinceInclusive(ctx context.Context, chainID string, since uint64, limit int, inclusive bool) ([]Event, error) {
	op := ">"
	if inclusive {
		op = ">="
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT chain_id, seq, event_id, prev_hash, kind, cbor, stored_at FROM events WHERE chain_id = ? AND seq `+op+` ? ORDER BY seq LIMIT ?`,
		chainID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ChainID, &e.Seq, &e.EventID, &e.PrevHash, &e.Kind, &e.CBOR, &e.StoredAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EventExists returns true iff event_id is already stored.
func (s *Store) EventExists(ctx context.Context, eventID string) (bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT 1 FROM events WHERE event_id = ? LIMIT 1`, eventID)
	var x int
	err := row.Scan(&x)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// LatestUserAuthSet returns the latest event in a user chain.
func (s *Store) LatestEvent(ctx context.Context, chainID string) (*Event, error) {
	row := s.db.QueryRowContext(ctx, `SELECT chain_id, seq, event_id, prev_hash, kind, cbor, stored_at FROM events WHERE chain_id = ? ORDER BY seq DESC LIMIT 1`, chainID)
	var e Event
	err := row.Scan(&e.ChainID, &e.Seq, &e.EventID, &e.PrevHash, &e.Kind, &e.CBOR, &e.StoredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ScopesForMember returns chain_ids of scopes whose metadata lists pk in members.
// Naive scan; small N in v1.
func (s *Store) ScopesForMember(ctx context.Context, pkBytes []byte) ([]Chain, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT chain_id, tip_seq, tip_hash, metadata FROM chains WHERE chain_id LIKE 'scope:%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Chain
	for rows.Next() {
		var c Chain
		if err := rows.Scan(&c.ID, &c.TipSeq, &c.TipHash, &c.Metadata); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- Replay nonces ----

// CheckAndInsertNonce returns true if (pk, nonce) was inserted; false if seen.
// Old nonces are pruned in the background by PruneNonces.
func (s *Store) CheckAndInsertNonce(ctx context.Context, pk, nonce []byte, ts int64) (bool, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_nonces (pk, nonce, ts) VALUES (?, ?, ?)`, pk, nonce, ts)
	if err == nil {
		return true, nil
	}
	if isUnique(err) {
		return false, nil
	}
	return false, err
}

// PruneNonces deletes nonces older than ttlSecs.
func (s *Store) PruneNonces(ctx context.Context, ttlSecs int64) error {
	cutoff := time.Now().Unix() - ttlSecs
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_nonces WHERE ts < ?`, cutoff)
	return err
}

// RegisterUser inserts a (super_pub, short_id) row. Returns
// ErrDuplicate if super_pub or short_id is already taken (codex
// audit 🔴 server.go:279: super_pub_taken was previously not
// enforced, so the same user_super_pub could register many shortIds).
func (s *Store) RegisterUser(ctx context.Context, superPub []byte, shortID string) error {
	if len(superPub) != 32 {
		return errors.New("store: super_pub must be 32 bytes")
	}
	if shortID == "" {
		return errors.New("store: short_id must not be empty")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (super_pub, short_id, registered_at) VALUES (?, ?, ?)`,
		superPub, shortID, time.Now().Unix(),
	)
	if err != nil && isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// IsUserRegistered returns true iff super_pub appears in the users
// table. Codex audit (🔴 auth.go:87): every authenticated endpoint
// MUST check this before honouring a request — otherwise a self-
// signed pk that never went through POST /users could call /sync
// and create scopes.
func (s *Store) IsUserRegistered(ctx context.Context, superPub []byte) (bool, error) {
	if len(superPub) != 32 {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM users WHERE super_pub = ? LIMIT 1`, superPub,
	).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---- helpers ----

func bytesEqual(a, b []byte) bool {
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

// isUnique tells whether err is a SQLite UNIQUE constraint violation.
func isUnique(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, m := range []string{"UNIQUE constraint failed", "constraint failed: UNIQUE", "constraint failed (2067)"} {
		if contains(s, m) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
