package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// Replication backup store (REPLICATION.md Phase 0).
//
// These methods operate ONLY on the backup_events / backup_sths archive,
// never on the live events / chains / translog_* tables. A backed-up
// chain is read-only, foreign-anchored data: this server stores it for
// disaster recovery but never serves it to clients and never re-signs it.
// Keeping the archive in separate tables with a distinct API is the
// structural guard behind the one-anchor invariant (REPLICATION.md §2):
// there is no code path that turns a backup row into a locally-anchored,
// locally-signed chain except the explicit operator restore.

// BackupMaxSeq returns the highest backed-up seq for (sourcePub, chainID),
// or -1 if nothing is stored yet. The replicator uses it to pull only the
// new suffix on each cycle.
func (s *Store) BackupMaxSeq(ctx context.Context, sourcePub []byte, chainID string) (int64, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq), -1) FROM backup_events WHERE source_pub = ? AND chain_id = ?`,
		sourcePub, chainID)
	var max int64
	if err := row.Scan(&max); err != nil {
		return -1, err
	}
	return max, nil
}

// BackupAppendEvents stores events verbatim under sourcePub. Idempotent
// for IDENTICAL re-stores (a retried/overlapping pull is harmless), but a
// CONFLICT — a different event_id or cbor already stored at the same
// (source, chain, seq) — is a hard error: it means the source served two
// different events for one slot (a fork or corruption), which must not be
// silently swallowed in a DR archive. Never touches the live tables.
func (s *Store) BackupAppendEvents(ctx context.Context, sourcePub []byte, evs []Event) error {
	if len(evs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, e := range evs {
		var exID string
		var exCBOR []byte
		err := tx.QueryRowContext(ctx,
			`SELECT event_id, cbor FROM backup_events WHERE source_pub=? AND chain_id=? AND seq=?`,
			sourcePub, e.ChainID, int64(e.Seq)).Scan(&exID, &exCBOR)
		switch {
		case err == sql.ErrNoRows:
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO backup_events
				   (source_pub, chain_id, seq, event_id, prev_hash, kind, cbor, stored_at)
				 VALUES (?,?,?,?,?,?,?,?)`,
				sourcePub, e.ChainID, int64(e.Seq), e.EventID, e.PrevHash, e.Kind, e.CBOR, e.StoredAt); err != nil {
				return err
			}
		case err != nil:
			return err
		default: // row exists — must be byte-identical
			if exID != e.EventID || !bytesEqual(exCBOR, e.CBOR) {
				return fmt.Errorf("backup conflict: source served a different event at %s seq %d (have %s, got %s)",
					e.ChainID, e.Seq, exID, e.EventID)
			}
		}
	}
	return tx.Commit()
}

// BackupPutSTH archives a source STH verbatim. Idempotent on
// (source, chain, tree_size).
func (s *Store) BackupPutSTH(ctx context.Context, sourcePub []byte, chainID string, sth translog.STH) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO backup_sths
		   (source_pub, chain_id, tree_size, root_hash, timestamp, signature)
		 VALUES (?,?,?,?,?,?)`,
		sourcePub, chainID, int64(sth.Head.TreeSize), sth.Head.RootHash, int64(sth.Head.Timestamp), sth.Signature)
	return err
}

// BackupEvents returns archived events for (sourcePub, chainID) ascending
// by seq — for verification and for the operator restore path.
func (s *Store) BackupEvents(ctx context.Context, sourcePub []byte, chainID string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT chain_id, seq, event_id, prev_hash, kind, cbor, stored_at
		   FROM backup_events WHERE source_pub = ? AND chain_id = ? ORDER BY seq`,
		sourcePub, chainID)
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

// BackupCurrentSTH returns the highest-size archived STH for
// (sourcePub, chainID), or ErrNotFound.
func (s *Store) BackupCurrentSTH(ctx context.Context, sourcePub []byte, chainID string) (translog.STH, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tree_size, root_hash, timestamp, signature FROM backup_sths
		  WHERE source_pub = ? AND chain_id = ? ORDER BY tree_size DESC LIMIT 1`,
		sourcePub, chainID)
	return scanSTH(chainID, row)
}

// BackupChainIDs lists the chain ids archived under sourcePub.
func (s *Store) BackupChainIDs(ctx context.Context, sourcePub []byte) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT chain_id FROM backup_events WHERE source_pub = ? ORDER BY chain_id`, sourcePub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// IsPeerPub reports whether pub is a TOFU-pinned peer. It authorises the
// peer-only replication endpoints — a server serves raw (encrypted) chain
// bytes only to peers it has pinned, never to anonymous callers.
func (s *Store) IsPeerPub(ctx context.Context, pub []byte) (bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT 1 FROM peers WHERE pub = ? LIMIT 1`, pub)
	var one int
	err := row.Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
