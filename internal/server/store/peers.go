package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// labelRE bounds the operator-declared self-label. Same shape both
// server-side (FD0_LABEL on this binary) and peer-side (the label
// copied verbatim from a remote peer's /v1/server-info). The narrow
// charset is what makes it safe to render in CLI output and on the
// website without escaping — a peer can't smuggle ANSI escapes or
// control characters into a downstream UI.
var labelRE = regexp.MustCompile(`^[a-z0-9-]{0,32}$`)

// ValidLabel reports whether s is a valid FD0_LABEL value: 0..32 chars
// of [a-z0-9-]. Empty is allowed (= "no label").
func ValidLabel(s string) bool { return labelRE.MatchString(s) }

// ErrPeerKeyMismatch is returned by UpsertPeer when a row already
// exists for url with a different pub. Rotation requires the operator
// to wipe the row manually (DELETE FROM peers WHERE url = ?), which
// makes the TOFU pin sticky against silent operator-side key swaps.
var ErrPeerKeyMismatch = errors.New("peer pubkey mismatch — pin held, refusing overwrite")

// UpsertPeer pins (url, pub) on first sight, then refreshes label +
// last_verified on subsequent calls. Returns ErrPeerKeyMismatch if a
// later call publishes a different pubkey for the same url.
//
// pub MUST be 32 bytes (ed25519 pubkey); label MUST already have passed
// ValidLabel — the caller (peer resolver) drops invalid labels before
// calling here. Pre-validation keeps the row clean: anything in the
// peers table is safe to render.
func (s *Store) UpsertPeer(ctx context.Context, url string, pub []byte, label string) error {
	if url == "" {
		return errors.New("store: empty peer URL")
	}
	if len(pub) != 32 {
		return errors.New("store: peer pub must be 32 bytes")
	}
	if !ValidLabel(label) {
		return errors.New("store: peer label fails [a-z0-9-]{0,32}")
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingPub []byte
	err = tx.QueryRowContext(ctx, `SELECT pub FROM peers WHERE url = ?`, url).Scan(&existingPub)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO peers (url, pub, label, first_seen, last_verified) VALUES (?, ?, ?, ?, ?)`,
			url, pub, label, now, now); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		if !bytesEqual(existingPub, pub) {
			return ErrPeerKeyMismatch
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE peers SET label = ?, last_verified = ? WHERE url = ?`,
			label, now, url); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListPeers returns every pinned peer in url-sorted order. Used by
// the /v1/server-info handler to embed the resolved peer list, and
// by /metrics gauges for peer-count visibility.
func (s *Store) ListPeers(ctx context.Context) ([]translog.PeerInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT url, pub, label FROM peers ORDER BY url`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []translog.PeerInfo{}
	for rows.Next() {
		var p translog.PeerInfo
		if err := rows.Scan(&p.URL, &p.Pub, &p.Label); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePeer removes a peer row. Operators run this manually to allow
// a key rotation: DELETE the row, the resolver re-TOFUs on next poll.
func (s *Store) DeletePeer(ctx context.Context, url string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE url = ?`, url)
	return err
}
