package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LoadOrCreateTranslogKey implements the TRANSLOG.md §4.1 startup
// matrix. Returns the loaded (or freshly generated) Ed25519 private
// key + corresponding pubkey, after cross-checking against the DB's
// translog_server_key cache.
//
// Startup matrix:
//
//	keyfile present | DB cached pub present | action
//	yes             | no                    | load file → derive pub → persist to DB
//	yes             | yes, matches keyfile  | load file → continue
//	yes             | yes, ≠ keyfile        | FATAL — accidental key swap
//	no              | yes                   | FATAL — DB expects a key the operator lost
//	no              | no                    | generate fresh keypair, persist file + DB,
//	                |                       | log WARN "back this up"
//
// `warn` is the WARN-level log function the caller supplies (server
// uses its standard logger). The fallback-generation message is
// emitted via this function so the operator sees it on stderr.
//
// Atomic file writes per TRANSLOG.md §4.1: tmp + fsync + rename +
// fsync(parent). A crash between any two steps either leaves the old
// keyfile (regenerate next boot) or a complete new keyfile (DB
// reconciles on next boot).
func LoadOrCreateTranslogKey(ctx context.Context, s *Store, path string, warn func(string)) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil, errors.New("translog key path must not be empty")
	}
	keyExists, fileBytes, err := readKeyFile(path)
	if err != nil {
		return nil, nil, err
	}
	dbPub, dbHasPub, err := loadDBPub(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case keyExists && !dbHasPub:
		// First-time DB persist after operator-supplied keyfile.
		priv, pub, err := keypairFromSeed(fileBytes)
		if err != nil {
			return nil, nil, err
		}
		if err := persistDBPub(ctx, s, pub); err != nil {
			return nil, nil, err
		}
		return priv, pub, nil

	case keyExists && dbHasPub:
		priv, pub, err := keypairFromSeed(fileBytes)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(pub, dbPub) {
			// FATAL: operator pointed at the wrong DB or swapped the
			// wrong keyfile. Refuse to start — silent acceptance would
			// invalidate every existing client's pin and orphan all
			// historical STHs without surfacing the swap.
			return nil, nil, fmt.Errorf("translog: keyfile %s does not match DB-cached pubkey — refusing to start (TRANSLOG.md §4.1 / §4.3)", path)
		}
		return priv, pub, nil

	case !keyExists && dbHasPub:
		// FATAL: DB expects a key that the operator no longer has.
		// Use a short prefix in the error for operator forensics; the
		// DB-validation in loadDBPub guarantees len(dbPub) ≥ 32.
		return nil, nil, fmt.Errorf("translog: DB has cached pubkey %x but keyfile %s is missing — operator must restore the keyfile or perform a key-rotation ceremony (TRANSLOG.md §4.3)", dbPub[:8], path)

	default:
		// Fresh deployment — generate.
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if err := writeKeyFileAtomic(path, priv); err != nil {
			return nil, nil, err
		}
		if err := persistDBPub(ctx, s, pub); err != nil {
			return nil, nil, err
		}
		if warn != nil {
			warn(fmt.Sprintf(
				"fd0-server: WARN — generated new transparency-log key at %s. "+
					"BACK THIS UP NOW. Loss requires a key-rotation ceremony "+
					"(TRANSLOG.md §4.3) and forces every client to re-pin on "+
					"next contact, dropping equivocation evidence for STHs "+
					"signed under the old key.", path))
		}
		return priv, pub, nil
	}
}

// readKeyFile loads `path` if it exists. Returns (true, content, nil)
// on success, (false, nil, nil) if missing, (false, nil, err) on any
// other I/O error.
func readKeyFile(path string) (bool, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("translog: read keyfile: %w", err)
	}
	return true, b, nil
}

// keypairFromSeed parses raw 64-byte Ed25519 private-key bytes (the
// standard Go layout: 32-byte seed || 32-byte pub) and validates that
// the appended pub matches what the seed actually derives.
//
// Without the consistency check, a malicious or corrupted keyfile could
// embed a pub that the seed does not produce; subsequent signatures
// (computed from the seed) would not verify under that pub — an obscure
// failure-mode caught by codex review. Anything other than 64 bytes,
// or any seed/pub mismatch, is startup-FATAL.
func keypairFromSeed(b []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(b) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("translog: keyfile must be %d bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	priv := ed25519.PrivateKey(append([]byte(nil), b...))
	derivedPriv := ed25519.NewKeyFromSeed(priv.Seed())
	if !bytes.Equal(derivedPriv, priv) {
		return nil, nil, errors.New("translog: keyfile seed||pub is internally inconsistent")
	}
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// writeKeyFileAtomic writes `data` to `path` atomically: tmp file with
// mode 0600 → fsync → rename → fsync parent. A crash between any two
// steps leaves either the old file untouched or the new file complete.
func writeKeyFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("translog: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".translog-key-*.tmp")
	if err != nil {
		return fmt.Errorf("translog: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on any error path past this point.
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("translog: chmod tmp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("translog: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("translog: fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("translog: close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("translog: rename: %w", err)
	}
	// fsync the parent directory so the rename is durable across
	// power-loss. fd0 targets POSIX; this MUST succeed per
	// TRANSLOG.md §4.1's atomicity contract — silently swallowing
	// the error would leave the keyfile rename in a metadata-only
	// state where a power-cut could resurrect the old name.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("translog: open parent dir for fsync: %w", err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return fmt.Errorf("translog: fsync parent dir: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("translog: close parent dir: %w", closeErr)
	}
	return nil
}

// loadDBPub reads the cached pubkey from translog_server_key.
// Returns (nil, false, nil) if the row is absent. Validates that the
// stored bytes are exactly ed25519.PublicKeySize — a corrupt row would
// otherwise panic later when we slice for an error message or pass it
// to verifiers.
func loadDBPub(ctx context.Context, s *Store) ([]byte, bool, error) {
	var pub []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT pub FROM translog_server_key WHERE id = 1`,
	).Scan(&pub)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("translog: read DB pub: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, false, fmt.Errorf("translog: cached DB pub has wrong length %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	return pub, true, nil
}

// persistDBPub writes the cached pubkey to translog_server_key.
// First-write only; never overwrites an existing row. The startup
// matrix above ensures we only call this when no row exists.
func persistDBPub(ctx context.Context, s *Store, pub []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO translog_server_key (id, pub, pub_pinned_at) VALUES (1, ?, ?)`,
		pub, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("translog: persist DB pub: %w", err)
	}
	return nil
}
