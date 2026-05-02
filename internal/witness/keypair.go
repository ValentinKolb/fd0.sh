package witness

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

// LoadOrCreateWitnessKey implements the witness keypair startup
// matrix, mirroring the server's design from
// internal/server/store/translog_key.go but for the witness's own
// cosign keypair.
//
// The witness signs every successfully-verified STH with this key
// (TRANSLOG.md §10). Clients pin the witness pub in their config and
// require ≥N cosigns from pinned witnesses before accepting a sync.
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
// `warn` is the WARN-level log function the caller supplies. The
// fallback-generation message is emitted via this function so the
// operator sees it on stderr.
func LoadOrCreateWitnessKey(ctx context.Context, s *Store, path string, warn func(string)) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if path == "" {
		return nil, nil, errors.New("witness key path must not be empty")
	}
	keyExists, fileBytes, err := readKeyFile(path)
	if err != nil {
		return nil, nil, err
	}
	dbPub, dbHasPub, err := loadDBWitnessPub(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case keyExists && !dbHasPub:
		priv, pub, err := keypairFromSeed(fileBytes)
		if err != nil {
			return nil, nil, err
		}
		if err := persistDBWitnessPub(ctx, s, pub); err != nil {
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
			// invalidate every client's witness pin and orphan all
			// historical cosigns without surfacing the swap.
			return nil, nil, fmt.Errorf("witness: keyfile %s does not match DB-cached pubkey — refusing to start (use a fresh DB or restore the original keyfile)", path)
		}
		return priv, pub, nil

	case !keyExists && dbHasPub:
		return nil, nil, fmt.Errorf("witness: DB has cached pubkey %x but keyfile %s is missing — operator must restore the keyfile or run with a fresh DB (clients pinned to %x will reject cosigns from any new key)", dbPub[:8], path, dbPub[:8])

	default:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if err := writeKeyFileAtomic(path, priv); err != nil {
			return nil, nil, err
		}
		if err := persistDBWitnessPub(ctx, s, pub); err != nil {
			return nil, nil, err
		}
		if warn != nil {
			warn(fmt.Sprintf(
				"fd0-witness: WARN — generated new cosign key at %s. "+
					"BACK THIS UP NOW. Loss requires every client that "+
					"pinned this witness to update its config. Pubkey "+
					"to publish: %x", path, pub))
		}
		return priv, pub, nil
	}
}

func readKeyFile(path string) (bool, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("witness: read keyfile: %w", err)
	}
	return true, b, nil
}

// keypairFromSeed parses raw 64-byte Ed25519 private-key bytes (Go's
// standard layout: 32-byte seed || 32-byte pub) and validates that
// the appended pub matches what the seed actually derives. Anything
// other than 64 bytes, or any seed/pub mismatch, is startup-FATAL.
func keypairFromSeed(b []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(b) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("witness: keyfile must be %d bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	priv := ed25519.PrivateKey(append([]byte(nil), b...))
	derivedPriv := ed25519.NewKeyFromSeed(priv.Seed())
	if !bytes.Equal(derivedPriv, priv) {
		return nil, nil, errors.New("witness: keyfile seed||pub is internally inconsistent")
	}
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// writeKeyFileAtomic writes `data` to `path` atomically: tmp file
// with mode 0600 → fsync → rename → fsync parent.
func writeKeyFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("witness: mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".witness-key-*.tmp")
	if err != nil {
		return fmt.Errorf("witness: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("witness: chmod tmp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("witness: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("witness: fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("witness: close tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("witness: rename: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("witness: open parent dir for fsync: %w", err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return fmt.Errorf("witness: fsync parent dir: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("witness: close parent dir: %w", closeErr)
	}
	return nil
}

func loadDBWitnessPub(ctx context.Context, s *Store) ([]byte, bool, error) {
	var pub []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT pub FROM witness_keypair WHERE id = 1`,
	).Scan(&pub)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("witness: read DB pub: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, false, fmt.Errorf("witness: cached DB pub has wrong length %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	return pub, true, nil
}

func persistDBWitnessPub(ctx context.Context, s *Store, pub []byte) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO witness_keypair (id, pub, pinned_at) VALUES (1, ?, ?)`,
		pub, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("witness: persist DB pub: %w", err)
	}
	return nil
}
