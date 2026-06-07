package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// ErrTranslogKeyMissing is returned by AppendLeaf when the translog
// signing key has not been installed via SetTranslogKey. Server boot
// should always install one — failure here means a configuration bug,
// not a per-request fault.
var ErrTranslogKeyMissing = errors.New("translog signing key not installed")

// SetTranslogKey installs the translog signing key. Idempotent: if the
// same key is already installed, no-op. A second call with a different
// key returns an error to catch accidental key swaps at runtime
// (rotation must go through the operational ceremony in TRANSLOG.md
// §4.3, not a hot reload).
//
// The provided slices are copied so the caller may zero/wipe their
// originals after install.
func (s *Store) SetTranslogKey(priv ed25519.PrivateKey, pub ed25519.PublicKey) error {
	if len(priv) != ed25519.PrivateKeySize || len(pub) != ed25519.PublicKeySize {
		return errors.New("translog key has wrong length")
	}
	if s.translogPriv != nil {
		if !bytes.Equal(s.translogPub, pub) {
			return errors.New("translog key already installed; rotation requires restart + DB ceremony")
		}
		return nil
	}
	s.translogPriv = ed25519.PrivateKey(append([]byte(nil), priv...))
	s.translogPub = ed25519.PublicKey(append([]byte(nil), pub...))
	return nil
}

// HasTranslogKey reports whether a translog signing key is installed.
// Server uses this to gate registering the translog endpoints.
func (s *Store) HasTranslogKey() bool { return s.translogPriv != nil }

// TranslogPub returns the installed translog signing pubkey, or nil if
// none. Used by the /v1/server-info handler to publish.
func (s *Store) TranslogPub() ed25519.PublicKey {
	if s.translogPub == nil {
		return nil
	}
	out := make([]byte, len(s.translogPub))
	copy(out, s.translogPub)
	return out
}

// AppendLeaf adds a new leaf for chainID in its OWN transaction. The
// production path is AppendWithTranslog (event + leaf in one tx);
// AppendLeaf exists for tests and for chains where the storage layer
// already committed the event separately and we need to re-establish
// translog coverage.
func (s *Store) AppendLeaf(ctx context.Context, chainID string, eventHash []byte, now uint64) (translog.STH, error) {
	if s.translogPriv == nil {
		return translog.STH{}, ErrTranslogKeyMissing
	}
	if len(eventHash) != translog.HashSize {
		return translog.STH{}, fmt.Errorf("AppendLeaf: eventHash must be %d bytes", translog.HashSize)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return translog.STH{}, err
	}
	defer tx.Rollback()
	sth, err := s.appendLeafTx(ctx, tx, chainID, eventHash, now)
	if err != nil {
		return translog.STH{}, err
	}
	if err := tx.Commit(); err != nil {
		return translog.STH{}, err
	}
	return sth, nil
}

// AppendWithTranslog atomically appends an event AND its translog
// leaf in a single SQL transaction. This is the production path:
// either both land or neither does, removing the partial-failure mode
// where event commits but leaf doesn't (would leave a permanent gap
// in the tree per codex review).
//
// `eventHash` is the 32-byte canonical event hash (= SHA-256 over
// PrevHashInput). `now` is the STH timestamp.
//
// Returns the newly-signed STH on success. Returns ErrDivergence /
// ErrDuplicate from the event-side append; ErrTranslogKeyMissing if
// no translog key has been installed.
func (s *Store) AppendWithTranslog(ctx context.Context, opts AppendOpts, eventHash []byte, now uint64) (translog.STH, error) {
	if s.translogPriv == nil {
		return translog.STH{}, ErrTranslogKeyMissing
	}
	if len(eventHash) != translog.HashSize {
		return translog.STH{}, fmt.Errorf("AppendWithTranslog: eventHash must be %d bytes", translog.HashSize)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return translog.STH{}, err
	}
	defer tx.Rollback()
	if err := s.appendTx(ctx, tx, opts); err != nil {
		return translog.STH{}, err
	}
	sth, err := s.appendLeafTx(ctx, tx, opts.ChainID, eventHash, now)
	if err != nil {
		return translog.STH{}, err
	}
	if err := tx.Commit(); err != nil {
		return translog.STH{}, err
	}
	return sth, nil
}

// appendLeafTx is the transaction-internal body of AppendLeaf. It does
// the incremental tree update + STH sign + STH persist within the
// supplied tx, returning the new STH. Callers must commit (or roll
// back) the surrounding tx.
//
// `eventHash` is the 32-byte canonical event hash. `now` is the STH
// timestamp.
func (s *Store) appendLeafTx(ctx context.Context, tx *sql.Tx, chainID string, eventHash []byte, now uint64) (translog.STH, error) {
	// Determine the next leaf index = current leaf count for chainID.
	var n uint64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM translog_nodes WHERE chain_id = ? AND level = 0`, chainID,
	).Scan(&n); err != nil {
		return translog.STH{}, err
	}

	// Insert the new leaf at (0, n).
	leafHash := translog.LeafHash(eventHash)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO translog_nodes (chain_id, level, index_at_level, hash) VALUES (?, ?, ?, ?)`,
		chainID, 0, int64(n), leafHash,
	); err != nil {
		return translog.STH{}, err
	}

	// Propagate up: a subtree at (level L, index_at_level k) is newly
	// completed iff (n+1) is divisible by 2^L. Walk from L=1 upward
	// while that holds, combining the just-finished right half with
	// the existing left sibling at one level down.
	completed := n + 1
	rightHash := leafHash
	rightIdx := n
	for level := uint64(1); ; level++ {
		if completed%(uint64(1)<<level) != 0 {
			break
		}
		leftIdx := rightIdx - 1
		var leftHash []byte
		if err := tx.QueryRowContext(ctx,
			`SELECT hash FROM translog_nodes WHERE chain_id = ? AND level = ? AND index_at_level = ?`,
			chainID, int64(level-1), int64(leftIdx),
		).Scan(&leftHash); err != nil {
			return translog.STH{}, fmt.Errorf("appendLeafTx: missing left sibling at (level=%d, idx=%d): %w", level-1, leftIdx, err)
		}
		parentHash := translog.NodeHash(leftHash, rightHash)
		parentIdx := rightIdx / 2
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO translog_nodes (chain_id, level, index_at_level, hash) VALUES (?, ?, ?, ?)`,
			chainID, int64(level), int64(parentIdx), parentHash,
		); err != nil {
			return translog.STH{}, err
		}
		rightHash = parentHash
		rightIdx = parentIdx
	}

	// Compute the canonical RFC 6962 root for tree size `completed`.
	rootHash, err := s.nodeHashTx(ctx, tx, chainID, 0, completed)
	if err != nil {
		return translog.STH{}, err
	}

	head := translog.TreeHead{
		ChainID:   chainID,
		TreeSize:  completed,
		RootHash:  rootHash,
		Timestamp: now,
	}
	sth, err := translog.SignSTH(s.translogPriv, head)
	if err != nil {
		return translog.STH{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO translog_sths (chain_id, tree_size, root_hash, timestamp, signature) VALUES (?, ?, ?, ?, ?)`,
		chainID, int64(sth.Head.TreeSize), sth.Head.RootHash, int64(sth.Head.Timestamp), sth.Signature,
	); err != nil {
		return translog.STH{}, err
	}
	return sth, nil
}

// SignServerInfo issues a fresh ServerInfo record signed by the
// translog key. The HTTP layer publishes this at /v1/server-info
// and clients pin the embedded pubkey on first contact (TRANSLOG.md
// §6.1). Keeps the priv key on the Store; HTTP layer only handles the
// resulting bytes.
//
// label is the operator-declared self-label for this server (empty when
// FD0_LABEL isn't set; caller is responsible for [a-z0-9-]{0,32}
// validation). peers is the current resolved-peer snapshot — pass nil
// for a solo server.
func (s *Store) SignServerInfo(now uint64, label string, peers []translog.PeerInfo) (translog.ServerInfo, error) {
	if s.translogPriv == nil {
		return translog.ServerInfo{}, ErrTranslogKeyMissing
	}
	return translog.SignServerInfo(s.translogPriv, now, label, peers)
}

// ProofsForChain assembles, in a single read transaction:
//   - the current STH for chainID
//   - one inclusion proof per element of leafIndices, against the
//     current STH's tree_size
//   - optionally the consistency proof from lastSTHSize → current
//
// All retrieval shares one CurrentSTH read and one snapshot of
// translog_nodes. Avoids the 1×CurrentSTH + N×InclusionProofFor + 1×
// ConsistencyProofFor round-trip storm that the previous server-side
// helper inflicted (codex review C3 #6).
//
// Behaviour for `lastSTHSize`:
//   - 0: omit consistency proof (client has no anchor yet).
//   - > 0 and <= current: include consistency proof (empty Nodes when
//     equal to current — TRANSLOG.md §5.4 mandates "present iff
//     last_sth_size > 0").
//   - > current: ErrIndexOutOfRange (client claims a future tree state
//     the server hasn't published).
func (s *Store) ProofsForChain(ctx context.Context, chainID string, leafIndices []uint64, lastSTHSize uint64) (*translog.STH, []translog.InclusionProof, *translog.ConsistencyProof, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()

	// CurrentSTH — read once for the rest of this call.
	row := tx.QueryRowContext(ctx,
		`SELECT tree_size, root_hash, timestamp, signature
		   FROM translog_sths
		  WHERE chain_id = ?
		  ORDER BY tree_size DESC LIMIT 1`, chainID,
	)
	sth, err := scanSTH(chainID, row)
	if err != nil {
		return nil, nil, nil, err
	}
	if lastSTHSize > sth.Head.TreeSize {
		return nil, nil, nil, ErrIndexOutOfRange
	}
	// Inclusion proofs.
	incs := make([]translog.InclusionProof, 0, len(leafIndices))
	for _, idx := range leafIndices {
		if idx >= sth.Head.TreeSize {
			return nil, nil, nil, ErrIndexOutOfRange
		}
		path, err := s.proofPathTx(ctx, tx, chainID, idx, 0, sth.Head.TreeSize)
		if err != nil {
			return nil, nil, nil, err
		}
		incs = append(incs, translog.InclusionProof{
			LeafIndex: idx,
			TreeSize:  sth.Head.TreeSize,
			AuditPath: path,
		})
	}
	// Consistency proof. lastSTHSize > 0 → always present (per spec
	// "iff supplied last_sth_size > 0"); for equality with current
	// the proof is the trivial empty list.
	var cons *translog.ConsistencyProof
	if lastSTHSize > 0 {
		var nodes [][]byte
		if lastSTHSize < sth.Head.TreeSize {
			nodes, err = s.subproofTx(ctx, tx, chainID, lastSTHSize, 0, sth.Head.TreeSize, true)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		cons = &translog.ConsistencyProof{
			FromSize: lastSTHSize,
			ToSize:   sth.Head.TreeSize,
			Nodes:    nodes,
		}
	}
	return &sth, incs, cons, nil
}

// EventSeqByID looks up an event's seq by content-addressed event_id.
// Used by the push-dup path to populate the InclusionProof leaf_index
// without re-decoding the request body.
func (s *Store) EventSeqByID(ctx context.Context, eventID string) (uint64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx, `SELECT seq FROM events WHERE event_id = ?`, eventID).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	return uint64(seq), nil
}

// CurrentSTH returns the most recent STH for chainID. Returns
// ErrNotFound if the chain has no STHs yet (= empty / no leaves).
func (s *Store) CurrentSTH(ctx context.Context, chainID string) (translog.STH, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tree_size, root_hash, timestamp, signature
		   FROM translog_sths
		  WHERE chain_id = ?
		  ORDER BY tree_size DESC LIMIT 1`, chainID,
	)
	return scanSTH(chainID, row)
}

// STHAt returns the STH that was signed when the tree had exactly
// treeSize leaves. Used by witness backfill (TRANSLOG.md §10).
// Returns ErrNotFound if no STH was ever signed at that size.
func (s *Store) STHAt(ctx context.Context, chainID string, treeSize uint64) (translog.STH, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tree_size, root_hash, timestamp, signature
		   FROM translog_sths WHERE chain_id = ? AND tree_size = ?`,
		chainID, int64(treeSize),
	)
	return scanSTH(chainID, row)
}

// InclusionProofFor returns the audit path proving the leaf at
// `leafIndex` is in chainID's tree of `treeSize` leaves. The returned
// slice is the leaf-to-root sibling path (RFC 6962 §2.1.1 PATH).
//
// Errors:
//   - ErrIndexOutOfRange if leafIndex >= treeSize or treeSize > current size.
//   - ErrNotFound if the chain has no events.
func (s *Store) InclusionProofFor(ctx context.Context, chainID string, leafIndex, treeSize uint64) ([][]byte, error) {
	current, err := s.currentTreeSize(ctx, chainID)
	if err != nil {
		return nil, err
	}
	if treeSize == 0 || leafIndex >= treeSize || treeSize > current {
		return nil, ErrIndexOutOfRange
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return s.proofPathTx(ctx, tx, chainID, leafIndex, 0, treeSize)
}

// ConsistencyProofFor returns the proof that chainID's tree at
// `oldSize` is a prefix of the tree at `newSize`. RFC 6962 §2.1.2.
//
// Returns:
//   - empty slice for oldSize == 0 (any tree is consistent with empty)
//     and for oldSize == newSize (trees are equal).
//   - ErrIndexOutOfRange if oldSize > newSize or newSize > current size.
//   - ErrNotFound if the chain has no events.
func (s *Store) ConsistencyProofFor(ctx context.Context, chainID string, oldSize, newSize uint64) ([][]byte, error) {
	current, err := s.currentTreeSize(ctx, chainID)
	if err != nil {
		return nil, err
	}
	if oldSize > newSize || newSize > current {
		return nil, ErrIndexOutOfRange
	}
	if oldSize == 0 || oldSize == newSize {
		return nil, nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return s.subproofTx(ctx, tx, chainID, oldSize, 0, newSize, true)
}

// ErrIndexOutOfRange is returned by proof functions when the requested
// index/size is outside the current tree.
var ErrIndexOutOfRange = errors.New("translog: index out of range")

// ---- helpers ----

// currentTreeSize returns the current leaf count for chainID. Returns
// (0, ErrNotFound) if the chain has no leaves.
func (s *Store) currentTreeSize(ctx context.Context, chainID string) (uint64, error) {
	var n uint64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM translog_nodes WHERE chain_id = ? AND level = 0`, chainID,
	).Scan(&n); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, ErrNotFound
	}
	return n, nil
}

// nodeHashTx returns the canonical RFC 6962 hash for the subtree
// spanning leaves [start, end) on chainID. Reads precomputed hashes
// from translog_nodes when [start, end) is a complete aligned subtree;
// recurses otherwise.
//
// Recursion bottoms out at single leaves (n=1). For typical fd0 chain
// sizes (≤ thousands), the worst case (a fully-unbalanced right spine)
// is bounded by O(n) NodeHash operations — well within request budget.
func (s *Store) nodeHashTx(ctx context.Context, tx *sql.Tx, chainID string, start, end uint64) ([]byte, error) {
	n := end - start
	if n == 0 {
		return translog.EmptyRoot(), nil
	}
	if n == 1 {
		return s.fetchNodeTx(ctx, tx, chainID, 0, start)
	}
	// Complete aligned subtree shortcut.
	if isPowerOfTwo(n) && start%n == 0 {
		level := log2u(n)
		idx := start / n
		h, err := s.fetchNodeTx(ctx, tx, chainID, level, idx)
		if err == nil {
			return h, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		// Not stored — fall through to recursion. (Should only happen
		// for the root-level subtree on a power-of-two-sized tree
		// where AppendLeaf stops just shy of inserting the final root,
		// but defensive recursion is cheap.)
	}
	k := largestPowerOfTwoLessThan(n)
	leftHash, err := s.nodeHashTx(ctx, tx, chainID, start, start+k)
	if err != nil {
		return nil, err
	}
	rightHash, err := s.nodeHashTx(ctx, tx, chainID, start+k, end)
	if err != nil {
		return nil, err
	}
	return translog.NodeHash(leftHash, rightHash), nil
}

// proofPathTx builds the leaf-to-root sibling path for `m` (target
// leaf index) within the leaf range [start, end). Mirrors RFC 6962
// PATH(m, D[n]).
func (s *Store) proofPathTx(ctx context.Context, tx *sql.Tx, chainID string, m, start, end uint64) ([][]byte, error) {
	n := end - start
	if n == 1 {
		return nil, nil
	}
	k := largestPowerOfTwoLessThan(n)
	relIndex := m - start
	if relIndex < k {
		// Target in left subtree; sibling is the right subtree.
		sub, err := s.proofPathTx(ctx, tx, chainID, m, start, start+k)
		if err != nil {
			return nil, err
		}
		sib, err := s.nodeHashTx(ctx, tx, chainID, start+k, end)
		if err != nil {
			return nil, err
		}
		return append(sub, sib), nil
	}
	// Target in right subtree; sibling is the left subtree.
	sub, err := s.proofPathTx(ctx, tx, chainID, m, start+k, end)
	if err != nil {
		return nil, err
	}
	sib, err := s.nodeHashTx(ctx, tx, chainID, start, start+k)
	if err != nil {
		return nil, err
	}
	return append(sub, sib), nil
}

// subproofTx implements RFC 6962 SUBPROOF(m, D[n], b) over the leaf
// range [start, end). Used by ConsistencyProofFor.
func (s *Store) subproofTx(ctx context.Context, tx *sql.Tx, chainID string, m, start, end uint64, b bool) ([][]byte, error) {
	n := end - start
	if m == n {
		if b {
			return nil, nil
		}
		h, err := s.nodeHashTx(ctx, tx, chainID, start, end)
		if err != nil {
			return nil, err
		}
		return [][]byte{h}, nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		sub, err := s.subproofTx(ctx, tx, chainID, m, start, start+k, b)
		if err != nil {
			return nil, err
		}
		sib, err := s.nodeHashTx(ctx, tx, chainID, start+k, end)
		if err != nil {
			return nil, err
		}
		return append(sub, sib), nil
	}
	sub, err := s.subproofTx(ctx, tx, chainID, m-k, start+k, end, false)
	if err != nil {
		return nil, err
	}
	sib, err := s.nodeHashTx(ctx, tx, chainID, start, start+k)
	if err != nil {
		return nil, err
	}
	return append(sub, sib), nil
}

// fetchNodeTx loads one node from translog_nodes; returns ErrNotFound
// if it's missing.
func (s *Store) fetchNodeTx(ctx context.Context, tx *sql.Tx, chainID string, level, indexAtLevel uint64) ([]byte, error) {
	var h []byte
	err := tx.QueryRowContext(ctx,
		`SELECT hash FROM translog_nodes WHERE chain_id = ? AND level = ? AND index_at_level = ?`,
		chainID, int64(level), int64(indexAtLevel),
	).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return h, err
}

// scanSTH builds an STH from a row of (tree_size, root_hash, timestamp, signature).
// The chain_id is supplied separately (not part of the row) so the STH's
// embedded TreeHead.ChainID matches the query input.
func scanSTH(chainID string, row *sql.Row) (translog.STH, error) {
	var (
		size      int64
		rootHash  []byte
		ts        int64
		signature []byte
	)
	if err := row.Scan(&size, &rootHash, &ts, &signature); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return translog.STH{}, ErrNotFound
		}
		return translog.STH{}, err
	}
	return translog.STH{
		Head: translog.TreeHead{
			ChainID:   chainID,
			TreeSize:  uint64(size),
			RootHash:  rootHash,
			Timestamp: uint64(ts),
		},
		Signature: signature,
	}, nil
}

// isPowerOfTwo and log2u are tiny helpers — kept here so the storage
// layer doesn't depend on internal pure-layer helpers (those live in
// translog/proof.go and are not exported).
func isPowerOfTwo(n uint64) bool { return n > 0 && (n&(n-1)) == 0 }

// log2u returns the floor(log2(n)) for n > 0. Caller must ensure n > 0.
// Used only when n is a power of two, where it's exact.
func log2u(n uint64) uint64 {
	var L uint64
	for n > 1 {
		n >>= 1
		L++
	}
	return L
}

// largestPowerOfTwoLessThan returns the largest power of two strictly
// less than n. Defined for n ≥ 2 (caller's responsibility).
func largestPowerOfTwoLessThan(n uint64) uint64 {
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

