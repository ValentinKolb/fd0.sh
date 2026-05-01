// Package translog implements the per-chain Merkle transparency log defined
// in TRANSLOG.md. It is purely cryptographic: hashing, RFC 6962 inclusion
// and consistency proofs, STH (signed tree head) construction, and STH
// signature verification. No I/O, no SQLite, no HTTP — those live in
// translog/store and the server package.
//
// The package is consumed by:
//   - the fd0-server, which builds trees incrementally and signs STHs;
//   - the fd0 client, which verifies inclusion and consistency proofs
//     received over the wire and persists the latest STH per chain;
//   - the fd0-witness, which fetches and archives STHs from a server URL,
//     verifying signatures and consistency between successive STHs.
//
// The seam between this package and translog/store is intentional: the
// pure layer is fully testable with fixed vectors (RFC 6962 §2.1.4 has
// canonical test vectors we adapt below), while the storage layer can
// evolve (in-memory → SQLite → other backends) without disturbing the
// crypto.
package translog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// HashSize is the byte length of every hash produced by this package.
// SHA-256 throughout; matches the chain-internal prev_hash size so leaf
// inputs need no length conversion.
const HashSize = 32

// LeafHash returns the leaf hash for an event whose canonical 32-byte
// content hash is `eventHash`. Per TRANSLOG.md §3.1:
//
//	leaf_hash = SHA-256("fd0-translog-leaf-v1" || eventHash)
//
// `eventHash` is the same 32-byte SHA-256 over the event's PrevHashInput()
// that drives prev_hash linking — uniform across UserEvent and ScopeEvent.
// Use LeafHashOfPrevInput when you have the canonical body bytes; use
// LeafHash directly when you already hold the 32-byte hash.
func LeafHash(eventHash []byte) []byte {
	if len(eventHash) != HashSize {
		// Refuse rather than silently truncate/pad. Callers should pass a
		// SHA-256 digest; anything else is a programming error.
		panic("translog.LeafHash: eventHash must be 32 bytes")
	}
	h := sha256.New()
	h.Write([]byte(proto.DomainTranslogLeaf))
	h.Write(eventHash)
	return h.Sum(nil)
}

// LeafHashOfPrevInput is a convenience that hashes `prevInput` (the same
// bytes returned by ScopeEvent.PrevHashInput / UserEvent.PrevHashInput)
// and applies LeafHash. Centralising the SHA-256 step here makes it
// impossible for a caller to forget either step or re-order them.
func LeafHashOfPrevInput(prevInput []byte) []byte {
	inner := sha256.Sum256(prevInput)
	return LeafHash(inner[:])
}

// NodeHash returns the inner-node hash combining two children. Per
// TRANSLOG.md §3.1:
//
//	node_hash = SHA-256("fd0-translog-node-v1" || left || right)
//
// `left` and `right` MUST each be HashSize bytes; mismatched lengths panic
// (programming error, not a runtime concern).
func NodeHash(left, right []byte) []byte {
	if len(left) != HashSize || len(right) != HashSize {
		panic("translog.NodeHash: child hashes must be 32 bytes each")
	}
	h := sha256.New()
	h.Write([]byte(proto.DomainTranslogNode))
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// EmptyRoot returns the canonical root hash of a tree with zero leaves.
// Per TRANSLOG.md §3.1, this uses its own domain so it is distinguishable
// from any leaf or node hash:
//
//	empty_root = SHA-256("fd0-translog-empty-v1")
//
// Returned as a fresh slice; the caller may mutate freely.
func EmptyRoot() []byte {
	h := sha256.Sum256([]byte(proto.DomainTranslogEmpty))
	return h[:]
}

// MerkleTreeHash returns the root hash of the RFC 6962 Merkle tree built
// over `leafHashes` (each must be HashSize bytes — pre-hashed via
// LeafHash or LeafHashOfPrevInput). Returns EmptyRoot() for the empty
// input.
//
// The tree shape: for n > 1 leaves, split at the largest power of two
// strictly less than n; recurse on the two halves; combine with NodeHash.
// O(n) time, O(log n) recursion depth.
//
// This function is not used in the server's hot path (the server builds
// trees incrementally — see translog/store). It is the canonical
// reference for tests and for any caller that has the full leaf list.
func MerkleTreeHash(leafHashes [][]byte) []byte {
	n := uint64(len(leafHashes))
	if n == 0 {
		return EmptyRoot()
	}
	if n == 1 {
		return append([]byte(nil), leafHashes[0]...)
	}
	k := largestPowerOfTwoLessThan(n)
	left := MerkleTreeHash(leafHashes[:k])
	right := MerkleTreeHash(leafHashes[k:])
	return NodeHash(left, right)
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less
// than n. Defined for n ≥ 2.
//
// Used by both the tree-shape constructor and the inclusion / consistency
// proof algorithms. Sharing one implementation keeps "what is the split
// point" consistent across the file.
func largestPowerOfTwoLessThan(n uint64) uint64 {
	if n < 2 {
		panic("largestPowerOfTwoLessThan: n must be ≥ 2")
	}
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// TreeHead is the unsigned summary of a chain's Merkle tree at one
// instant. The signature in STH binds these four fields. Wire format
// follows TRANSLOG.md §3.2.
type TreeHead struct {
	ChainID   string `cbor:"chain_id"`
	TreeSize  uint64 `cbor:"tree_size"`
	RootHash  []byte `cbor:"root_hash"`
	Timestamp uint64 `cbor:"timestamp"`
}

// STH is a TreeHead with a server signature. Wire format follows
// TRANSLOG.md §3.3.
type STH struct {
	Head      TreeHead `cbor:"head"`
	Signature []byte   `cbor:"signature"`
}

// SignedInput returns the bytes that the server signs (and that the
// verifier reconstructs) for an STH:
//
//	"fd0-translog-sth-v1" || cbor(head)
//
// The CBOR encoding is deterministic per RFC 8949 §4.2.1, so server and
// verifier agree byte-for-byte without negotiating an encoding.
func (h *TreeHead) SignedInput() ([]byte, error) {
	body, err := proto.Marshal(h)
	if err != nil {
		return nil, err
	}
	return append([]byte(proto.DomainTranslogSTH), body...), nil
}

// SignSTH constructs and signs an STH for `head` using `priv`. The
// returned STH is wire-ready.
//
// The function does not validate `head` semantically (e.g., that
// RootHash matches a real tree). The caller — usually the storage layer
// in translog/store — is responsible for building head from a real
// incremental tree state. SignSTH is purely the cryptographic step.
func SignSTH(priv ed25519.PrivateKey, head TreeHead) (STH, error) {
	si, err := head.SignedInput()
	if err != nil {
		return STH{}, err
	}
	sig := ed25519.Sign(priv, si)
	return STH{Head: head, Signature: sig}, nil
}

// VerifySTH checks an STH's signature under `pub` AND validates the head
// for structural consistency (root-hash length, the size=0 ⇔
// root=EmptyRoot binding). Either failure mode is observable as the
// returned sentinel error.
//
// We bundle the structural checks into VerifySTH (rather than asking
// callers to call ValidateTreeHead first) because every consumer wants
// both — separating them invites a future caller to verify the
// signature alone and trust a malformed head.
func VerifySTH(pub ed25519.PublicKey, sth STH) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("translog.VerifySTH: pub must be 32 bytes")
	}
	if err := ValidateTreeHead(sth.Head); err != nil {
		return err
	}
	if len(sth.Signature) != ed25519.SignatureSize {
		return ErrSTHBadSignature
	}
	si, err := sth.Head.SignedInput()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, si, sth.Signature) {
		return ErrSTHBadSignature
	}
	return nil
}

// ValidateTreeHead checks the structural invariants on a TreeHead that
// every honest server is required to satisfy. Returns ErrSTHBadHead on
// failure. Used by VerifySTH and exposed for callers (witness binary)
// that want to validate a head independently.
//
// Checks:
//   - RootHash length == HashSize (rejects truncated / malformed STHs).
//   - tree_size ≤ maxTreeSize (RFC 6962 §3 limit; well above any real
//     deployment, but a sanity ceiling against pathological values).
//   - tree_size == 0 ⇔ RootHash == EmptyRoot(). Without this binding a
//     server could sign (size=0, root=anything) or (size=N, root=EmptyRoot)
//     and a naive verifier would not flag it.
func ValidateTreeHead(head TreeHead) error {
	if len(head.RootHash) != HashSize {
		return ErrSTHBadHead
	}
	if head.TreeSize > maxTreeSize {
		return ErrSTHBadHead
	}
	emptyR := EmptyRoot()
	rootIsEmpty := equalHashSlices(head.RootHash, emptyR)
	if head.TreeSize == 0 && !rootIsEmpty {
		return ErrSTHBadHead
	}
	if head.TreeSize > 0 && rootIsEmpty {
		return ErrSTHBadHead
	}
	return nil
}

// maxTreeSize is the inclusive upper bound on tree_size: 2^63 - 1.
// Two reasons for the bound (rather than the full uint64 range):
//   - Server-side storage uses SQLite INTEGER, which is signed 64-bit.
//     2^63 - 1 = SQLite INTEGER MAX; values above don't round-trip.
//   - The RFC 6962 / RFC 9162 verifier arithmetic on (fn, sn) shifts
//     down from size-1; capping below 2^64 - 1 leaves enough headroom
//     to never approach overflow.
//
// Any real chain growing one event per second saturates this in ~292
// billion years; the cap exists for sanity, not engineering need.
const maxTreeSize uint64 = (1 << 63) - 1

// equalHashSlices is a non-secret-comparison helper kept here (next to
// VerifySTH) so the file doesn't depend on proof.go for trivial bytes
// equality. Constant-time variant lives in proof.go.
func equalHashSlices(a, b []byte) bool {
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

// ServerInfo is the self-signed pubkey-publication record returned by
// GET /v1/server-info. Wire format follows TRANSLOG.md §4.2.
type ServerInfo struct {
	ServerPub []byte `cbor:"server_pub"`
	IssuedAt  uint64 `cbor:"issued_at"`
	Domain    string `cbor:"domain"`
	Signature []byte `cbor:"signature"`
}

// serverInfoSigned is the subset of ServerInfo whose CBOR encoding is the
// signature input. Domain and Signature are deliberately excluded —
// Domain is the prefix appended by SignedInput; Signature is what we are
// computing.
type serverInfoSigned struct {
	ServerPub []byte `cbor:"server_pub"`
	IssuedAt  uint64 `cbor:"issued_at"`
}

// SignServerInfo constructs and signs a ServerInfo record. The Domain
// field is set to proto.DomainTranslogServerInfo; the signature covers
// "fd0-translog-server-info-v1" || cbor({server_pub, issued_at}).
func SignServerInfo(priv ed25519.PrivateKey, issuedAt uint64) (ServerInfo, error) {
	pub := priv.Public().(ed25519.PublicKey)
	body, err := proto.Marshal(serverInfoSigned{
		ServerPub: pub,
		IssuedAt:  issuedAt,
	})
	if err != nil {
		return ServerInfo{}, err
	}
	si := append([]byte(proto.DomainTranslogServerInfo), body...)
	return ServerInfo{
		ServerPub: pub,
		IssuedAt:  issuedAt,
		Domain:    proto.DomainTranslogServerInfo,
		Signature: ed25519.Sign(priv, si),
	}, nil
}

// VerifyServerInfo checks that `info` is self-consistent: the embedded
// pubkey verifies the signature and the Domain field matches the
// expected constant. (No timestamp check — IssuedAt is informational
// metadata, not a security primitive.)
//
// Returns ErrServerInfoBadSignature on signature mismatch;
// ErrServerInfoBadDomain on a wrong / missing Domain field. The pinning
// ceremony (TRANSLOG.md §6.1) is the layer that decides whether to TRUST
// the embedded pubkey — this function only proves the record was authored
// by the holder of that key.
func VerifyServerInfo(info ServerInfo) error {
	if info.Domain != proto.DomainTranslogServerInfo {
		return ErrServerInfoBadDomain
	}
	if len(info.ServerPub) != ed25519.PublicKeySize {
		return ErrServerInfoBadSignature
	}
	if len(info.Signature) != ed25519.SignatureSize {
		return ErrServerInfoBadSignature
	}
	body, err := proto.Marshal(serverInfoSigned{
		ServerPub: info.ServerPub,
		IssuedAt:  info.IssuedAt,
	})
	if err != nil {
		return err
	}
	si := append([]byte(proto.DomainTranslogServerInfo), body...)
	if !ed25519.Verify(info.ServerPub, si, info.Signature) {
		return ErrServerInfoBadSignature
	}
	return nil
}

// Sentinel errors so callers can match without parsing strings.
var (
	ErrSTHBadHead             = errors.New("translog: malformed tree head (size/root binding violated)")
	ErrSTHBadSignature        = errors.New("translog: bad STH signature")
	ErrServerInfoBadSignature = errors.New("translog: bad server-info signature")
	ErrServerInfoBadDomain    = errors.New("translog: server-info wrong domain")
	ErrInclusionProofInvalid  = errors.New("translog: inclusion proof does not verify")
	ErrConsistencyProofInvalid = errors.New("translog: consistency proof does not verify")
	ErrIndexOutOfRange         = errors.New("translog: index out of range")
	ErrSizeRegression          = errors.New("translog: tree_size regression")
)
