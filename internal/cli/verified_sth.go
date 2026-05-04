package cli

// VerifiedSTH is a type-state wrapper for a translog STH that has
// been verified by VerifyAndCrossCheck (signature OK, inclusion
// proofs OK, consistency proof against any prior anchor OK,
// witness cross-check OK if the policy demanded it).
//
// Wave D motivation: every "advance LastSTH" path must be preceded
// by a successful verify. Past audits found three sites where the
// caller's verify error was checked, but the persistence step then
// re-extracted ps.STH or r.STH from the response and bypassed the
// post-verification typed value — a refactor could plausibly
// reorder operations so the encode runs against an unverified
// STH. With the type-state, EncodeSTH is gated on a value the
// caller can only obtain from a successful Verify call.
//
// The struct field is unexported and the type has no exported
// constructor, so user code outside this package cannot fabricate
// a VerifiedSTH. The two construction paths inside the package:
//
//   - newVerifiedSTH(sth) — called by VerifyAndCrossCheck after
//     all per-pulled-leaf and consistency checks pass
//   - decodeVerifiedSTH(bytes) — called when reading sd.LastSTH
//     from the sealed vault (which was itself written from a
//     successful verify in a prior round, so vault contents are
//     trusted by induction)
import (
	"errors"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// verifiedToken is the sealing sentinel addressed by codex review of
// Wave D. The struct field carrying it is unexported (lowercase
// `seal`), and the only constructor that initialises it lives
// inside this package. A composite literal `cli.VerifiedSTH{}`
// constructed elsewhere therefore has seal.ok == false; EncodeSTH
// rejects such forged tokens at runtime. Without the sentinel,
// `cli.VerifiedSTH{}` would compile across package boundaries and
// the type-state would only be a soft hint.
type verifiedToken struct{ ok bool }

// VerifiedSTH carries a translog.STH that has cleared every
// signature, inclusion-proof, consistency-proof, and witness
// cross-check gate enforced by VerifyAndCrossCheck. The only paths
// to a non-zero VerifiedSTH are via that function (fresh verify) or
// decodeVerifiedSTH (reading from a sealed vault that previously
// stored a verified value).
//
// Wire-format note: VerifiedSTH itself is NEVER serialised to disk
// — only the wrapped STH is. The "verified" state is a runtime
// invariant for the lifetime of the value.
//
// Codex review fix: byte slices inside the wrapped STH are deep-
// copied at construction so post-verify mutations of the source
// (the server response struct) cannot retroactively change the
// bytes that EncodeSTH will eventually marshal.
type VerifiedSTH struct {
	sth  translog.STH
	seal verifiedToken
}

// errUnsealedVerifiedSTH is returned by EncodeSTH when called with
// a value that did NOT originate from a package-internal
// constructor (newVerifiedSTH / decodeVerifiedSTH). Such values
// have seal.ok == false — the empty composite literal escape from
// across package boundaries.
var errUnsealedVerifiedSTH = errors.New("VerifiedSTH: forged token (must come from VerifyAndCrossCheck)")

// STH returns a deep copy of the underlying translog.STH. The deep
// copy ensures a caller mutating the returned value (or its byte
// slices) cannot retroactively poison the verified state held by
// VerifiedSTH itself.
func (v VerifiedSTH) STH() translog.STH { return cloneSTH(v.sth) }

// TreeSize is a convenience accessor — the most-frequently-read
// field across sync paths (LastSTH max-tracking, push consistency
// anchors).
func (v VerifiedSTH) TreeSize() uint64 { return v.sth.Head.TreeSize }

// IsZero reports whether v carries the zero translog.STH (no
// verification has ever happened on this value). Useful for
// optional-anchor parameters in pull/push verify calls.
func (v VerifiedSTH) IsZero() bool {
	return v.sth.Head.TreeSize == 0 && len(v.sth.Signature) == 0
}

// newVerifiedSTH wraps an STH that has just cleared every gate in
// VerifyAndCrossCheck. Package-private; the only legitimate caller
// is VerifyAndCrossCheck itself. Sets the seal sentinel and
// deep-clones byte slices so the wrapped value is independent of
// the source.
func newVerifiedSTH(sth translog.STH) *VerifiedSTH {
	return &VerifiedSTH{sth: cloneSTH(sth), seal: verifiedToken{ok: true}}
}

// decodeVerifiedSTH parses a CBOR-encoded STH from the vault and
// wraps it as VerifiedSTH. The trust assumption is that anything
// in s.Body.LastSTH was placed there by a previous successful
// VerifyAndCrossCheck call (vault contents are sealed by the
// agent's master key; corruption causes a separate decode error).
//
// Returns (nil, nil) on empty input — used to mean "no anchor yet".
// Caller must check for nil before using.
func decodeVerifiedSTH(b []byte) (*VerifiedSTH, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var sth translog.STH
	if err := proto.Unmarshal(b, &sth); err != nil {
		return nil, err
	}
	// Unmarshal already produced a fresh allocation; no extra clone
	// needed, but the seal must still be set so EncodeSTH accepts.
	return &VerifiedSTH{sth: sth, seal: verifiedToken{ok: true}}, nil
}

// cloneSTH returns a deep copy of an STH (independent byte slices
// for RootHash and Signature). Inexpensive — both slices are
// hash-sized.
func cloneSTH(s translog.STH) translog.STH {
	out := translog.STH{
		Head: translog.TreeHead{
			ChainID:   s.Head.ChainID,
			TreeSize:  s.Head.TreeSize,
			Timestamp: s.Head.Timestamp,
		},
		Signature: append([]byte(nil), s.Signature...),
	}
	out.Head.RootHash = append([]byte(nil), s.Head.RootHash...)
	return out
}
