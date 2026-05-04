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
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// VerifiedSTH carries a translog.STH that has cleared every
// signature, inclusion-proof, consistency-proof, and witness
// cross-check gate enforced by VerifyAndCrossCheck. The only paths
// to a VerifiedSTH are via that function (fresh verify) or
// decodeVerifiedSTH (reading from a sealed vault that previously
// stored a verified value).
//
// Wire-format note: VerifiedSTH itself is NEVER serialised to disk
// — only the wrapped STH is. The "verified" state is a runtime
// invariant for the lifetime of the value.
type VerifiedSTH struct {
	sth translog.STH
}

// STH returns the underlying translog.STH. Caller may inspect the
// fields freely but should NOT round-trip the value back into a new
// VerifiedSTH — the wrapper reflects a verification that took
// place at a specific moment, and any post-mutation requires a
// fresh Verify call.
func (v VerifiedSTH) STH() translog.STH { return v.sth }

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
// is VerifyAndCrossCheck itself.
func newVerifiedSTH(sth translog.STH) *VerifiedSTH {
	return &VerifiedSTH{sth: sth}
}

// decodeVerifiedSTH parses a CBOR-encoded STH from the vault and
// wraps it as VerifiedSTH. The trust assumption is that anything
// in s.Body.LastSTH was placed there by a previous successful
// VerifyAndCrossCheck call (vault contents are sealed by the
// agent's master key; corruption causes a separate decode error).
//
// Returns (nil, nil) on empty input — the legacy behaviour of
// DecodeSTH, used to mean "no anchor yet". Caller must check for
// nil before using.
func decodeVerifiedSTH(b []byte) (*VerifiedSTH, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var sth translog.STH
	if err := proto.Unmarshal(b, &sth); err != nil {
		return nil, err
	}
	return &VerifiedSTH{sth: sth}, nil
}
