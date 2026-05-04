package proto

import (
	"errors"
	"fmt"
)

// ScopeID is a validated scope identifier per STORAGE.md / PROTOCOL.md
// §1.3 — exactly "s_" followed by 26 chars in [a-z2-7] (lowercase RFC
// 4648 base32, no padding), 28 chars total.
//
// OPAQUE struct rather than `type ScopeID string` so that the only
// way to obtain a non-zero value is through ParseScopeID (validates
// untrusted input) or DeriveScopeID (protocol-derived, valid by
// construction). A direct conversion `ScopeID(rawString)` does not
// compile — codex review (Wave C-1) flagged the soft-newtype as
// bypass-able since any package could cast around the validator.
//
// Internal pass-through is a value copy; comparisons via `==` work
// because the only field is comparable. Map keys work for the same
// reason. Format-string sites use the String() method implicitly.
//
// Custom CBOR marshallers are intentionally NOT defined — ScopeID
// is not directly serialised on the wire (SignedPrefix.Scope is
// *string, the CBOR text-string form is used as-is), and any future
// at-rest encoding should validate via ParseScopeID at decode.
type ScopeID struct {
	s string
}

// ParseScopeID validates and wraps an untrusted scope id. Returns an
// error if `s` is not exactly 28 chars and does not match the
// `s_[a-z2-7]{26}` shape. The empty string is rejected (vs. the
// "absent" sentinel of `ScopeID{}` / `IsZero` true for unset values).
func ParseScopeID(s string) (ScopeID, error) {
	if !ValidScopeIDShape(s) {
		return ScopeID{}, fmt.Errorf("invalid scope id %q (must match s_[a-z2-7]{26})", s)
	}
	return ScopeID{s: s}, nil
}

// MustParseScopeID is the panicking variant for tests + protocol-derived
// strings (where the shape is guaranteed by construction). NEVER call
// this on untrusted input — use ParseScopeID and propagate the error.
func MustParseScopeID(s string) ScopeID {
	id, err := ParseScopeID(s)
	if err != nil {
		panic(err)
	}
	return id
}

// String returns the underlying canonical form. The fmt package picks
// this up automatically for %s and %v.
func (id ScopeID) String() string { return id.s }

// IsZero reports whether the ScopeID is the unset sentinel (== ScopeID{}).
// Useful at boundaries where an "absent" scope is meaningful — e.g. the
// genesis-event scope is *ScopeID == nil; a present-but-empty ScopeID is
// distinct.
func (id ScopeID) IsZero() bool { return id.s == "" }

// ScopePtr returns a *string pointer wrapping id's underlying form.
// Used by event builders that mark genesis events with a nil pointer
// (PROTOCOL.md §4.1) and successor events with a non-nil pointer to
// the binding scope id. The wire form is a CBOR text string —
// keeping SignedPrefix.Scope as *string avoids rippling the type
// through the CBOR layer and downstream verifiers (server, witness,
// older clients). The wire schema is unchanged.
func ScopePtr(id ScopeID) *string {
	s := id.s
	return &s
}

// ValidScopeIDShape reports whether s matches the canonical
// `s_[a-z2-7]{26}` shape. Pure check — no side effects, no allocation.
// Exposed so the legacy `fdhome.ValidScopeID` predicate can delegate
// here and so server-side validators can reject malformed inputs
// before any path-join.
func ValidScopeIDShape(s string) bool {
	if len(s) != 28 || s[0] != 's' || s[1] != '_' {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '2' && c <= '7':
		default:
			return false
		}
	}
	return true
}

// ErrEmptyScopeID is returned by helpers that resolve a *ScopeID
// expected to be non-nil at the call site (e.g. successor-event scope
// fields). Genesis events legitimately carry *ScopeID == nil; callers
// that want to distinguish "absent" from "invalid shape" should check
// the pointer first and delegate the shape check to ValidScopeIDShape.
var ErrEmptyScopeID = errors.New("empty scope id")
