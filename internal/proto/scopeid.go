package proto

import (
	"errors"
	"fmt"
)

// ScopeID is a validated scope identifier per STORAGE.md / PROTOCOL.md
// §1.3 — exactly "s_" followed by 26 chars in [a-z2-7] (lowercase RFC
// 4648 base32, no padding), 28 chars total.
//
// Newtype rather than raw string so the compiler can enforce
// "must come from ParseScopeID or DeriveScopeID" at API boundaries
// where a path-traversal segment or other unvalidated string would
// otherwise be silently accepted (e.g. fdhome.ScopeChain ⇒ joining
// `../etc/passwd` into the chain dir).
//
// Internal value-pass-through and CBOR/JSON wire encoding treat
// ScopeID as its underlying string. Map keys, sort orders and
// comparisons all behave identically to string. Custom marshallers
// are intentionally NOT defined — the wire format is a plain string,
// and named-string types serialise as the underlying value.
type ScopeID string

// ParseScopeID validates and wraps an untrusted scope id. Returns an
// error if `s` is not exactly 28 chars and does not match the
// `s_[a-z2-7]{26}` shape. The empty string is rejected (vs. the
// nil-ScopeID convention of `*ScopeID == nil` for genesis events).
func ParseScopeID(s string) (ScopeID, error) {
	if !ValidScopeIDShape(s) {
		return "", fmt.Errorf("invalid scope id %q (must match s_[a-z2-7]{26})", s)
	}
	return ScopeID(s), nil
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

// String returns the underlying canonical form. Equivalent to
// `string(id)` but reads more clearly at format-string call sites.
func (id ScopeID) String() string { return string(id) }

// ScopePtr returns a *string pointer wrapping id. Used by event
// builders that mark genesis events with a nil pointer (PROTOCOL.md
// §4.1) and successor events with a non-nil pointer to the binding
// scope id. The wire form is the underlying string — keeping
// SignedPrefix.Scope as *string avoids rippling the type rename
// through the CBOR layer and downstream verifiers.
func ScopePtr(id ScopeID) *string {
	s := string(id)
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
