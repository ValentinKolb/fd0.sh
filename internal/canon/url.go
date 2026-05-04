// Package canon holds canonicalised forms of values that flow across
// trust boundaries — server URLs, scope identifiers, etc. — wrapped
// in opaque types whose only constructors validate the input.
//
// Wave C-2 motivation: the URL drift bug class
// (sync ↔ witness ↔ pinning lookup all expecting the same canonical
// form, but built ad-hoc with subtly different normalisation) was
// recurring in past audits. By exposing a single Parse function that
// runs the canonical normalisation, every entry point at the type
// boundary produces a value other code can compare bit-for-bit.
package canon

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// URL is a canonicalised server URL. The zero value is invalid;
// values must be obtained from ParseURL (validates + normalises) or
// MustParseURL (panics on failure — for protocol-derived inputs and
// tests).
//
// Canonical form per FD0 conventions:
//   - lowercase scheme
//   - lowercase host (RFC 3986 §3.2.2)
//   - trailing slash stripped from the path
//   - query and fragment are dropped (a server endpoint URL must not
//     carry these)
//
// Two visually different inputs that name the same logical server
// (e.g. "HTTPS://Example.COM/" vs "https://example.com") therefore
// produce a byte-identical URL value. Map keys, equality checks
// across sync / witness / pin layers all line up.
type URL struct {
	s string
}

// ParseURL canonicalises and wraps an untrusted server URL. Returns
// an error if the input is empty, unparseable, missing the scheme or
// host. The returned URL is the byte-stable canonical form.
func ParseURL(raw string) (URL, error) {
	if raw == "" {
		return URL{}, errors.New("server URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return URL{}, fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return URL{}, fmt.Errorf("server URL must include scheme and host: %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return URL{s: u.String()}, nil
}

// MustParseURL panics on validation failure. Use only for inputs the
// caller can guarantee are valid (e.g. compiled-in defaults, test
// fixtures); never on operator-supplied strings.
func MustParseURL(raw string) URL {
	u, err := ParseURL(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// String returns the canonical form. fmt picks this up for %s/%v.
func (u URL) String() string { return u.s }

// IsZero reports whether u is the zero value (no URL was ever
// constructed). Useful at boundaries where a nil-like sentinel is
// meaningful.
func (u URL) IsZero() bool { return u.s == "" }

// JoinPath appends a path suffix to the canonical URL and returns the
// concatenated string. Use this instead of `u.String() + "/foo"` so
// the join logic is centralised — extra trailing slashes never sneak
// in. Example: `u.JoinPath("/sync")` → "https://server.example/sync".
func (u URL) JoinPath(suffix string) string {
	if suffix == "" {
		return u.s
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return u.s + suffix
}
