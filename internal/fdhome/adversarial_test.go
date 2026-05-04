package fdhome

import (
	"path/filepath"
	"strings"
	"testing"
)

// Adversarial tests for fdhome — paths and config parsing. Covers
// the codex-found path-traversal bug and assorted config edge cases.

// TestAdvScopeChainRejectsPathTraversal locks the fdhome.go:51 fix:
// ScopeChain MUST validate scope_id against the spec pattern
// (s_[a-z2-7]{26}) before joining. Without this, a hostile peer
// or corrupted local index could feed `../../etc/passwd` and the
// returned path would escape p.Chains.
//
// Codex test audit: every case below MUST be REJECTED (return ""),
// not "accepted but inside p.Chains" — the spec doesn't allow any
// non-conforming scope_id. The previous test silently passed
// non-spec inputs that happened to land under p.Chains.
func TestAdvScopeChainRejectsPathTraversal(t *testing.T) {
	p := Paths{Chains: "/safe/chains"}
	mustReject := []string{
		"../../etc/passwd",
		"..",
		"../sibling/file",
		"/abs/path",
		"normal/with/slash",
		"with\x00null",
		"",
		"s_../escape",
		"s_short",
		"s_TOOLONGtoolongtoolongtoolongtoolongtoolong",
		"X_aaaaaaaaaaaaaaaaaaaaaaaaaa",
		"s_AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"s_aaaaaaaaaaaaaaaaaaaaaaaaa1",
		"s_aaaaaaaaaaaaaaaaaaaaaaaaa0",
		"s_aaaaaaaaaaaaaaaaaaaaaaaaa9",
	}
	for _, sid := range mustReject {
		got := p.ScopeChain(sid)
		if got != "" {
			t.Errorf("scope_id %q must be rejected (returned %q)", sid, got)
		}
	}
	_ = filepath.Clean
	_ = strings.HasPrefix
}

// TestAdvScopeChainAcceptsValidIDs is the positive companion: every
// valid spec-shape ID MUST produce a non-empty path inside p.Chains.
func TestAdvScopeChainAcceptsValidIDs(t *testing.T) {
	p := Paths{Chains: "/safe/chains"}
	cases := []string{
		"s_aaaaaaaaaaaaaaaaaaaaaaaaaa",
		"s_222222222222222222222222aa",
		"s_77777777aaaaa22aabcde22fgh",
		"s_abcdefghijklmnopqrstuvwxyz", // 26 lowercase letters
	}
	for _, sid := range cases {
		got := p.ScopeChain(sid)
		if got == "" {
			t.Errorf("valid scope_id %q rejected", sid)
		}
		want := filepath.Join(p.Chains, sid+".cbor")
		if got != want {
			t.Errorf("scope_id %q: got %q, want %q", sid, got, want)
		}
	}
}

// TestAdvValidScopeIDExactLength locks the length check.
func TestAdvValidScopeIDExactLength(t *testing.T) {
	cases := map[string]bool{
		"":                              false,
		"s_":                            false,
		"s_a":                           false,
		"s_aaaaaaaaaaaaaaaaaaaaaaaaa":   false, // 25 chars after s_
		"s_aaaaaaaaaaaaaaaaaaaaaaaaaa":  true,  // 26 chars
		"s_aaaaaaaaaaaaaaaaaaaaaaaaaaa": false, // 27 chars
	}
	for in, want := range cases {
		if got := ValidScopeID(in); got != want {
			t.Errorf("ValidScopeID(%q) = %v, want %v", in, got, want)
		}
	}
}
