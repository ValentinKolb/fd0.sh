package fdhome

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Adversarial tests for fdhome — paths and config parsing. Covers
// the codex-found path-traversal bug and assorted config edge cases.

// TestAdvScopeChainRejectsPathTraversal locks the fdhome.go:51 fix
// (Wave C-1, hardened in C-1.1 with opaque newtype):
// ScopeChain takes a typed proto.ScopeID and that type's only
// constructors validate against `s_[a-z2-7]{26}`. Path-traversal
// input therefore fails at the construction site (proto.ParseScopeID)
// — a raw string can no longer reach ScopeChain at all.
//
// We assert the upstream gate here: every malformed input must be
// REJECTED by ParseScopeID. The defence-in-depth ScopeChain shape
// check still runs against ScopeID{} sentinels too.
func TestAdvScopeChainRejectsPathTraversal(t *testing.T) {
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
		if _, err := proto.ParseScopeID(sid); err == nil {
			t.Errorf("scope_id %q must be rejected by ParseScopeID", sid)
		}
	}
	// Defence-in-depth: zero ScopeID{} (skipped construction)
	// must still produce empty path from ScopeChain.
	p := Paths{Chains: "/safe/chains"}
	if got := p.ScopeChain(proto.ScopeID{}); got != "" {
		t.Errorf("zero ScopeID{} must return \"\" from ScopeChain, got %q", got)
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
		got := p.ScopeChain(proto.MustParseScopeID(sid))
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
