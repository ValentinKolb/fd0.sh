package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestRetryAfterDelay(t *testing.T) {
	const max = 30 * time.Second
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", time.Second},        // empty → default 1s
		{"garbage", time.Second}, // unparseable → default
		{"0", time.Second},       // non-positive → default
		{"-5", time.Second},      // negative → default
		{"3", 3 * time.Second},   // normal
		{" 7 ", 7 * time.Second}, // whitespace tolerated
		{"999", max},             // clamped to max
	}
	for _, c := range cases {
		if got := retryAfterDelay(c.header, max); got != c.want {
			t.Errorf("retryAfterDelay(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

func TestValidateScopePullPageRequiresContiguousSuffix(t *testing.T) {
	genesis := proto.ScopeEvent{SignedPrefix: proto.SignedPrefix{
		Kind: "member.change",
		Seq:  0,
	}}
	genesisInput, err := genesis.PrevHashInput()
	if err != nil {
		t.Fatal(err)
	}
	scopeID := proto.DeriveScopeID(proto.EventID(genesisInput)).String()
	genesisHash := proto.HashPrefix(genesisInput)
	scopeRef := scopeID

	one := proto.ScopeEvent{SignedPrefix: proto.SignedPrefix{
		Kind:     "secret.set",
		Scope:    &scopeRef,
		Seq:      1,
		PrevHash: genesisHash[:],
	}}
	oneInput, err := one.PrevHashInput()
	if err != nil {
		t.Fatal(err)
	}
	oneHash := proto.HashPrefix(oneInput)
	two := proto.ScopeEvent{SignedPrefix: proto.SignedPrefix{
		Kind:     "secret.set",
		Scope:    &scopeRef,
		Seq:      2,
		PrevHash: oneHash[:],
	}}

	twoInput, err := two.PrevHashInput()
	if err != nil {
		t.Fatal(err)
	}
	twoHash := proto.HashPrefix(twoInput)
	if err := validateScopePullPage(scopeID, pullCursor{}, 2, twoHash[:], []proto.ScopeEvent{genesis, one, two}); err != nil {
		t.Fatalf("valid full chain rejected: %v", err)
	}
	cursor := pullCursor{Seq: 0, Hash: genesisHash[:]}
	if err := validateScopePullPage(scopeID, cursor, 2, twoHash[:], []proto.ScopeEvent{one, two}); err != nil {
		t.Fatalf("valid suffix rejected: %v", err)
	}
	if err := validateScopePullPage(scopeID, cursor, 2, twoHash[:], []proto.ScopeEvent{two}); !errors.Is(err, errScopePullDiverged) {
		t.Fatalf("forward sequence gap must require reconcile, got %v", err)
	}
	if err := validateScopePullPage(scopeID, cursor, 2, twoHash[:], nil); !errors.Is(err, errScopePullDiverged) {
		t.Fatalf("empty page before tip must require reconcile, got %v", err)
	}
	if err := validateScopePullPage(scopeID, pullCursor{Seq: 3, Hash: twoHash[:]}, 2, twoHash[:], nil); err != nil {
		t.Fatalf("local pending suffix rejected: %v", err)
	}

	wrongScope := one
	other := proto.DeriveScopeID("other").String()
	wrongScope.SignedPrefix.Scope = &other
	if err := validateScopePullPage(scopeID, cursor, 1, oneHash[:], []proto.ScopeEvent{wrongScope}); err == nil {
		t.Fatal("scope substitution accepted")
	}

	wrongPrev := one
	wrongPrev.SignedPrefix.PrevHash = make([]byte, 32)
	if err := validateScopePullPage(scopeID, cursor, 1, oneHash[:], []proto.ScopeEvent{wrongPrev}); !errors.Is(err, errScopePullDiverged) {
		t.Fatalf("non-contiguous prev_hash must require reconcile, got %v", err)
	}
}
