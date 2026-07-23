package cli

import (
	"context"
	"errors"
	"fmt"
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

func TestRunSyncBatchesAdaptsToWriteCapacity(t *testing.T) {
	var limits []int
	calls := 0
	budget := &syncRunBudget{membershipPages: maxMembershipPagesPerSync}
	err := runSyncBatches(context.Background(), "https://example.test", budget, func(
		_ context.Context,
		_ string,
		limit int,
		gotBudget *syncRunBudget,
	) error {
		if gotBudget != budget {
			t.Fatal("sync budget was reset between rounds")
		}
		limits = append(limits, limit)
		calls++
		switch calls {
		case 1, 2:
			return errSyncRateLimited
		case 3:
			return errSyncMorePushes
		default:
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{32, 16, 8, 8}
	if len(limits) != len(want) {
		t.Fatalf("limits=%v, want %v", limits, want)
	}
	for i := range want {
		if limits[i] != want[i] {
			t.Fatalf("limits=%v, want %v", limits, want)
		}
	}
}

func TestRunSyncBatchesReturnsRateLimitAtMinimum(t *testing.T) {
	err := runSyncBatches(
		context.Background(),
		"https://example.test",
		&syncRunBudget{membershipPages: maxMembershipPagesPerSync},
		func(
			_ context.Context,
			_ string,
			_ int,
			_ *syncRunBudget,
		) error {
			return errSyncRateLimited
		})
	if !errors.Is(err, errSyncRateLimited) {
		t.Fatalf("got %v, want rate limit", err)
	}
}

func TestMembershipDiscoveryRequestCarriesCursor(t *testing.T) {
	body, err := buildMembershipDiscoveryRequest("scope:s_0256")
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Pull struct {
			DiscoverMemberships bool   `cbor:"discover_memberships"`
			MembershipAfter     string `cbor:"membership_after"`
			MembershipLimit     uint64 `cbor:"membership_limit"`
		} `cbor:"pull"`
		Push []any `cbor:"push"`
	}
	if err := proto.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	if !request.Pull.DiscoverMemberships ||
		request.Pull.MembershipAfter != "scope:s_0256" ||
		request.Pull.MembershipLimit != membershipPageSize ||
		len(request.Push) != 0 {
		t.Fatalf("unexpected request: %+v", request)
	}
}

func TestValidateMembershipPageBoundsServerWork(t *testing.T) {
	memberships := make([]membershipResult, membershipPageSize+1)
	for i := range memberships {
		memberships[i].ScopeID = proto.DeriveScopeID(fmt.Sprintf("scope-%d", i)).String()
	}
	if err := validateMembershipPage("", memberships, "scope:s_next"); err == nil {
		t.Fatal("oversized membership page accepted")
	}
	if err := validateMembershipPage(
		"scope:s_z",
		nil,
		"scope:s_a",
	); err == nil {
		t.Fatal("non-advancing membership cursor accepted")
	}
	valid := proto.DeriveScopeID("tail").String()
	if err := validateMembershipPage("", []membershipResult{{ScopeID: valid}}, "not-scope:"+valid); err == nil {
		t.Fatal("malformed membership cursor accepted")
	}
	other := proto.DeriveScopeID("other").String()
	if err := validateMembershipPage("", []membershipResult{{ScopeID: valid}}, "scope:"+other); err == nil {
		t.Fatal("membership cursor unrelated to page tail accepted")
	}
}

func TestSyncRequestCarriesPersistedMembershipCursor(t *testing.T) {
	body, err := buildSyncRequestBody(
		map[string]pullCursor{},
		nil,
		true,
		"scope:s_0256",
		1000,
	)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Pull struct {
			MembershipAfter string `cbor:"membership_after"`
		} `cbor:"pull"`
	}
	if err := proto.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	if request.Pull.MembershipAfter != "scope:s_0256" {
		t.Fatalf("membership cursor = %q", request.Pull.MembershipAfter)
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
