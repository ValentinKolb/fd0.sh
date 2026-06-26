package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// pickUnlockMethod is the policy for choosing which auth method gets
// the credential prompt. The contract:
//   - explicit --method wins; if no enrolled method matches, error
//     names the offending request and the available types.
//   - empty --method picks the first method by method_id (sorted ASC)
//     so script-driven invocations are deterministic.

func TestPickUnlockMethod_NoActive(t *testing.T) {
	t.Parallel()
	_, err := pickUnlockMethod(nil, "")
	if err == nil {
		t.Fatalf("expected error for empty active list")
	}
}

func TestPickUnlockMethod_ExplicitRequest_Match(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_b", MethodType: proto.AuthYubikey},
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
	}
	got, err := pickUnlockMethod(active, "yubikey")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "am_b" {
		t.Fatalf("got method_id=%s, want am_b", got.MethodID)
	}
}

func TestPickUnlockMethod_ExplicitRequest_NoMatch(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
	}
	_, err := pickUnlockMethod(active, "yubikey")
	if err == nil {
		t.Fatalf("expected error for unknown method type")
	}
	if !strings.Contains(err.Error(), "yubikey") {
		t.Fatalf("error should name the requested method, got: %v", err)
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("error should list available methods, got: %v", err)
	}
}

func TestPickUnlockMethod_DefaultPicksFirstByID(t *testing.T) {
	t.Parallel()
	// Order matters: the function must sort by method_id ASCENDING,
	// not pick the first slice element.
	active := []proto.AuthMethod{
		{MethodID: "am_z", MethodType: proto.AuthYubikey},
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
		{MethodID: "am_m", MethodType: proto.AuthYubikey},
	}
	got, err := pickUnlockMethod(active, "")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "am_a" {
		t.Fatalf("got method_id=%s, want am_a (smallest)", got.MethodID)
	}
}

func TestPickUnlockMethod_SingleMethodNoFlag(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_only", MethodType: proto.AuthYubikey},
	}
	got, err := pickUnlockMethod(active, "")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "am_only" {
		t.Fatalf("got method_id=%s, want am_only", got.MethodID)
	}
}

// pickUnlockMethod sorts by method_id ascending. Non-ULID method_ids
// (legacy fixtures, hand-edited chains, future-format keys) MUST
// still produce a deterministic, predictable choice. Specifically a
// short or non-prefix id like "0" or "x" should NOT silently
// dominate a normal "am_..." id without the user noticing — when the
// CLI auto-picks, it logs which id it took. We pin the deterministic
// behaviour here.
func TestPickUnlockMethod_NonULIDMethodID(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_01HVWZZ", MethodType: proto.AuthPassphrase},
		// "0" sorts before any "am_..." string lexicographically.
		// If it wins, the agent had better not crash — and the CLI
		// must surface the auto-pick logging so the user notices.
		{MethodID: "0", MethodType: proto.AuthYubikey},
	}
	got, err := pickUnlockMethod(active, "")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "0" {
		t.Fatalf("got method_id=%s, want 0 (smallest by lexicographic sort)", got.MethodID)
	}
	if got.MethodType != proto.AuthYubikey {
		t.Fatalf("got method_type=%s, want yubikey", got.MethodType)
	}
}

// Empty method_id is an unusual case — fixture or corruption. The
// function should still terminate and pick something, not crash.
func TestPickUnlockMethod_EmptyMethodID(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "", MethodType: proto.AuthYubikey},
		{MethodID: "am_b", MethodType: proto.AuthPassphrase},
	}
	got, err := pickUnlockMethod(active, "")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "" {
		t.Fatalf("empty string sorts smallest; got %s want \"\"", got.MethodID)
	}
}

func TestDistinctMethodTypes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []proto.AuthMethod
		want int
	}{
		{"empty", nil, 0},
		{"single", []proto.AuthMethod{{MethodType: "passphrase"}}, 1},
		{"two distinct", []proto.AuthMethod{{MethodType: "passphrase"}, {MethodType: "yubikey"}}, 2},
		{"two same", []proto.AuthMethod{{MethodType: "passphrase"}, {MethodType: "passphrase"}}, 1},
		{"mixed dup", []proto.AuthMethod{{MethodType: "passphrase"}, {MethodType: "yubikey"}, {MethodType: "passphrase"}}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := distinctMethodTypes(c.in)
			if len(got) != c.want {
				t.Fatalf("got %d distinct, want %d (got %v)", len(got), c.want, got)
			}
		})
	}
}

func TestFriendlyUnlockErrorHidesAEADDetails(t *testing.T) {
	t.Parallel()
	err := friendlyUnlockError(errors.New("agent: vault: AEAD-open wrap am_123: cipher: message authentication failed"))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "AEAD") || strings.Contains(err.Error(), "cipher") || strings.Contains(err.Error(), "am_123") {
		t.Fatalf("error leaked internals: %s", err)
	}
	if !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("error should explain likely cause: %s", err)
	}
}
