package cli

import (
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
