//go:build yubikey

package yubikey

import (
	"crypto/ecdh"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// These tests run on the yubikey-tagged build but DO NOT require a
// real card. Hardware-dependent behaviour is exercised in
// integration_yubikey_test.go, which is opt-in via the
// FD0_YUBIKEY_HARDWARE env var.

// pivWrapper with no slotPub cached (slot empty) MUST return a clean,
// actionable error from PublicX25519 — never a SIGSEGV from a nil
// dereference, never a generic "internal" string.
func TestPivWrapper_PublicX25519_NoSlotKey(t *testing.T) {
	t.Parallel()
	p := &pivWrapper{slot: SlotKeyManagement, pivSlot: piv.SlotKeyManagement}
	_, err := p.PublicX25519()
	if err == nil {
		t.Fatalf("expected error when slot has no key, got nil")
	}
	if !strings.Contains(err.Error(), "Enroll") {
		t.Fatalf("error should point the user at Enroll, got: %v", err)
	}
}

func TestPivWrapper_SharedSecret_NoSlotKey(t *testing.T) {
	t.Parallel()
	p := &pivWrapper{slot: SlotKeyManagement, pivSlot: piv.SlotKeyManagement}
	_, err := p.SharedSecret(make([]byte, 32))
	if err == nil {
		t.Fatalf("expected error when slot has no key, got nil")
	}
	if !strings.Contains(err.Error(), "Enroll") {
		t.Fatalf("error should point the user at Enroll, got: %v", err)
	}
}

// SharedSecret length validation MUST fire before any code path that
// would touch hardware. Set slotPub so the no-key check passes; the
// length check should still fail before reaching yk.PrivateKey
// (which would NPE on the nil yk).
func TestPivWrapper_SharedSecret_RejectsBadEphLength(t *testing.T) {
	t.Parallel()
	stubPub, err := ecdh.X25519().NewPublicKey(make32(0x01))
	if err != nil {
		t.Fatal(err)
	}
	p := &pivWrapper{
		slot:    SlotKeyManagement,
		pivSlot: piv.SlotKeyManagement,
		slotPub: stubPub,
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		_, err := p.SharedSecret(make([]byte, n))
		if err == nil {
			t.Fatalf("eph len=%d: expected error, got nil", n)
		}
		if !strings.Contains(err.Error(), "32 bytes") {
			t.Fatalf("eph len=%d: error should mention 32-byte requirement, got: %v", n, err)
		}
	}
}

// All-zero / low-order ephPub is accepted by ecdh.X25519().NewPublicKey
// (which only validates length) and rejected at the ECDH step. We
// can't exercise that without a real card, so the corresponding
// integration test lives in integration_yubikey_test.go behind the
// FD0_YUBIKEY_HARDWARE gate. The constant-time post-check in our
// SharedSecret is a third defensive layer on top of the curve's own
// rejection.

func TestInitialize_NotImplemented(t *testing.T) {
	t.Parallel()
	_, err := Initialize(SlotKeyManagement, "", TouchAlways, PinAlways)
	if err == nil {
		t.Fatalf("Initialize: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "use Enroll") {
		t.Fatalf("error should redirect to Enroll, got: %v", err)
	}
}

// Enroll without a connected card surfaces a clean "no smartcards"
// error rather than panicking. This is the only Enroll path we can
// exercise without hardware; the happy-path test lives in
// integration_yubikey_test.go.
func TestEnroll_NoCard(t *testing.T) {
	t.Parallel()
	if testHasYubikeyAttached() {
		t.Skip("skipping no-card test: a YubiKey is plugged in")
	}
	_, err := Enroll(EnrollOptions{
		Slot:        SlotKeyManagement,
		PIN:         "",
		TouchPolicy: TouchNever,
	})
	if err == nil {
		t.Fatalf("expected 'no smartcards' error, got nil")
	}
	if !strings.Contains(err.Error(), "no smartcards") && !strings.Contains(err.Error(), "smartcards detected") {
		t.Fatalf("error should report missing card, got: %v", err)
	}
}

// Enroll input validation must happen BEFORE any hardware contact so
// callers don't see a confusing PIV error for a clearly malformed
// PIN string. We trip the PIN length check; the function never gets
// to piv.Cards().
func TestEnroll_RejectsBadPIN(t *testing.T) {
	t.Parallel()
	for _, pin := range []string{"123", "very-long-pin-over-eight", "12\x00345"} {
		_, err := Enroll(EnrollOptions{
			Slot:        SlotKeyManagement,
			PIN:         pin,
			TouchPolicy: TouchNever,
		})
		if err == nil {
			t.Fatalf("PIN=%q: expected validation error, got nil", pin)
		}
	}
}

func TestMapTouchPolicy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   TouchPolicy
		want piv.TouchPolicy
	}{
		{TouchAlways, piv.TouchPolicyAlways},
		{TouchNever, piv.TouchPolicyNever},
		{TouchCached, piv.TouchPolicyCached},
		{TouchPolicy(99), piv.TouchPolicyAlways}, // unknown → secure default
	}
	for _, c := range cases {
		if got := mapTouchPolicy(c.in); got != c.want {
			t.Errorf("mapTouchPolicy(%v): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMapSlot(t *testing.T) {
	t.Parallel()
	if got, ok := mapSlot(SlotKeyManagement); !ok || got != piv.SlotKeyManagement {
		t.Errorf("mapSlot(SlotKeyManagement) = (%v, %v), want (piv.SlotKeyManagement, true)", got, ok)
	}
	if _, ok := mapSlot(SlotID(0x9c)); ok {
		t.Errorf("mapSlot(0x9c): want unsupported, got supported")
	}
	if _, ok := mapSlot(SlotID(0)); ok {
		t.Errorf("mapSlot(0): want unsupported, got supported")
	}
}

// ---- helpers ----

func make32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// testHasYubikeyAttached probes for a connected card without
// requiring the explicit hardware-test gate. Returns true iff a card
// is visible to the PCSC layer; on any other error returns false.
func testHasYubikeyAttached() bool {
	cards, err := piv.Cards()
	if err != nil {
		return false
	}
	return len(cards) > 0
}

