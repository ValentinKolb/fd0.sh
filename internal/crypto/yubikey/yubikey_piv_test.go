//go:build yubikey

package yubikey

import (
	"strings"
	"testing"
)

// On the yubikey-tagged build, hardware-day pieces are stubs that
// return descriptive "pending" errors. These tests pin those stubs so
// a future hardware-day commit MUST update them in lockstep — if the
// stub silently returns nil, the test catches it.

func TestPivWrapper_PublicX25519_PendingError(t *testing.T) {
	t.Parallel()
	// Construct without piv.Open: we only want to exercise the
	// hardware-pending stub. yk is nil, but PublicX25519 doesn't touch
	// yk in the current scaffold.
	p := &pivWrapper{slot: SlotKeyManagement}
	_, err := p.PublicX25519()
	if err == nil {
		t.Fatalf("PublicX25519: expected pending-hardware error, got nil")
	}
	if !strings.Contains(err.Error(), "pending hardware-day") {
		t.Fatalf("error message should mention pending hardware-day work, got: %v", err)
	}
}

func TestPivWrapper_SharedSecret_PendingError(t *testing.T) {
	t.Parallel()
	p := &pivWrapper{slot: SlotKeyManagement}
	_, err := p.SharedSecret(make([]byte, 32))
	if err == nil {
		t.Fatalf("SharedSecret: expected pending-hardware error, got nil")
	}
	if !strings.Contains(err.Error(), "pending hardware-day") {
		t.Fatalf("error message should mention pending hardware-day work, got: %v", err)
	}
}

// SharedSecret MUST validate the input length before it reaches the
// hardware-day stub. This catches an invariant the contract requires
// implementations to enforce.
func TestPivWrapper_SharedSecret_RejectsBadEphLengthBeforeHardware(t *testing.T) {
	t.Parallel()
	p := &pivWrapper{slot: SlotKeyManagement}
	for _, n := range []int{0, 1, 31, 33, 64} {
		_, err := p.SharedSecret(make([]byte, n))
		if err == nil {
			t.Fatalf("eph len=%d: expected error, got nil", n)
		}
		if strings.Contains(err.Error(), "pending hardware-day") {
			t.Fatalf("eph len=%d: should fail length check before hardware path, got pending-hardware error: %v", n, err)
		}
	}
}

// OpenSealedBox(pivWrapper, ...) must surface the hardware-pending
// error rather than masking it as a generic crypto failure. Order
// matters: PublicX25519 is the first card call, so the stub error
// from THAT method is what surfaces.
func TestPivWrapper_OpenSealedBox_SurfacesPendingError(t *testing.T) {
	t.Parallel()
	p := &pivWrapper{slot: SlotKeyManagement}
	// Length-valid placeholder so we get past ParseSealed.
	sealed := make([]byte, 48)
	_, err := OpenSealedBox(p, sealed)
	if err == nil {
		t.Fatalf("OpenSealedBox: expected pending-hardware error, got nil")
	}
	if !strings.Contains(err.Error(), "pending hardware-day") {
		t.Fatalf("error should propagate pending-hardware message, got: %v", err)
	}
}

// Initialize / Enroll are explicit hardware-day TODOs. Pin their
// pending-error behaviour the same way.
func TestInitialize_PendingError(t *testing.T) {
	t.Parallel()
	_, err := Initialize(SlotKeyManagement, "", TouchAlways, PinAlways)
	if err == nil {
		t.Fatalf("Initialize: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "pending hardware-day") {
		t.Fatalf("error should mention pending hardware-day work, got: %v", err)
	}
}

func TestEnroll_PendingError(t *testing.T) {
	t.Parallel()
	_, err := Enroll(EnrollOptions{Slot: SlotKeyManagement})
	if err == nil {
		t.Fatalf("Enroll: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "pending hardware-day") {
		t.Fatalf("error should mention pending hardware-day work, got: %v", err)
	}
	// The pending message MUST also tell future readers where to look:
	// it points at TODO.md / the recorder so the next person doesn't
	// repeat the audit work. The message is part of the contract.
	if !strings.Contains(err.Error(), "TODO.md") {
		t.Fatalf("error should reference TODO.md for hardware-day procedure, got: %v", err)
	}
}
