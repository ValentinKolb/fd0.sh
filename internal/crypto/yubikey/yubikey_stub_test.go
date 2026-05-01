//go:build !yubikey

package yubikey

import "testing"

// TestStubBuild_NoSurprises asserts that the no-tag build returns
// ErrNotEnabled from every entry point. The yubikey-tagged build has
// real implementations (or pending-hardware stubs with different error
// messages), so this test only runs without the tag.
func TestStubBuild_NoSurprises(t *testing.T) {
	if _, err := List(); err != ErrNotEnabled {
		t.Errorf("List() = %v, want ErrNotEnabled", err)
	}
	if _, err := Open(Default()); err != ErrNotEnabled {
		t.Errorf("Open() = %v, want ErrNotEnabled", err)
	}
	if _, err := Initialize(SlotKeyManagement, "", TouchAlways, PinAlways); err != ErrNotEnabled {
		t.Errorf("Initialize() = %v, want ErrNotEnabled", err)
	}
	if _, err := Enroll(EnrollOptions{Slot: SlotKeyManagement}); err != ErrNotEnabled {
		t.Errorf("Enroll() = %v, want ErrNotEnabled", err)
	}
}
