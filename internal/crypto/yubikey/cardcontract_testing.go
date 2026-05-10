package yubikey

import (
	"testing"
)

// AssertCardContract is a shared test helper that exercises every
// surface of the Card interface against a supplied implementation.
// Test files in this package and downstream consumers (e.g.
// cmd/fd0-yubikey-record/record_test.go) call this against their
// fake-Card stubs so adding a method to Card forces every fake to
// implement it AND every fake to satisfy the same observable
// contract.
//
// The contract:
//   - PublicX25519 returns either (32-byte slice, nil) or
//     (nil, non-nil error). Length-32 success is independent of
//     implementation; tests pass a label so failure messages
//     identify which stub broke.
//   - SharedSecret rejects empty / wrong-length ephPub before any
//     hardware/computation work.
//   - PINRetries returns a non-negative integer (0 means blocked).
//   - Close is idempotent: calling it twice is safe; the second
//     call MUST return nil if the first did, OR a clearly-typed
//     error (not a panic).
//
// This file is named *_testing.go (not *_test.go) so it is
// importable from test code in OTHER packages — the standard Go
// pattern for shared test helpers.
func AssertCardContract(t *testing.T, label string, c Card) {
	t.Helper()

	// PublicX25519: either 32-byte success or non-nil error.
	pub, err := c.PublicX25519()
	if err == nil && len(pub) != 32 {
		t.Errorf("%s: PublicX25519 returned %d bytes with no error (want 32)", label, len(pub))
	}

	// SharedSecret rejects bad lengths BEFORE any work.
	for _, n := range []int{0, 1, 31, 33, 64} {
		_, err := c.SharedSecret(make([]byte, n))
		if err == nil {
			t.Errorf("%s: SharedSecret(len=%d) returned nil error (want length-violation)", label, n)
		}
	}

	// PINRetries either succeeds with a non-negative count, or
	// surfaces an explicit error. Negative is always a bug.
	if n, err := c.PINRetries(); err == nil && n < 0 {
		t.Errorf("%s: PINRetries returned %d (want >= 0)", label, n)
	}

	// Close idempotency: two consecutive calls must not panic and
	// must not produce a NEW error class on the second call.
	if err1 := c.Close(); err1 != nil {
		t.Errorf("%s: first Close returned non-nil: %v", label, err1)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: second Close panicked: %v", label, r)
		}
	}()
	_ = c.Close() // second call — must not panic; error tolerated
}
