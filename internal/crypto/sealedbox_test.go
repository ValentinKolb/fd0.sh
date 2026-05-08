package crypto

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestParseSealed_AcceptsMinimumLength(t *testing.T) {
	t.Parallel()
	in := make([]byte, SealedMinLen)
	for i := range in {
		in[i] = byte(i)
	}
	eph, ct, err := ParseSealed(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(eph[:], in[:SealedEphPubLen]) {
		t.Fatalf("ephPub mismatch")
	}
	if len(ct) != 16 {
		t.Fatalf("ct len: have %d, want 16 (Poly1305 tag for empty plaintext)", len(ct))
	}
	if !bytes.Equal(ct, in[SealedEphPubLen:]) {
		t.Fatalf("ct mismatch")
	}
}

func TestParseSealed_AcceptsLargerInputs(t *testing.T) {
	t.Parallel()
	for _, plainLen := range []int{1, 32, 1024, 65536} {
		in := make([]byte, SealedEphPubLen+16+plainLen)
		for i := range in {
			in[i] = byte(i % 251) // arbitrary non-zero pattern
		}
		eph, ct, err := ParseSealed(in)
		if err != nil {
			t.Fatalf("plainLen=%d: unexpected error: %v", plainLen, err)
		}
		if !bytes.Equal(eph[:], in[:SealedEphPubLen]) {
			t.Fatalf("plainLen=%d: ephPub mismatch", plainLen)
		}
		if !bytes.Equal(ct, in[SealedEphPubLen:]) {
			t.Fatalf("plainLen=%d: ct mismatch", plainLen)
		}
	}
}

func TestParseSealed_RejectsTooShort(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 31, 32, 47, SealedMinLen - 1} {
		in := make([]byte, n)
		_, _, err := ParseSealed(in)
		if err == nil {
			t.Fatalf("len=%d: expected error, got nil", n)
		}
		if !errors.Is(err, ErrSealedTooShort) {
			t.Fatalf("len=%d: error chain missing ErrSealedTooShort: %v", n, err)
		}
	}
}

func TestParseSealed_RejectsNil(t *testing.T) {
	t.Parallel()
	_, _, err := ParseSealed(nil)
	if !errors.Is(err, ErrSealedTooShort) {
		t.Fatalf("nil input: want ErrSealedTooShort chain, got %v", err)
	}
}

// EphPub is copied (caller cannot retain a reference into the input
// buffer). ct is documented as aliasing — that is intentional, but we
// still test the contract so future refactors notice if it changes.
func TestParseSealed_EphPubIsCopy(t *testing.T) {
	t.Parallel()
	in := make([]byte, SealedMinLen)
	for i := range in {
		in[i] = 0xAB
	}
	eph, _, err := ParseSealed(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := range in {
		in[i] = 0x00
	}
	for i, b := range eph {
		if b != 0xAB {
			t.Fatalf("eph[%d] mutated after caller wiped input: got 0x%02x", i, b)
		}
	}
}

func TestParseSealed_CtAliasesInput(t *testing.T) {
	// Documented behaviour: ct shares storage with the input. Test pins
	// that contract — if a future change copies ct, this fails so the
	// docs/comments get updated in lockstep.
	t.Parallel()
	in := make([]byte, SealedMinLen+8)
	for i := range in {
		in[i] = byte(i)
	}
	_, ct, err := ParseSealed(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	in[SealedEphPubLen] ^= 0xff
	if ct[0] != in[SealedEphPubLen] {
		t.Fatalf("ct does not alias input as documented")
	}
}

// ct's capacity MUST equal its length so callers who append to it cannot
// reach past the sealed-box ciphertext into uninitialised memory or
// adjacent caller buffers.
func TestParseSealed_CtCapacityClamped(t *testing.T) {
	t.Parallel()
	// Allocate a buffer larger than the sealed payload to give ct's
	// "leak window" something to step into if the clamp is missing.
	backing := make([]byte, SealedMinLen+64)
	for i := range backing {
		backing[i] = 0xAA
	}
	sealed := backing[:SealedMinLen+8]
	_, ct, err := ParseSealed(sealed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cap(ct) != len(ct) {
		t.Fatalf("ct cap=%d len=%d: capacity leak — append() can mutate beyond sealed-box", cap(ct), len(ct))
	}
	// Sanity: appending to ct must produce a NEW backing array.
	tail := append(ct, 0x55)
	if &tail[0] == &ct[0] {
		t.Fatalf("append reused backing array — capacity not clamped")
	}
	// And the original backing buffer must be untouched at the byte just
	// past the sealed-box ct end.
	if backing[SealedMinLen+8] != 0xAA {
		t.Fatalf("byte past sealed-box was mutated by append-to-ct: 0x%02x", backing[SealedMinLen+8])
	}
}

// Soak: feed ParseSealed a stream of pseudo-random sealed-box-shaped
// blobs (using curve25519 to derive realistic eph pubkeys, then opaque
// ct payloads), assert no panics and structural invariants hold.
func TestParseSealed_FuzzShape(t *testing.T) {
	t.Parallel()
	for seed := byte(0); seed < 64; seed++ {
		scalar := make([]byte, 32)
		for i := range scalar {
			scalar[i] = seed + byte(i)
		}
		eph, err := curve25519.X25519(scalar, curve25519.Basepoint)
		if err != nil {
			t.Fatalf("curve25519: %v", err)
		}
		ctLen := int(seed)*7 + 16
		blob := append(append([]byte{}, eph...), make([]byte, ctLen)...)
		gotEph, gotCt, err := ParseSealed(blob)
		if err != nil {
			t.Fatalf("seed=%d: parse: %v", seed, err)
		}
		if !bytes.Equal(gotEph[:], eph) {
			t.Fatalf("seed=%d: eph mismatch", seed)
		}
		if len(gotCt) != ctLen {
			t.Fatalf("seed=%d: ct len: have %d, want %d", seed, len(gotCt), ctLen)
		}
	}
}
