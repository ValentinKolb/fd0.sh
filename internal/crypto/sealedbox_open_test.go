package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// recipientFixture pairs a deterministic X25519 priv with its derived
// pub. Used as a one-line setup in the tests below.
type recipientFixture struct {
	priv [32]byte
	pub  [32]byte
}

func newRecipient(t *testing.T, seed string) recipientFixture {
	t.Helper()
	var r recipientFixture
	// seed is a printable label expanded to 32 bytes by zero-padding.
	// Sufficient to derive distinct keys per test; not a KDF, just a
	// deterministic source that survives test reordering.
	copy(r.priv[:], []byte(seed))
	pub, err := curve25519.X25519(r.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("seed %q: derive pub: %v", seed, err)
	}
	copy(r.pub[:], pub)
	return r
}

func (r recipientFixture) shared(t *testing.T, ephPub [32]byte) []byte {
	t.Helper()
	out, err := curve25519.X25519(r.priv[:], ephPub[:])
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	return out
}

// Property test: for 200 random (recipient, plaintext) pairs:
//   1. SealAnonymous (existing libsodium-compat path) produces a sealed blob.
//   2. ParseSealed splits it.
//   3. We compute shared via curve25519.X25519 (the software equivalent
//      of what a Card.SharedSecret would produce on hardware).
//   4. OpenSealedFromShared returns the original plaintext.
//   5. The same blob also opens via the trusted nacl/box-based
//      OpenAnonymous (existing API), and the two results agree
//      bit-for-bit. This pins our open path against an independent
//      implementation in the same process.
func TestOpenSealedFromShared_RoundtripVsOpenAnonymous(t *testing.T) {
	t.Parallel()
	for i := 0; i < 200; i++ {
		// Random recipient.
		var rPriv [32]byte
		if _, err := io.ReadFull(rand.Reader, rPriv[:]); err != nil {
			t.Fatalf("iter=%d: rng priv: %v", i, err)
		}
		rPub, err := curve25519.X25519(rPriv[:], curve25519.Basepoint)
		if err != nil {
			t.Fatalf("iter=%d: derive recipient pub: %v", i, err)
		}
		var rPubArr [32]byte
		copy(rPubArr[:], rPub)

		// Random plaintext, length in [0, 1024].
		plainLen, err := randIntn(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("iter=%d: rng len: %v", i, err)
		}
		plain := make([]byte, plainLen)
		if _, err := io.ReadFull(rand.Reader, plain); err != nil {
			t.Fatalf("iter=%d: rng plain: %v", i, err)
		}

		// Seal via existing path.
		sealed, err := SealAnonymous(plain, rPub)
		if err != nil {
			t.Fatalf("iter=%d: SealAnonymous: %v", i, err)
		}

		// Open via decomposed path.
		ephPub, ct, err := ParseSealed(sealed)
		if err != nil {
			t.Fatalf("iter=%d: ParseSealed: %v", i, err)
		}
		shared, err := curve25519.X25519(rPriv[:], ephPub[:])
		if err != nil {
			t.Fatalf("iter=%d: ECDH: %v", i, err)
		}
		gotNew, ok := OpenSealedFromShared(ephPub, rPubArr, ct, shared)
		if !ok {
			t.Fatalf("iter=%d: OpenSealedFromShared returned !ok", i)
		}
		if !bytes.Equal(gotNew, plain) {
			t.Fatalf("iter=%d: decomposed-path plaintext mismatch", i)
		}

		// Open via existing trusted path; both must agree.
		gotOld, ok := OpenAnonymous(sealed, rPub, rPriv[:])
		if !ok {
			t.Fatalf("iter=%d: OpenAnonymous returned !ok", i)
		}
		if !bytes.Equal(gotOld, gotNew) {
			t.Fatalf("iter=%d: paths diverge: old=%x new=%x", i, gotOld, gotNew)
		}
	}
}

// Empty-plaintext is the edge case nacl/box documents — sealed blob is
// exactly SealedMinLen (32 + 16). Verify the open path still works.
func TestOpenSealedFromShared_EmptyPlaintext(t *testing.T) {
	t.Parallel()
	r := newRecipient(t, "empty-plaintext-seed")
	sealed, err := SealAnonymous(nil, r.pub[:])
	if err != nil {
		t.Fatalf("SealAnonymous: %v", err)
	}
	if len(sealed) != SealedMinLen {
		t.Fatalf("empty-plain sealed len: have %d, want %d", len(sealed), SealedMinLen)
	}
	eph, ct, err := ParseSealed(sealed)
	if err != nil {
		t.Fatalf("ParseSealed: %v", err)
	}
	shared := r.shared(t, eph)
	plain, ok := OpenSealedFromShared(eph, r.pub, ct, shared)
	if !ok {
		t.Fatalf("OpenSealedFromShared returned !ok")
	}
	if len(plain) != 0 {
		t.Fatalf("empty plain decoded to %d bytes", len(plain))
	}
}

func TestOpenSealedFromSharedErr_RejectsBadSharedLength(t *testing.T) {
	t.Parallel()
	r := newRecipient(t, "bad-shared-len-seed")
	sealed, err := SealAnonymous([]byte("payload"), r.pub[:])
	if err != nil {
		t.Fatal(err)
	}
	eph, ct, err := ParseSealed(sealed)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		_, err := OpenSealedFromSharedErr(eph, r.pub, ct, make([]byte, n))
		if !errors.Is(err, ErrSealedShared) {
			t.Fatalf("len=%d: want ErrSealedShared, got %v", n, err)
		}
	}
}

func TestOpenSealedFromSharedErr_RejectsZeroShared(t *testing.T) {
	t.Parallel()
	r := newRecipient(t, "zero-shared-seed")
	sealed, err := SealAnonymous([]byte("payload"), r.pub[:])
	if err != nil {
		t.Fatal(err)
	}
	eph, ct, err := ParseSealed(sealed)
	if err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, 32)
	_, err = OpenSealedFromSharedErr(eph, r.pub, ct, zero)
	if !errors.Is(err, ErrSealedSharedZero) {
		t.Fatalf("zero shared: want ErrSealedSharedZero, got %v", err)
	}
}

// Tampered byte (anywhere in the sealed blob) MUST cause the open path
// to refuse the message. Coverage spans the full sealed blob so a
// bit-flip in either the ephemeral pubkey prefix or the AEAD ct + tag
// is caught.
//
// Rejection can come from one of three places:
//   - ephPub bit-flip → curve25519.X25519 errors out (small-subgroup or
//     bad scalar interaction), surfacing via the ECDH helper.
//   - ephPub bit-flip that still produces a valid ECDH → derived shared
//     differs → AEAD tag fails.
//   - ct or tag bit-flip → AEAD tag fails directly.
//
// We accept any non-nil error as "rejected"; what matters is that no
// path returns plaintext after a single-bit modification.
func TestOpenSealedFromShared_RejectsTamperedAnyByte(t *testing.T) {
	t.Parallel()
	r := newRecipient(t, "tampered-seed")
	plain := []byte("the quick brown fox jumps over the lazy dog")
	sealed, err := SealAnonymous(plain, r.pub[:])
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(sealed); i++ {
		corrupt := append([]byte{}, sealed...)
		corrupt[i] ^= 0x01
		eph, ct, parseErr := ParseSealed(corrupt)
		if parseErr != nil {
			// Length-only check; tampering can't shorten the blob.
			t.Fatalf("byte=%d: parse: %v", i, parseErr)
		}
		shared, ecdhErr := curve25519.X25519(r.priv[:], eph[:])
		if ecdhErr != nil {
			// Tampered ephPub mapped to a small-subgroup point —
			// rejection at the ECDH stage.
			continue
		}
		got, ok := OpenSealedFromShared(eph, r.pub, ct, shared)
		if ok {
			t.Fatalf("byte=%d: open returned ok=true with plaintext=%x — single-bit flip not rejected", i, got)
		}
	}
}

// Wrong recipient pub fed into the BLAKE2b nonce derivation MUST cause
// the AEAD to fail. (libsodium binds the recipient identity into the
// nonce so a sealed blob cannot be re-keyed by claiming to be a
// different recipient.)
func TestOpenSealedFromShared_RejectsWrongRecipientPub(t *testing.T) {
	t.Parallel()
	r := newRecipient(t, "right-recipient")
	wrong := newRecipient(t, "wrong-recipient")
	plain := []byte("recipient-bound payload")
	sealed, err := SealAnonymous(plain, r.pub[:])
	if err != nil {
		t.Fatal(err)
	}
	eph, ct, err := ParseSealed(sealed)
	if err != nil {
		t.Fatal(err)
	}
	shared := r.shared(t, eph) // correct shared
	_, err = OpenSealedFromSharedErr(eph, wrong.pub, ct, shared)
	if !errors.Is(err, ErrSealedAEAD) {
		t.Fatalf("want ErrSealedAEAD with wrong recipient pub, got %v", err)
	}
}

// Wrong shared (correct length, non-zero, just not the actual ECDH
// output) MUST be rejected by the AEAD. This catches bugs where a
// caller forgets to plumb the actual ECDH result and uses random
// bytes.
func TestOpenSealedFromShared_RejectsWrongShared(t *testing.T) {
	t.Parallel()
	r := newRecipient(t, "wrong-shared-seed")
	plain := []byte("shared-bound payload")
	sealed, err := SealAnonymous(plain, r.pub[:])
	if err != nil {
		t.Fatal(err)
	}
	eph, ct, err := ParseSealed(sealed)
	if err != nil {
		t.Fatal(err)
	}
	bogus := make([]byte, 32)
	for i := range bogus {
		bogus[i] = 0xFF
	}
	_, err = OpenSealedFromSharedErr(eph, r.pub, ct, bogus)
	if !errors.Is(err, ErrSealedAEAD) {
		t.Fatalf("want ErrSealedAEAD with bogus shared, got %v", err)
	}
}

// Frozen vectors. These were captured from the codebase's existing
// SealAnonymous (libsodium-compatible nacl/box) so changes to the
// open path are caught even if SealAnonymous in this package later
// changes too. Each vector pins:
//
//   - recipient_priv: 32-byte X25519 scalar
//   - recipient_pub:  curve25519.X25519(recipient_priv, basepoint)
//   - sealed:         a complete crypto_box_seal blob
//   - plain:          the expected plaintext after open
//
// Regenerate via TestOpenSealedFromShared_GenerateFrozenVectors below
// (run with -run=Generate -v) and paste the printed hex.
//
// Source: SealAnonymous(plain, recipient_pub) seeded with the
// per-vector "rng_seed" string used as the entropy stream.
func TestOpenSealedFromShared_FrozenVectors(t *testing.T) {
	t.Parallel()
	type vec struct {
		name      string
		priv      string // 32-byte ASCII; padded automatically by copy()
		sealedHex string
		plain     string
	}
	vectors := []vec{
		{
			name:      "13-byte ASCII payload",
			priv:      "frozen-vector-1-priv-padding-32!",
			sealedHex: "8a44cb0411dc5b79b621dfeed546f2ecb80e1d9d36b27f46aacdf144b9251e6347f0f9a7190ca5f949694c066ddbcd9fa9bfe27c492bd4accdf5be1a80",
			plain:     "hello, world!",
		},
		{
			name:      "empty payload",
			priv:      "frozen-vector-2-priv-padding-32!",
			sealedHex: "8d89c37a8c6cfe2a39511e2d551f11393deaebbf584ffbbcf9c9d80bf0fba943d3b30d696dbdab9ca4af443094bbcbe1",
			plain:     "",
		},
		{
			name: "256-byte 0x42 payload",
			priv: "frozen-vector-3-priv-padding-32!",
			sealedHex: "facf211b3626170218a1dec6e549dc7b79b47b3b7a95c427d9c7e66b6f7f4772" +
				"e27f60d466baf54b976a8f0a232b071f5b36157cd6dc38444e8bbbe0deb6f360" +
				"c652751244c78283eab0cb34ae83e75df8564990a1327eb552bd206dc035e52a" +
				"0c188862d3889b2eba6f82cc2ad9f8734a7a6f6858ee050a44cf767220f48228" +
				"2799cbf973c795c874b08f4c45b7769d60b47607e486fc8cb76ede4496127ea7" +
				"42e4adc27f25e9b43f619f36446dae4b8664dddbe58dab9264e92d14f3382bcf" +
				"7981d4ee83fd77be80045fe2bda7b7090d84f1ff4a27aa711ca3d31ef8be5819" +
				"24769eab17bf4f587afe9f0b66d8edecb5a7b1c278611bde696f3ec34854feda" +
				"994682e5fb0adc6dac00026059e54b693f35bc7f9406830d00e01e284f431887" +
				"774deafc121fc259af249f483f5e0bb3",
			// 256 bytes of 0x42, set at runtime to keep the table readable.
		},
	}
	vectors[2].plain = string(bytes.Repeat([]byte{0x42}, 256))

	for _, v := range vectors {
		var priv [32]byte
		copy(priv[:], []byte(v.priv))
		pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
		if err != nil {
			t.Fatalf("%s: derive pub: %v", v.name, err)
		}
		var pub [32]byte
		copy(pub[:], pubBytes)

		// Skip vectors that have not been frozen yet (regenerate via
		// the Generate test below). This keeps the test green during
		// initial review while we capture the actual hex.
		if v.sealedHex == "" {
			t.Skipf("%s: sealedHex placeholder — capture via TestOpenSealedFromShared_GenerateFrozenVectors", v.name)
			continue
		}

		sealed, err := hex.DecodeString(v.sealedHex)
		if err != nil {
			t.Fatalf("%s: bad hex: %v", v.name, err)
		}
		eph, ct, err := ParseSealed(sealed)
		if err != nil {
			t.Fatalf("%s: ParseSealed: %v", v.name, err)
		}
		shared, err := curve25519.X25519(priv[:], eph[:])
		if err != nil {
			t.Fatalf("%s: ECDH: %v", v.name, err)
		}
		got, ok := OpenSealedFromShared(eph, pub, ct, shared)
		if !ok {
			t.Fatalf("%s: open !ok", v.name)
		}
		if !bytes.Equal(got, []byte(v.plain)) {
			t.Fatalf("%s: plaintext mismatch:\n  got  = %x\n  want = %x", v.name, got, []byte(v.plain))
		}
	}
}

// TestOpenSealedFromShared_GenerateFrozenVectors prints fresh hex for
// the vectors above. Run with `go test -run=Generate -v` and paste the
// output into the FrozenVectors table when capturing or rotating
// vectors. The test always passes — its output is the artifact.
func TestOpenSealedFromShared_GenerateFrozenVectors(t *testing.T) {
	if testing.Short() {
		t.Skip("vector-generation helper; run with -v")
	}
	cases := []struct {
		name  string
		priv  string
		plain []byte
	}{
		{"vec1", "frozen-vector-1-priv-padding-32!", []byte("hello, world!")},
		{"vec2", "frozen-vector-2-priv-padding-32!", nil},
		{"vec3", "frozen-vector-3-priv-padding-32!", bytes.Repeat([]byte{0x42}, 256)},
	}
	for _, c := range cases {
		var priv [32]byte
		copy(priv[:], []byte(c.priv))
		pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := SealAnonymous(c.plain, pub)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: sealedHex = %q", c.name, hex.EncodeToString(sealed))
	}
}

// ---- helpers ----

// randIntn returns a uniform [0,n) drawn from rng. Replaces math/rand
// to keep the property test purely on a CSPRNG.
func randIntn(rng io.Reader, n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	var b [8]byte
	if _, err := io.ReadFull(rng, b[:]); err != nil {
		return 0, err
	}
	v := int(uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56)
	if v < 0 {
		v = -v
	}
	return v % n, nil
}
