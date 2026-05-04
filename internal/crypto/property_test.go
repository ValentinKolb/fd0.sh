package crypto

import (
	"bytes"
	"math/rand"
	"testing"
)

// Property tests for the AEAD + X25519 primitives. Each property
// runs over a SEEDED PRNG (math/rand) so failures are reproducible
// from the printed seed. Edge sizes (0, 1, near-max) are exercised
// explicitly via prepended cases — uniform random distribution
// would only hit them with low probability.
//
// The contract under test:
//
//   - AEAD encrypt-then-decrypt with identical (key, nonce, aad)
//     MUST recover the exact plaintext bit-for-bit.
//   - AEAD with ANY mutation of (key, nonce, ct, aad) MUST fail.
//   - Same inputs MUST yield byte-identical ct (AES-GCM is
//     deterministic given (key, nonce, plain, aad)).
//   - 1-bit plaintext flip MUST yield different ct (sanity that
//     plaintext actually drives the keystream/tag).
//   - Wrong key/nonce sizes MUST be rejected at seal time.
//   - X25519 mapping is deterministic per Ed25519 pub/priv pair,
//     and the converted (pub, priv) is a working sealed-box pair.
//   - Sealed boxes opened with the wrong recipient MUST fail.

const aeadIterations = 200

func TestPropertyAEADRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(0xA1AD))
	cases := edgePlainSizes(aeadIterations, r)
	for i, plainSize := range cases {
		key := randSeeded(r, 32)
		nonce := randSeeded(r, 12)
		plain := randSeeded(r, plainSize)
		aad := randSeeded(r, edgeAADSize(i, r))

		ct, err := AEADSeal(key, nonce, plain, aad)
		if err != nil {
			t.Fatalf("seed=0xA1AD i=%d (plain=%d aad=%d): seal: %v", i, plainSize, len(aad), err)
		}
		if len(ct) != plainSize+16 {
			t.Fatalf("seed=0xA1AD i=%d: ct length %d, want %d", i, len(ct), plainSize+16)
		}
		recovered, err := AEADOpen(key, nonce, ct, aad)
		if err != nil {
			t.Fatalf("seed=0xA1AD i=%d: open: %v", i, err)
		}
		if !bytes.Equal(plain, recovered) {
			t.Fatalf("seed=0xA1AD i=%d: roundtrip mismatch (plain=%d aad=%d)", i, plainSize, len(aad))
		}
	}
}

func TestPropertyAEADTamperRejects(t *testing.T) {
	r := rand.New(rand.NewSource(0x7AAA))
	for i := 0; i < aeadIterations; i++ {
		key := randSeeded(r, 32)
		nonce := randSeeded(r, 12)
		plain := randSeeded(r, 1+r.Intn(256))
		aad := randSeeded(r, r.Intn(64))
		ct, err := AEADSeal(key, nonce, plain, aad)
		if err != nil {
			t.Fatal(err)
		}

		switch i % 4 {
		case 0:
			tampered := append([]byte(nil), key...)
			tampered[r.Intn(len(tampered))] ^= 0x01
			if _, err := AEADOpen(tampered, nonce, ct, aad); err == nil {
				t.Fatalf("seed=0x7AAA i=%d: tampered key did not reject", i)
			}
		case 1:
			tampered := append([]byte(nil), nonce...)
			tampered[r.Intn(len(tampered))] ^= 0x01
			if _, err := AEADOpen(key, tampered, ct, aad); err == nil {
				t.Fatalf("seed=0x7AAA i=%d: tampered nonce did not reject", i)
			}
		case 2:
			tampered := append([]byte(nil), ct...)
			tampered[r.Intn(len(tampered))] ^= 0x01
			if _, err := AEADOpen(key, nonce, tampered, aad); err == nil {
				t.Fatalf("seed=0x7AAA i=%d: tampered ct did not reject", i)
			}
		case 3:
			if len(aad) == 0 {
				continue
			}
			tampered := append([]byte(nil), aad...)
			tampered[r.Intn(len(tampered))] ^= 0x01
			if _, err := AEADOpen(key, nonce, ct, tampered); err == nil {
				t.Fatalf("seed=0x7AAA i=%d: tampered aad did not reject", i)
			}
		}
	}
}

// TestPropertyAEADDeterminismAndSensitivity locks in two AES-GCM
// invariants: same (key, nonce, plain, aad) yields the SAME ct;
// any 1-bit plaintext flip yields a DIFFERENT ct. The latter would
// silently fail if the implementation reused a static keystream
// regardless of input — the kind of bug only a property test
// would surface.
func TestPropertyAEADDeterminismAndSensitivity(t *testing.T) {
	r := rand.New(rand.NewSource(0xDD55))
	for i := 0; i < 100; i++ {
		key := randSeeded(r, 32)
		nonce := randSeeded(r, 12)
		plain := randSeeded(r, 64)
		aad := randSeeded(r, 16)
		ct1, _ := AEADSeal(key, nonce, plain, aad)
		ct2, _ := AEADSeal(key, nonce, plain, aad)
		if !bytes.Equal(ct1, ct2) {
			t.Fatalf("seed=0xDD55 i=%d: identical inputs yielded different ct", i)
		}
		plain2 := append([]byte(nil), plain...)
		plain2[0] ^= 0x01
		ct3, _ := AEADSeal(key, nonce, plain2, aad)
		if bytes.Equal(ct1, ct3) {
			t.Fatalf("seed=0xDD55 i=%d: 1-bit plaintext flip yielded identical ct (key/nonce reuse vuln)", i)
		}
	}
}

func TestPropertyAEADWrongKeySizeRejects(t *testing.T) {
	r := rand.New(rand.NewSource(0xBADD))
	for _, sz := range []int{0, 1, 15, 16, 24, 31, 33, 64} {
		key := randSeeded(r, sz)
		nonce := randSeeded(r, 12)
		_, err := AEADSeal(key, nonce, []byte("plain"), nil)
		if err == nil {
			t.Fatalf("seal with %d-byte key should fail", sz)
		}
	}
}

func TestPropertyAEADWrongNonceSizeRejects(t *testing.T) {
	r := rand.New(rand.NewSource(0xBADE))
	key := randSeeded(r, 32)
	for _, sz := range []int{0, 1, 8, 11, 13, 16, 24} {
		nonce := randSeeded(r, sz)
		_, err := AEADSeal(key, nonce, []byte("plain"), nil)
		if err == nil {
			t.Fatalf("seal with %d-byte nonce should fail", sz)
		}
	}
}

// TestPropertyAEADOpenWrongSizesReject locks the symmetric guarantee
// at decrypt-time: AEADOpen must reject (not panic) when given a
// wrong-size key, wrong-size nonce, or truncated/short ciphertext.
// Without this, an attacker who can influence sizes could trigger
// a panic and DOS a verifier.
func TestPropertyAEADOpenWrongSizesReject(t *testing.T) {
	r := rand.New(rand.NewSource(0xBADC))
	key := randSeeded(r, 32)
	nonce := randSeeded(r, 12)
	ct, err := AEADSeal(key, nonce, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, ks := range []int{0, 1, 15, 16, 24, 31, 33, 64} {
		bad := randSeeded(r, ks)
		_, err := AEADOpen(bad, nonce, ct, nil)
		if err == nil {
			t.Fatalf("open with %d-byte key should fail", ks)
		}
	}
	for _, ns := range []int{0, 1, 8, 11, 13, 16, 24} {
		bad := randSeeded(r, ns)
		_, err := AEADOpen(key, bad, ct, nil)
		if err == nil {
			t.Fatalf("open with %d-byte nonce should fail", ns)
		}
	}
	// Truncation: any prefix shorter than the GCM tag (16) must fail.
	for _, n := range []int{0, 1, 5, 15} {
		_, err := AEADOpen(key, nonce, ct[:n], nil)
		if err == nil {
			t.Fatalf("open with %d-byte truncated ct should fail", n)
		}
	}
	// Extra trailing byte: also rejected.
	withExtra := append(append([]byte(nil), ct...), 0x42)
	if _, err := AEADOpen(key, nonce, withExtra, nil); err == nil {
		t.Fatal("open with appended byte should fail")
	}
}

// TestPropertyEdToX25519Consistency: for every Ed25519 keypair, the
// X25519 conversion of pub MUST match the X25519-pub derived from
// the converted X25519-priv. Without this invariant, sealed boxes
// addressed to a recipient's converted pub could not be opened by
// the recipient using their converted priv.
func TestPropertyEdToX25519Consistency(t *testing.T) {
	for i := 0; i < 50; i++ {
		pub, priv, err := GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		xPub, err := EdPubToX25519(pub.Bytes())
		if err != nil {
			t.Fatalf("iter=%d: EdPubToX25519: %v", i, err)
		}
		xPriv, err := EdPrivToX25519(priv.Bytes())
		if err != nil {
			t.Fatalf("iter=%d: EdPrivToX25519: %v", i, err)
		}

		// Sealed-box: encrypt to xPub, open with (xPub, xPriv).
		// If the conversion drifted, this would silently fail.
		plain := []byte("property test plaintext")
		sealed, err := SealAnonymous(plain, xPub)
		if err != nil {
			t.Fatalf("iter=%d: SealAnonymous: %v", i, err)
		}
		opened, ok := OpenAnonymous(sealed, xPub, xPriv)
		if !ok || !bytes.Equal(opened, plain) {
			t.Fatalf("iter=%d: sealed-box roundtrip failed (pub/priv conversion drift)", i)
		}
	}
}

// TestPropertyEdToX25519Deterministic: the conversion is a pure
// function — calling EdPubToX25519 twice on the same input yields
// byte-identical output.
func TestPropertyEdToX25519Deterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		pub, priv, err := GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		x1, _ := EdPubToX25519(pub.Bytes())
		x2, _ := EdPubToX25519(pub.Bytes())
		if !bytes.Equal(x1, x2) {
			t.Fatalf("iter=%d: EdPubToX25519 non-deterministic", i)
		}
		p1, _ := EdPrivToX25519(priv.Bytes())
		p2, _ := EdPrivToX25519(priv.Bytes())
		if !bytes.Equal(p1, p2) {
			t.Fatalf("iter=%d: EdPrivToX25519 non-deterministic", i)
		}
	}
}

// TestPropertySealedBoxTamperRejects: any single-bit mutation of a
// sealed box (ephemeral pub or ciphertext) MUST cause OpenAnonymous
// to fail. Exercises the implicit tag/MAC across the full envelope.
// Truncation (any prefix shorter than ephPub+1+tag) must also fail.
func TestPropertySealedBoxTamperRejects(t *testing.T) {
	r := rand.New(rand.NewSource(0xBEEF))
	for i := 0; i < 50; i++ {
		pub, priv, _ := GenerateIdentity()
		xPub, _ := EdPubToX25519(pub.Bytes())
		xPriv, _ := EdPrivToX25519(priv.Bytes())
		plain := randSeeded(r, 16+r.Intn(64))
		sealed, err := SealAnonymous(plain, xPub)
		if err != nil {
			t.Fatal(err)
		}
		// Baseline: opens.
		if _, ok := OpenAnonymous(sealed, xPub, xPriv); !ok {
			t.Fatalf("iter=%d: baseline open failed", i)
		}
		// Flip one byte at a random position.
		tampered := append([]byte(nil), sealed...)
		idx := r.Intn(len(tampered))
		tampered[idx] ^= 0x01
		if _, ok := OpenAnonymous(tampered, xPub, xPriv); ok {
			t.Fatalf("iter=%d: 1-bit flip at pos %d (of %d) opened", i, idx, len(sealed))
		}
		// Truncated to anything less than full length must fail.
		for _, cut := range []int{0, 1, 16, len(sealed) - 1} {
			if cut < 0 || cut >= len(sealed) {
				continue
			}
			if _, ok := OpenAnonymous(sealed[:cut], xPub, xPriv); ok {
				t.Fatalf("iter=%d: truncated to %d/%d opened", i, cut, len(sealed))
			}
		}
	}
}

// TestPropertySealedBoxWrongRecipientRejects: a sealed box addressed
// to recipient A MUST fail to open under recipient B's keypair. This
// is exercised in focused tests already; the property version runs
// at scale to catch any nondeterministic acceptance.
func TestPropertySealedBoxWrongRecipientRejects(t *testing.T) {
	for i := 0; i < 100; i++ {
		pubA, privA, _ := GenerateIdentity()
		pubB, privB, _ := GenerateIdentity()
		xPubA, _ := EdPubToX25519(pubA.Bytes())
		xPubB, _ := EdPubToX25519(pubB.Bytes())
		xPrivA, _ := EdPrivToX25519(privA.Bytes())
		xPrivB, _ := EdPrivToX25519(privB.Bytes())

		plain := []byte("for A only")
		sealed, err := SealAnonymous(plain, xPubA)
		if err != nil {
			t.Fatal(err)
		}
		// A opens fine.
		opened, ok := OpenAnonymous(sealed, xPubA, xPrivA)
		if !ok || !bytes.Equal(opened, plain) {
			t.Fatalf("iter=%d: A failed to open own sealed box", i)
		}
		// B with B's keypair fails.
		if _, ok := OpenAnonymous(sealed, xPubB, xPrivB); ok {
			t.Fatalf("iter=%d: B opened A's sealed box (catastrophic)", i)
		}
		// B's pub + A's priv fails (mismatched halves).
		if _, ok := OpenAnonymous(sealed, xPubB, xPrivA); ok {
			t.Fatalf("iter=%d: opened with mismatched pub/priv halves", i)
		}
	}
}

// ---- helpers ----

// edgePlainSizes returns a sequence of plaintext sizes for the
// roundtrip property: explicit edges first (0, 1, 15, 16, 17, 4095,
// 4096), then random sizes filling the rest.
func edgePlainSizes(total int, r *rand.Rand) []int {
	edges := []int{0, 1, 15, 16, 17, 31, 32, 33, 4095, 4096}
	out := make([]int, 0, total)
	out = append(out, edges...)
	for len(out) < total {
		out = append(out, r.Intn(4097))
	}
	return out
}

// edgeAADSize returns either an edge size or a random size; called
// per iteration so AAD varies independently of plaintext.
func edgeAADSize(i int, r *rand.Rand) int {
	switch i {
	case 0:
		return 0
	case 1:
		return 1
	case 2:
		return 256
	default:
		return r.Intn(257)
	}
}

func randSeeded(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	if n > 0 {
		_, _ = r.Read(b)
	}
	return b
}
