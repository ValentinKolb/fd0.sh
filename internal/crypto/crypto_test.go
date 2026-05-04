package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// ----- Ed25519 sign/verify -----

func TestEd25519SignVerifyRoundtrip(t *testing.T) {
	pub, priv, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, msg, sig) {
		t.Fatal("valid signature failed to verify")
	}
	// Tampered message → reject.
	if Verify(pub, []byte("tampered"), sig) {
		t.Fatal("modified message should fail verification")
	}
	// Tampered signature → reject.
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	if Verify(pub, msg, bad) {
		t.Fatal("modified signature should fail verification")
	}
	// Wrong-length pub/sig → reject.
	if Verify(pub[:31], msg, sig) {
		t.Fatal("short pub should fail verification")
	}
	if Verify(pub, msg, sig[:63]) {
		t.Fatal("short sig should fail verification")
	}
}

// ----- Ed25519 → X25519 derivation consistency -----

func TestEdToX25519Consistency(t *testing.T) {
	// Property: for any Ed25519 keypair (pub, priv),
	//   X25519Pub(EdPrivToX25519(priv)) == EdPubToX25519(pub)
	// because both compute the Curve25519 public key for the same identity.
	for i := 0; i < 16; i++ {
		pub, priv, err := GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		xPubFromPub, err := EdPubToX25519(pub)
		if err != nil {
			t.Fatalf("iter %d: EdPubToX25519: %v", i, err)
		}
		xPrivScalar, err := EdPrivToX25519(priv)
		if err != nil {
			t.Fatalf("iter %d: EdPrivToX25519: %v", i, err)
		}
		xPubFromPriv, err := X25519Pub(xPrivScalar)
		if err != nil {
			t.Fatalf("iter %d: X25519Pub: %v", i, err)
		}
		if !bytes.Equal(xPubFromPub, xPubFromPriv) {
			t.Fatalf("iter %d: X25519 pub mismatch:\n  from-pub : %x\n  from-priv: %x", i, xPubFromPub, xPubFromPriv)
		}
	}
}

func TestEdPrivToX25519BadInput(t *testing.T) {
	if _, err := EdPrivToX25519([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on too-short priv")
	}
}

func TestEdPubToX25519BadInput(t *testing.T) {
	if _, err := EdPubToX25519([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on too-short pub")
	}
}

// ----- AEAD: AES-256-GCM -----

func TestAEADRoundtrip(t *testing.T) {
	key, _ := RandomBytes(32)
	nonce, _ := Nonce12()
	plain := []byte("the secret payload")
	aad := []byte("scope=foo,version=1")
	ct, err := AEADSeal(key, nonce, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := AEADOpen(key, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypted plaintext mismatch")
	}
}

func TestAEADTamperRejection(t *testing.T) {
	key, _ := RandomBytes(32)
	nonce, _ := Nonce12()
	ct, _ := AEADSeal(key, nonce, []byte("plain"), []byte("aad"))

	// Wrong AAD must reject.
	if _, err := AEADOpen(key, nonce, ct, []byte("aad-different")); err == nil {
		t.Fatal("tampered AAD should fail decrypt")
	}
	// Wrong key must reject.
	otherKey, _ := RandomBytes(32)
	if _, err := AEADOpen(otherKey, nonce, ct, []byte("aad")); err == nil {
		t.Fatal("wrong key should fail decrypt")
	}
	// Wrong nonce must reject.
	otherNonce, _ := Nonce12()
	if _, err := AEADOpen(key, otherNonce, ct, []byte("aad")); err == nil {
		t.Fatal("wrong nonce should fail decrypt")
	}
	// Flipped ciphertext byte must reject.
	bad := append([]byte(nil), ct...)
	bad[0] ^= 1
	if _, err := AEADOpen(key, nonce, bad, []byte("aad")); err == nil {
		t.Fatal("tampered ciphertext should fail decrypt")
	}
}

func TestAEADBadKeySize(t *testing.T) {
	if _, err := AEADSeal(make([]byte, 16), make([]byte, 12), nil, nil); err == nil {
		t.Fatal("expected error on 16-byte key (we require 32)")
	}
}

// ----- Argon2id -----

// Known-answer test for Argon2id. Pins the exact bytes the (Argon2id, m, t,
// p, output=32B) tuple produces for a fixed input. A regression here means
// either the underlying library changed output (rare; Argon2id is RFC 9106
// and stable) or our parameters drifted — investigate either before touching
// this hex string.
func TestArgon2idKAT(t *testing.T) {
	pass := []byte("anchor-password")
	salt := []byte("anchor-salt-0123") // 16 B
	got, err := DeriveKey(pass, salt, Argon2Params{M: 32 * 1024, T: 2, P: 1})
	if err != nil {
		t.Fatal(err)
	}
	const wantHex = "7f229af6faa7bd12a15e06fc2e7143bd1b1243a7e95bae0cabd4d69afd775c43"
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("Argon2id KAT mismatch:\n  got  %x\n  want %s", got, wantHex)
	}
}

func TestArgon2idDeterministic(t *testing.T) {
	pass := []byte("correct horse battery staple")
	salt := bytes.Repeat([]byte{0xab}, 16)
	a, err := DeriveKey(pass, salt, DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKey(pass, salt, DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("Argon2id not deterministic for identical inputs")
	}
	if len(a) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(a))
	}
	// Different password → different key.
	c, err := DeriveKey([]byte("other"), salt, DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("different password produced same key")
	}
	// Different salt → different key.
	otherSalt := bytes.Repeat([]byte{0xcd}, 16)
	d, err := DeriveKey(pass, otherSalt, DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, d) {
		t.Fatal("different salt produced same key")
	}
}

// TestArgon2idValidationRejectsBadParams locks in the codex 🔴 fix:
// caller-supplied Argon2 params from an untrusted vault header
// MUST be rejected with an error (not a panic / OOM).
func TestArgon2idValidationRejectsBadParams(t *testing.T) {
	pass := []byte("x")
	salt := []byte("anchor-salt-0123")
	bad := []Argon2Params{
		{M: 32 * 1024, T: 0, P: 1},        // T==0 would panic in argon2.IDKey
		{M: 32 * 1024, T: 2, P: 0},        // P==0 likewise
		{M: 0, T: 2, P: 1},                // M too small
		{M: 8 * 1024, T: 2, P: 1},         // M below MinArgon2
		{M: 1024 * 1024 * 4, T: 2, P: 1},  // M above MaxArgon2 (4 GiB)
		{M: 32 * 1024, T: 1024, P: 1},     // T above MaxArgon2
		{M: 32 * 1024, T: 2, P: 64},       // P above MaxArgon2
	}
	for i, p := range bad {
		if _, err := DeriveKey(pass, salt, p); err == nil {
			t.Errorf("case %d: DeriveKey accepted bad params %+v", i, p)
		}
	}
}

// TestEdPrivToX25519NoCapLeak locks in the codex 🔴 fix: the
// returned scalar must NOT alias an internal SHA-512 buffer with
// extra capacity holding the Ed25519 prefix.
func TestEdPrivToX25519NoCapLeak(t *testing.T) {
	_, priv, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	x, err := EdPrivToX25519(priv)
	if err != nil {
		t.Fatal(err)
	}
	if cap(x) != len(x) {
		t.Fatalf("EdPrivToX25519 result has cap %d > len %d — caller could re-slice to read SHA-512 prefix", cap(x), len(x))
	}
	// Re-slicing to capacity must NOT yield additional bytes.
	full := x[:cap(x)]
	if len(full) != 32 {
		t.Fatalf("re-slice to cap returned %d bytes (want 32)", len(full))
	}
}

// ----- Sealed-box (libsodium crypto_box_seal) -----

func TestSealedBoxRoundtrip(t *testing.T) {
	pub, priv, _ := GenerateIdentity()
	xPub, _ := EdPubToX25519(pub)
	xPriv, _ := EdPrivToX25519(priv)

	plain := []byte("a 32-byte OEK or whatever blob")
	sealed, err := SealAnonymous(plain, xPub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed, plain) {
		t.Fatal("sealed equals plain")
	}
	got, ok := OpenAnonymous(sealed, xPub, xPriv)
	if !ok {
		t.Fatal("OpenAnonymous failed for valid sealed-box")
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("plaintext mismatch")
	}
}

func TestSealedBoxWrongRecipient(t *testing.T) {
	pubA, _, _ := GenerateIdentity()
	xPubA, _ := EdPubToX25519(pubA)

	_, privB, _ := GenerateIdentity()
	xPrivB, _ := EdPrivToX25519(privB)

	sealed, _ := SealAnonymous([]byte("for A"), xPubA)
	xPubB, _ := X25519Pub(xPrivB)
	if _, ok := OpenAnonymous(sealed, xPubB, xPrivB); ok {
		t.Fatal("wrong recipient should not open")
	}
}

func TestSealedBoxBadInputs(t *testing.T) {
	if _, err := SealAnonymous([]byte("x"), []byte{1, 2}); err == nil {
		t.Fatal("expected error on too-short pub")
	}
	if _, ok := OpenAnonymous(nil, []byte{1, 2}, []byte{3, 4}); ok {
		t.Fatal("expected failure on short keys")
	}
}

// ----- Random + nonce uniqueness -----

func TestRandomBytesUnique(t *testing.T) {
	a, _ := RandomBytes(32)
	b, _ := RandomBytes(32)
	if bytes.Equal(a, b) {
		t.Fatal("two RandomBytes calls returned identical bytes")
	}
}

func TestNonce12Length(t *testing.T) {
	for i := 0; i < 8; i++ {
		n, err := Nonce12()
		if err != nil {
			t.Fatal(err)
		}
		if len(n) != 12 {
			t.Fatalf("Nonce12 returned %d bytes, want 12", len(n))
		}
	}
}

// ----- Secret (memguard wrapper) -----

func TestSecretLifecycle(t *testing.T) {
	src := bytes.Repeat([]byte{0xa5}, 32)
	s := NewSecretCopy(src)
	if s.Len() != 32 {
		t.Fatalf("Len got %d, want 32", s.Len())
	}
	if !bytes.Equal(s.Bytes(), src) {
		t.Fatal("Bytes mismatch")
	}
	if !s.Equal(src) {
		t.Fatal("Equal should hold")
	}
	if s.Equal(bytes.Repeat([]byte{0x5a}, 32)) {
		t.Fatal("Equal should fail for different content")
	}
	s.Destroy()
	// After Destroy: Len == 0, Bytes returns nil.
	if s.Len() != 0 {
		t.Fatal("Destroyed secret should report Len 0")
	}
	if s.Bytes() != nil {
		t.Fatal("Destroyed secret should return nil bytes")
	}
}

func TestSecretNilSafe(t *testing.T) {
	var s *Secret
	if s.Len() != 0 {
		t.Fatal("nil Secret Len should be 0")
	}
	if s.Bytes() != nil {
		t.Fatal("nil Secret Bytes should be nil")
	}
	s.Destroy() // must not panic
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("Wipe missed byte %d (=%d)", i, v)
		}
	}
}

// ----- Sanity: ed25519 std private-key shape -----

func TestEd25519PrivateKeyShape(t *testing.T) {
	pub, priv, _ := GenerateIdentity()
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("ed25519 private key size %d != %d", len(priv), ed25519.PrivateKeySize)
	}
	// stdlib stores priv as seed||pub
	if !bytes.Equal(priv[32:], pub) {
		t.Fatal("priv[32:] should equal pub (stdlib invariant)")
	}
}
