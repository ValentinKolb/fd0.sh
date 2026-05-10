package yubikey

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestMockCard_NewMockCard_FreshKey(t *testing.T) {
	t.Parallel()
	c1, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatalf("NewMockCard: %v", err)
	}
	c2, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatalf("NewMockCard: %v", err)
	}
	p1, err := c1.PublicX25519()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := c2.PublicX25519()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(p1, p2) {
		t.Fatalf("two fresh MockCards produced the same pubkey — RNG broken or constructor caching")
	}
}

func TestMockCard_NewMockCard_NilRNG_UsesRandReader(t *testing.T) {
	t.Parallel()
	// Passing nil should not panic and should produce a valid card.
	c, err := NewMockCard(nil)
	if err != nil {
		t.Fatalf("NewMockCard(nil): %v", err)
	}
	pub, err := c.PublicX25519()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 32 {
		t.Fatalf("pub len: have %d, want 32", len(pub))
	}
}

func TestMockCard_NewMockCard_DeterministicWithSeededRNG(t *testing.T) {
	t.Parallel()
	c1, err := NewMockCard(bytes.NewReader(deterministicSeed(1)))
	if err != nil {
		t.Fatalf("c1: %v", err)
	}
	c2, err := NewMockCard(bytes.NewReader(deterministicSeed(1)))
	if err != nil {
		t.Fatalf("c2: %v", err)
	}
	p1, _ := c1.PublicX25519()
	p2, _ := c2.PublicX25519()
	if !bytes.Equal(p1, p2) {
		t.Fatalf("same seed should produce same pubkey")
	}
}

func TestMockCard_NewMockCard_RNGError(t *testing.T) {
	t.Parallel()
	_, err := NewMockCard(failingReader{})
	if err == nil {
		t.Fatalf("expected error from failingReader, got nil")
	}
}

func TestMockCard_NewMockCardFromPriv_RejectsBadLength(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 31, 33, 64} {
		_, err := NewMockCardFromPriv(make([]byte, n))
		if !errors.Is(err, ErrMockCardBadPriv) {
			t.Fatalf("len=%d: want ErrMockCardBadPriv, got %v", n, err)
		}
	}
}

func TestMockCard_NewMockCardFromPriv_CopiesInput(t *testing.T) {
	t.Parallel()
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = 0xCD
	}
	c, err := NewMockCardFromPriv(priv)
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	for i := range priv {
		priv[i] = 0
	}
	// SharedSecret with a fresh eph keypair must still produce a valid
	// non-zero shared secret if the constructor copied priv.
	ephPriv := deterministicSeed(2)
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := c.SharedSecret(ephPub)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	if isAllZero(shared) {
		t.Fatalf("shared secret all-zero — constructor did not copy priv")
	}
}

func TestMockCard_PublicX25519_ReturnsFreshCopy(t *testing.T) {
	t.Parallel()
	c, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := c.PublicX25519()
	for i := range p1 {
		p1[i] = 0
	}
	p2, _ := c.PublicX25519()
	if isAllZero(p2) {
		t.Fatalf("PublicX25519 returned an alias — caller mutation poisoned subsequent reads")
	}
}

func TestMockCard_SharedSecret_RejectsBadEphLength(t *testing.T) {
	t.Parallel()
	c, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		_, err := c.SharedSecret(make([]byte, n))
		if err == nil {
			t.Fatalf("eph len=%d: expected error, got nil", n)
		}
	}
}

// SharedSecret(card_priv, eph_pub) must equal SharedSecret(eph_priv,
// card_pub) — that is the ECDH symmetry property. Test 200 random
// pairs, fail on first mismatch.
func TestMockCard_SharedSecret_ECDHSymmetry(t *testing.T) {
	t.Parallel()
	for iter := 0; iter < 200; iter++ {
		card, err := NewMockCard(rand.Reader)
		if err != nil {
			t.Fatalf("iter=%d: card ctor: %v", iter, err)
		}
		ephPriv := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, ephPriv); err != nil {
			t.Fatalf("iter=%d: read eph priv: %v", iter, err)
		}
		ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
		if err != nil {
			t.Fatalf("iter=%d: eph pub: %v", iter, err)
		}
		fromCard, err := card.SharedSecret(ephPub)
		if err != nil {
			t.Fatalf("iter=%d: card.SharedSecret: %v", iter, err)
		}
		cardPub, _ := card.PublicX25519()
		fromEph, err := curve25519.X25519(ephPriv, cardPub)
		if err != nil {
			t.Fatalf("iter=%d: eph-side ECDH: %v", iter, err)
		}
		if !bytes.Equal(fromCard, fromEph) {
			t.Fatalf("iter=%d: ECDH asymmetry: card=%x eph=%x", iter, fromCard, fromEph)
		}
		if isAllZero(fromCard) {
			t.Fatalf("iter=%d: shared secret all-zero", iter)
		}
	}
}

// curve25519.X25519 returns an error on small-subgroup inputs that
// produce an all-zero shared secret. MockCard.SharedSecret must
// propagate that error so callers can hard-refuse.
//
// The vectors below are the canonical low-order X25519 points that
// every implementation MUST reject. A hardware Card must produce the
// same behaviour, so the same table is reused in any future
// hardware-day verification suite. Source: RFC 7748 §6.1 / libsodium
// crypto_scalarmult_curve25519_ref10_check_input.
func TestMockCard_SharedSecret_RejectsSmallSubgroup(t *testing.T) {
	t.Parallel()
	lowOrder := [][]byte{
		// 0
		hexBytes(t, "0000000000000000000000000000000000000000000000000000000000000000"),
		// 1
		hexBytes(t, "0100000000000000000000000000000000000000000000000000000000000000"),
		// 325606250916557431795983626356110631294008115727848805560023387167927233504
		hexBytes(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		// 39382357235489614581723060781553021112529911719440698176882885853963445705823
		hexBytes(t, "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
		// p − 1
		hexBytes(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		// p
		hexBytes(t, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		// p + 1
		hexBytes(t, "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	}
	c, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i, eph := range lowOrder {
		_, err := c.SharedSecret(eph)
		if err == nil {
			t.Fatalf("vector[%d]: expected error on low-order ephPub %x, got nil", i, eph)
		}
	}
}

// MockCard MUST satisfy the shared Card contract. This pins the
// contract for downstream fakes that compose with MockCard.
func TestMockCard_AssertContract(t *testing.T) {
	t.Parallel()
	c, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	AssertCardContract(t, "MockCard", c)
}

func TestMockCard_Close_IsNoop(t *testing.T) {
	t.Parallel()
	c, _ := NewMockCard(rand.Reader)
	if err := c.Close(); err != nil {
		t.Fatalf("Close should be a no-op, got %v", err)
	}
	// Idempotent.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}
}

// ---- helpers ----

func deterministicSeed(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) { return 0, errors.New("rng broken") }

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
