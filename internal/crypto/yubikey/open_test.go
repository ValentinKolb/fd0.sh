package yubikey

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
)

// Happy path: MockCard + SealAnonymous → OpenSealedBox round-trips
// arbitrary plaintext lengths. This is the test that proves the
// pure-software path is end-to-end correct without any hardware.
func TestOpenSealedBox_MockCardRoundtrip(t *testing.T) {
	t.Parallel()
	card, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatalf("MockCard: %v", err)
	}
	pub, _ := card.PublicX25519()
	for _, n := range []int{0, 1, 13, 256, 4096} {
		plain := make([]byte, n)
		if _, err := rand.Read(plain); err != nil {
			t.Fatal(err)
		}
		sealed, err := crypto.SealAnonymous(plain, pub)
		if err != nil {
			t.Fatalf("len=%d: SealAnonymous: %v", n, err)
		}
		got, err := OpenSealedBox(card, sealed)
		if err != nil {
			t.Fatalf("len=%d: OpenSealedBox: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("len=%d: plaintext mismatch", n)
		}
	}
}

func TestOpenSealedBox_RejectsNilCard(t *testing.T) {
	t.Parallel()
	_, err := OpenSealedBox(nil, make([]byte, 48))
	if err == nil {
		t.Fatalf("expected error for nil card, got nil")
	}
}

// Classic Go gotcha: a nil pointer wrapped in a non-nil interface.
// Without the typed-nil guard inside OpenSealedBox, every method call
// would SIGSEGV. We test the most likely real-world case
// (var c Card = (*MockCard)(nil)) explicitly.
func TestOpenSealedBox_RejectsTypedNilCard(t *testing.T) {
	t.Parallel()
	var c Card = (*MockCard)(nil)
	_, err := OpenSealedBox(c, make([]byte, 48))
	if err == nil {
		t.Fatalf("expected error for typed-nil card, got nil")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Fatalf("error should mention nil, got: %v", err)
	}
}

func TestOpenSealedBox_PropagatesParseError(t *testing.T) {
	t.Parallel()
	card, _ := NewMockCard(rand.Reader)
	_, err := OpenSealedBox(card, []byte("too-short"))
	if err == nil {
		t.Fatalf("expected error on short input, got nil")
	}
	if !errors.Is(err, crypto.ErrSealedTooShort) {
		t.Fatalf("error chain missing ErrSealedTooShort: %v", err)
	}
}

func TestOpenSealedBox_PropagatesPubkeyError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("pub-broken-sentinel")
	stub := &stubCard{pubErr: sentinel}
	_, err := OpenSealedBox(stub, validSealedBlob(t))
	if err == nil {
		t.Fatalf("expected error from pubkey fetch, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("error chain missing sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "card pubkey") {
		t.Fatalf("error missing 'card pubkey' context: %v", err)
	}
}

func TestOpenSealedBox_RejectsBadPubkeyLength(t *testing.T) {
	t.Parallel()
	stub := &stubCard{pub: make([]byte, 31)}
	_, err := OpenSealedBox(stub, validSealedBlob(t))
	if err == nil {
		t.Fatalf("expected error on 31-byte pubkey, got nil")
	}
}

func TestOpenSealedBox_PropagatesSharedSecretError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("ecdh-broken-sentinel")
	stub := &stubCard{
		pub:       make([]byte, 32), // valid length so SharedSecret is reached
		sharedErr: sentinel,
	}
	_, err := OpenSealedBox(stub, validSealedBlob(t))
	if err == nil {
		t.Fatalf("expected error from SharedSecret, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("error chain missing sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "shared secret") {
		t.Fatalf("error missing 'shared secret' context: %v", err)
	}
}

func TestOpenSealedBox_PropagatesAEADFailure(t *testing.T) {
	t.Parallel()
	// Two MockCards: one is the recipient (sealed for); the other is
	// the "wrong" card whose ECDH output won't match.
	right, _ := NewMockCard(rand.Reader)
	wrong, _ := NewMockCard(rand.Reader)
	pubRight, _ := right.PublicX25519()
	sealed, err := crypto.SealAnonymous([]byte("payload"), pubRight)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSealedBox(wrong, sealed)
	if err == nil {
		t.Fatalf("expected AEAD failure when wrong card opens, got nil")
	}
	if !errors.Is(err, crypto.ErrSealedAEAD) {
		t.Fatalf("error chain missing ErrSealedAEAD: %v", err)
	}
}

// MockCard end-to-end across many random pairs. This is the broadest
// test in the package — sustained property coverage for the whole
// hardware-substituted path.
func TestOpenSealedBox_PropertyMockCard(t *testing.T) {
	t.Parallel()
	for i := 0; i < 100; i++ {
		card, err := NewMockCard(rand.Reader)
		if err != nil {
			t.Fatalf("iter=%d: MockCard: %v", i, err)
		}
		pub, _ := card.PublicX25519()

		plainLen, err := readByte(rand.Reader)
		if err != nil {
			t.Fatalf("iter=%d: rng len: %v", i, err)
		}
		plain := make([]byte, int(plainLen)+1)
		if _, err := rand.Read(plain); err != nil {
			t.Fatalf("iter=%d: rng plain: %v", i, err)
		}

		sealed, err := crypto.SealAnonymous(plain, pub)
		if err != nil {
			t.Fatalf("iter=%d: SealAnonymous: %v", i, err)
		}
		got, err := OpenSealedBox(card, sealed)
		if err != nil {
			t.Fatalf("iter=%d: OpenSealedBox: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("iter=%d: plaintext mismatch", i)
		}
	}
}

// ---- helpers ----

// stubCard is a Card whose every method can be made to fail. Used to
// drive the error-propagation tests without setting up a real
// MockCard for each case.
type stubCard struct {
	pub       []byte
	pubErr    error
	sharedErr error
}

func (s *stubCard) PublicX25519() ([]byte, error) {
	if s.pubErr != nil {
		return nil, s.pubErr
	}
	return append([]byte(nil), s.pub...), nil
}

func (s *stubCard) SharedSecret(ephPub []byte) ([]byte, error) {
	if s.sharedErr != nil {
		return nil, s.sharedErr
	}
	// Return a non-degenerate constant; AEAD will fail downstream
	// because it has no relation to the recipient's actual scalar.
	out := make([]byte, 32)
	out[0] = 0x42
	return out, nil
}

func (s *stubCard) Close() error { return nil }

// validSealedBlob produces a length-valid (parse-passing) blob using
// a fresh MockCard, so error tests can drive the OpenSealedBox path
// past ParseSealed without colliding with that error.
func validSealedBlob(t *testing.T) []byte {
	t.Helper()
	card, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := card.PublicX25519()
	sealed, err := crypto.SealAnonymous([]byte("placeholder"), pub)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func readByte(r interface{ Read([]byte) (int, error) }) (byte, error) {
	var b [1]byte
	if _, err := r.Read(b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}
