package yubikey

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// MockCard is a software implementation of the Card interface used for
// unit and property tests. It holds an X25519 keypair in process memory
// and runs ECDH via the standard golang.org/x/crypto/curve25519 path.
//
// Use this anywhere the production code would consume a Card and
// hardware is not available — including: pure crypto roundtrip tests,
// the sealed-box recorder's self-tests, and integration paths that
// exercise the agent + sync code without a YubiKey on the bench.
//
// MockCard is read-only after construction and therefore safe for
// concurrent use across goroutines.
type MockCard struct {
	// priv is the 32-byte X25519 scalar. Stored in plain memory; this
	// type is for tests only and is NOT a substitute for the on-card
	// path in production.
	priv [32]byte
	// pub is curve25519.X25519(priv, basepoint), cached at
	// construction so PublicX25519 is O(1) and allocation-free.
	pub [32]byte
}

// ErrMockCardBadPriv is returned by NewMockCardFromPriv when the supplied
// scalar is the wrong length.
var ErrMockCardBadPriv = errors.New("yubikey: MockCard priv must be 32 bytes")

// NewMockCard generates a fresh X25519 keypair from the supplied entropy
// source. Pass crypto/rand.Reader for normal use; a deterministic
// io.Reader for reproducible tests.
func NewMockCard(rng io.Reader) (*MockCard, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var priv [32]byte
	if _, err := io.ReadFull(rng, priv[:]); err != nil {
		return nil, err
	}
	return mockCardFromPrivArray(priv)
}

// NewMockCardFromPriv constructs a MockCard from a caller-supplied
// 32-byte X25519 scalar. Useful for golden-vector replay where the
// keypair must be deterministic.
//
// The function copies priv; the caller's slice is never retained.
func NewMockCardFromPriv(priv []byte) (*MockCard, error) {
	if len(priv) != 32 {
		return nil, ErrMockCardBadPriv
	}
	var p [32]byte
	copy(p[:], priv)
	return mockCardFromPrivArray(p)
}

func mockCardFromPrivArray(priv [32]byte) (*MockCard, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	c := &MockCard{priv: priv}
	copy(c.pub[:], pub)
	return c, nil
}

// PublicX25519 returns a fresh copy of the cached 32-byte pubkey.
func (c *MockCard) PublicX25519() ([]byte, error) {
	out := make([]byte, 32)
	copy(out, c.pub[:])
	return out, nil
}

// SharedSecret computes X25519(priv, ephPub).
//
// curve25519.X25519 itself enforces RFC 7748 §6.1 contributory-behaviour
// rejection (returns an error on the small-subgroup low-order points),
// so callers can rely on a non-nil error to mean "do not use this
// shared secret".
func (c *MockCard) SharedSecret(ephPub []byte) ([]byte, error) {
	if len(ephPub) != 32 {
		return nil, errors.New("yubikey: MockCard.SharedSecret: ephPub must be 32 bytes")
	}
	return curve25519.X25519(c.priv[:], ephPub)
}

// Close is a no-op for software cards.
func (c *MockCard) Close() error { return nil }

// Compile-time check: MockCard satisfies Card.
var _ Card = (*MockCard)(nil)
