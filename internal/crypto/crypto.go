// Package crypto wraps the small set of primitives fd0 uses, with helpers
// that bind each call site to its domain separator (PROTOCOL.md §1).
//
// Identity keys are Ed25519. X25519 ECDH keys are derived from Ed25519 by
// crypto_sign_ed25519_pk_to_curve25519 / sk_to_curve25519 (§1.2). AEAD is
// AES-256-GCM. Sealed-box is libsodium-compatible (nacl/box.SealAnonymous).
// Argon2id is the only passphrase KDF.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// ---- Random ----

// RandomBytes returns n cryptographically-random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Nonce12 returns 12 random bytes (AEAD nonce).
func Nonce12() ([]byte, error) { return RandomBytes(12) }

// ---- Ed25519 ----

// GenerateIdentity creates a fresh Ed25519 keypair. The private key is the
// 64-byte expanded form (seed||public); callers must keep it locked.
func GenerateIdentity() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

// Sign produces an Ed25519 signature over msg with priv.
func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify returns true iff sig is a valid Ed25519 signature of msg under pub.
func Verify(pub []byte, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// ---- Ed25519 → X25519 (PROTOCOL.md §1.2) ----

// EdPubToX25519 converts an Ed25519 public key to its Curve25519 counterpart
// via crypto_sign_ed25519_pk_to_curve25519.
func EdPubToX25519(edPub []byte) ([]byte, error) {
	if len(edPub) != ed25519.PublicKeySize {
		return nil, errors.New("crypto: bad ed25519 public key length")
	}
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, err
	}
	return p.BytesMontgomery(), nil
}

// EdPrivToX25519 converts a 64-byte Ed25519 expanded private key to its
// Curve25519 scalar via crypto_sign_ed25519_sk_to_curve25519.
//
// The libsodium derivation hashes the 32-byte seed with SHA-512, clamps the
// first 32 bytes, and returns those as the X25519 scalar.
func EdPrivToX25519(edPriv []byte) ([]byte, error) {
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("crypto: bad ed25519 private key length")
	}
	seed := edPriv[:32]
	h := sha512Sum(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	return h[:32], nil
}

// ---- AEAD: AES-256-GCM ----

// AEADSeal encrypts plain under a 32-byte key, prepending the 12-byte nonce.
// On the wire we always use 12-byte random nonces (PROTOCOL.md §5).
// Returned ciphertext layout is nonce(12) || ciphertext || tag(16) when
// includeNonce is true; otherwise just ciphertext||tag with caller-managed nonce.
func AEADSeal(key, nonce, plain, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("crypto: bad nonce size")
	}
	return gcm.Seal(nil, nonce, plain, aad), nil
}

// AEADOpen decrypts ct under key with the given nonce and aad.
func AEADOpen(key, nonce, ct, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto: AES-256 key must be 32 bytes")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// ---- Argon2id ----

// Argon2Params for K_unlock and K_recovery.
type Argon2Params struct {
	M uint32 // memory (KiB)
	T uint32 // iterations
	P uint8  // parallelism
}

// DefaultArgon2 is the parameter set used for new wraps and recovery files.
// 64 MiB / 3 passes / 1 lane is OWASP's mid-tier recommendation for Argon2id.
var DefaultArgon2 = Argon2Params{M: 64 * 1024, T: 3, P: 1}

// DeriveKey runs Argon2id and returns 32 bytes.
func DeriveKey(password, salt []byte, p Argon2Params) []byte {
	return argon2.IDKey(password, salt, p.T, p.M, p.P, 32)
}

// ---- Sealed-box (libsodium crypto_box_seal) ----

// SealAnonymous wraps plain so only the recipient (X25519 pub) can open it.
// Used for KeyDelivery. nacl/box.SealAnonymous is the libsodium-compatible
// implementation.
func SealAnonymous(plain, recipientX25519Pub []byte) ([]byte, error) {
	if len(recipientX25519Pub) != 32 {
		return nil, errors.New("crypto: bad recipient pubkey length")
	}
	var pub [32]byte
	copy(pub[:], recipientX25519Pub)
	return box.SealAnonymous(nil, plain, &pub, rand.Reader)
}

// OpenAnonymous opens a sealed-box for recipient with priv (X25519 32-byte
// scalar) and corresponding pub.
func OpenAnonymous(sealed, recipientX25519Pub, recipientX25519Priv []byte) ([]byte, bool) {
	if len(recipientX25519Pub) != 32 || len(recipientX25519Priv) != 32 {
		return nil, false
	}
	var pub, priv [32]byte
	copy(pub[:], recipientX25519Pub)
	copy(priv[:], recipientX25519Priv)
	out, ok := box.OpenAnonymous(nil, sealed, &pub, &priv)
	return out, ok
}

// X25519Pub derives the X25519 public key for the given X25519 private scalar.
func X25519Pub(priv []byte) ([]byte, error) {
	if len(priv) != 32 {
		return nil, errors.New("crypto: bad X25519 priv length")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return pub, nil
}
