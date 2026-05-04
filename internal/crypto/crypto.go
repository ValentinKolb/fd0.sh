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
	"fmt"
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
//
// Wave C-3 (minimal): runtime length-check eliminates the panic
// class. Previously a wrong-sized priv (32B instead of 64B,
// truncated CBOR decode, etc.) would land in ed25519.Sign and
// panic; now we surface a controlled error. Production callers
// already validate length upstream — this is defence-in-depth.
//
// Note: this entry keeps the legacy []byte signature for
// backwards compatibility with the broad call-site surface
// (vault, agent, server, witness, every test fixture). For new
// code, prefer SignTyped which takes Ed25519Priv from the
// type-state-enforcing constructor.
func Sign(priv ed25519.PrivateKey, msg []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("crypto: Sign: bad priv length %d (want %d)", len(priv), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(priv, msg), nil
}

// SignTyped is the type-state entry — accepts a validated
// Ed25519Priv that, by construction, has the correct length.
// Equivalent to Sign with no possibility of length-related
// failure (the zero-value safeguard fires on a forged composite
// literal). Prefer this in new code.
func SignTyped(priv Ed25519Priv, msg []byte) ([]byte, error) {
	if priv.IsZero() {
		return nil, errSignBadKey
	}
	return ed25519.Sign(priv.asStdlib(), msg), nil
}

// Verify returns true iff sig is a valid Ed25519 signature of msg under pub.
func Verify(pub []byte, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// VerifyTyped is the type-state entry — accepts a validated
// Ed25519Pub. Length is correct by construction. Prefer in new code.
func VerifyTyped(pub Ed25519Pub, msg, sig []byte) bool {
	if pub.IsZero() || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub.asStdlib(), msg, sig)
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
//
// SECURITY: returns a fresh 32-byte slice with zero-byte cap padding —
// `h[:32]` would have shared the underlying 64-byte SHA-512 buffer with
// cap 64, letting any caller re-slice to `[:64]` and read the
// Ed25519 prefix bytes (h[32:64]). Combined with any signature
// produced by the same private key, an attacker could recover the
// signing scalar (codex audit: signature subagent finding 🔴).
// We additionally wipe the full SHA-512 buffer before returning so
// the prefix never lingers in memory the caller can reach.
func EdPrivToX25519(edPriv []byte) ([]byte, error) {
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("crypto: bad ed25519 private key length")
	}
	seed := edPriv[:32]
	h := sha512Sum(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	out := make([]byte, 32)
	copy(out, h[:32])
	// Zero the entire SHA-512 buffer (incl. the Ed25519 prefix) so
	// no caller-reachable memory holds the unredacted hash.
	for i := range h {
		h[i] = 0
	}
	return out, nil
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
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("crypto: bad nonce size")
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

// MinArgon2 / MaxArgon2 bound the Argon2id parameter ranges
// DeriveKey will accept. Anything outside these bounds is treated as
// adversarial input (a tampered vault header, a forged recovery
// file, or a downgrade attempt) and rejected — protecting both
// against panics (T=0 / P=0 inside argon2.IDKey) and against
// memory-exhaustion DoS (huge M).
//
// The minimums are deliberately lower than DefaultArgon2 so we can
// still accept legitimate older vaults written with weaker params,
// but they still require enough work to be useful as a KDF. The
// maximums cap memory at ~1 GiB and iterations / parallelism at
// values no honest implementation should exceed.
var (
	MinArgon2 = Argon2Params{M: 16 * 1024, T: 1, P: 1}        // 16 MiB / 1 pass / 1 lane
	MaxArgon2 = Argon2Params{M: 1024 * 1024, T: 16, P: 16}    // 1 GiB / 16 passes / 16 lanes
)

// ValidateArgon2 checks the supplied params are within accepted
// bounds. Returned errors are descriptive so the caller can surface
// them to operators looking at corrupt-vault diagnostics.
func ValidateArgon2(p Argon2Params) error {
	if p.M < MinArgon2.M || p.M > MaxArgon2.M {
		return fmt.Errorf("crypto: argon2 memory %d KiB out of accepted range [%d, %d]", p.M, MinArgon2.M, MaxArgon2.M)
	}
	if p.T < MinArgon2.T || p.T > MaxArgon2.T {
		return fmt.Errorf("crypto: argon2 iterations %d out of accepted range [%d, %d]", p.T, MinArgon2.T, MaxArgon2.T)
	}
	if p.P < MinArgon2.P || p.P > MaxArgon2.P {
		return fmt.Errorf("crypto: argon2 parallelism %d out of accepted range [%d, %d]", p.P, MinArgon2.P, MaxArgon2.P)
	}
	return nil
}

// DeriveKey runs Argon2id and returns 32 bytes. Validates the
// parameter set first — caller-supplied params can come from
// untrusted vault / recovery file headers, where T=0 or P=0 would
// panic inside argon2.IDKey and a huge M would OOM the process
// (codex review: 🔴).
func DeriveKey(password, salt []byte, p Argon2Params) ([]byte, error) {
	if err := ValidateArgon2(p); err != nil {
		return nil, err
	}
	return argon2.IDKey(password, salt, p.T, p.M, p.P, 32), nil
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
