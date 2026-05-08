package crypto

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/salsa20/salsa"
)

// Sealed-box layout (libsodium crypto_box_seal):
//
//	sealed = ephemeral_pub(32) || aead_ciphertext(>= 16, includes Poly1305 tag)
//
// nacl/box uses the same wire format, so blobs produced by SealAnonymous
// (above) round-trip through ParseSealed → ECDH-step → OpenSealedFromShared.
//
// We split parsing from open() so the on-card path can do the (sole)
// hardware-bound step — ECDH against the slot's private key — between
// these two pure-software functions. THREATS.md notes the rationale: the
// X25519 priv never leaves the card, and the rest of the construction
// (HSalsa20 key derivation + BLAKE2b nonce + XSalsa20-Poly1305 open) is
// constant-time pure-Go.

// SealedEphPubLen is the length of the ephemeral X25519 pubkey prefix on a
// sealed-box blob.
const SealedEphPubLen = 32

// SealedMinLen is the minimum length of a well-formed sealed-box: the
// ephemeral pubkey plus a 16-byte Poly1305 authenticator on an
// empty-plaintext AEAD.
const SealedMinLen = SealedEphPubLen + 16

// ErrSealedTooShort is returned by ParseSealed when input is too short to
// hold an ephemeral pubkey plus a Poly1305 tag.
var ErrSealedTooShort = errors.New("crypto: sealed-box too short")

// ParseSealed splits a sealed-box blob into the embedded ephemeral X25519
// pubkey and the AEAD ciphertext (which still carries its Poly1305 tag).
//
// The returned ephPub is a fresh copy. The returned ct aliases the input
// slice — callers that intend to mutate the input MUST NOT touch it
// before they finish consuming ct.
//
// SealedSharedSecretLen is the length of the X25519 ECDH output that
// feeds into OpenSealedFromShared.
const SealedSharedSecretLen = 32

// ErrSealedShared is returned by OpenSealedFromShared when the supplied
// shared-secret length is wrong.
var ErrSealedShared = errors.New("crypto: shared secret must be 32 bytes")

// ErrSealedSharedZero is returned by OpenSealedFromShared when the
// supplied shared secret is all-zero — RFC 7748 §6.1's signal that the
// ephemeral pubkey was a small-subgroup point. Producing keying
// material from a zero shared would let an attacker forge sealed
// blobs the recipient considers valid.
var ErrSealedSharedZero = errors.New("crypto: shared secret is all-zero (small-subgroup ephemeral)")

// ParseSealed is a structural check only: it does NOT verify the AEAD or
// the embedded pubkey. The open path (OpenSealedFromShared) is
// responsible for cryptographic verification.
func ParseSealed(sealed []byte) (ephPub [32]byte, ct []byte, err error) {
	if len(sealed) < SealedMinLen {
		return [32]byte{}, nil, fmt.Errorf("%w: have %d, need >= %d", ErrSealedTooShort, len(sealed), SealedMinLen)
	}
	copy(ephPub[:], sealed[:SealedEphPubLen])
	// Full three-index slice: clamp ct's capacity to its length so callers
	// who append to ct cannot mutate bytes beyond the sealed-box ciphertext
	// in the underlying buffer.
	ct = sealed[SealedEphPubLen:len(sealed):len(sealed)]
	return ephPub, ct, nil
}

// OpenSealedFromShared completes the libsodium crypto_box_seal_open path
// after the X25519 ECDH step has run. The construction matches
// nacl/box.OpenAnonymous (which is itself libsodium-compatible — that
// is the same library this package already uses for SealAnonymous):
//
//	key   = HSalsa20(shared, zero_nonce, sigma)            // nacl box "after" key derivation
//	nonce = BLAKE2b(ephPub || recipientPub, output=24 B)   // libsodium sealed-box nonce
//	plain = secretbox.Open(ct, nonce, key)                 // XSalsa20-Poly1305
//
// "shared" is the 32-byte output of X25519(recipient_priv, ephPub). On
// hardware the YubiKey produces it; in tests a software MockCard
// computes it via curve25519.X25519. OpenSealedFromShared itself is
// pure software and never sees the recipient's private key.
//
// Returns (plaintext, true) on success and (nil, false) on any failure
// — wrong shared-secret length, all-zero shared secret, or AEAD
// authentication failure. The boolean mirrors nacl/box.OpenAnonymous;
// the parallel variant OpenSealedFromSharedErr returns a typed error
// for callers who want to distinguish failure modes.
func OpenSealedFromShared(ephPub, recipientPub [32]byte, ct, shared []byte) ([]byte, bool) {
	plain, err := OpenSealedFromSharedErr(ephPub, recipientPub, ct, shared)
	if err != nil {
		return nil, false
	}
	return plain, true
}

// OpenSealedFromSharedErr is OpenSealedFromShared with a typed error
// return. Used by callers (the YubiKey open-path wrapper, the
// recorder's self-check) that want to log WHY an open failed.
//
// AEAD failures collapse to a single sentinel (ErrSealedAEAD) — the
// AEAD itself reveals no information about why the tag check failed,
// and exposing more would be a side channel.
func OpenSealedFromSharedErr(ephPub, recipientPub [32]byte, ct, shared []byte) ([]byte, error) {
	if len(shared) != SealedSharedSecretLen {
		return nil, fmt.Errorf("%w: have %d", ErrSealedShared, len(shared))
	}
	if isAllZero(shared) {
		return nil, ErrSealedSharedZero
	}

	// HSalsa20(shared, zero_nonce, sigma) → 32-byte symmetric key.
	// Same construction as golang.org/x/crypto/nacl/box.Precompute.
	var sharedArr [32]byte
	copy(sharedArr[:], shared)
	var key [32]byte
	salsa.HSalsa20(&key, &[16]byte{}, &sharedArr, &salsa.Sigma)
	// Wipe the shared-secret copy on the stack as soon as the symmetric
	// key is derived. Use the package-level Wipe so the runtime.KeepAlive
	// prevents dead-store elimination — same defence the rest of the
	// codebase relies on for sensitive material.
	Wipe(sharedArr[:])

	// nonce = BLAKE2b(ephPub || recipientPub) with 24-byte output.
	// blake2b.New(size=24) gives us the right-sized digest directly,
	// matching nacl/box.sealNonce.
	h, err := blake2b.New(24, nil)
	if err != nil {
		// blake2b.New(24, nil) only fails on bad parameters; with 24
		// and nil this branch is unreachable in practice. Return a
		// clear error if it ever changes.
		Wipe(key[:])
		return nil, fmt.Errorf("crypto: sealed-box blake2b init: %w", err)
	}
	_, _ = h.Write(ephPub[:])
	_, _ = h.Write(recipientPub[:])
	var nonce [24]byte
	h.Sum(nonce[:0])

	plain, ok := secretbox.Open(nil, ct, &nonce, &key)
	Wipe(key[:])
	if !ok {
		return nil, ErrSealedAEAD
	}
	return plain, nil
}

// ErrSealedAEAD is returned by OpenSealedFromSharedErr when the
// XSalsa20-Poly1305 authentication fails. Callers MUST treat this the
// same way they would treat any other AEAD-tag failure: drop the
// message; do not log the ciphertext; do not retry with a different
// shared secret.
var ErrSealedAEAD = errors.New("crypto: sealed-box AEAD authentication failed")

// isAllZero is constant-time over the input length. The cost is
// negligible compared to ECDH, and a timing-safe scan removes the
// (theoretical) zero-vs-nonzero branch from the open path.
func isAllZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}
