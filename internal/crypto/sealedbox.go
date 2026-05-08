package crypto

import (
	"errors"
	"fmt"
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
