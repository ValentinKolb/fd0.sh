package vault

import (
	"errors"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// PassphraseResolver derives K_unlock from a passphrase via Argon2id.
//
// public_params layout for passphrase methods (PROTOCOL.md §3.1):
//
//	salt(16) || cbor(Argon2Params{m,t,p})
type PassphraseResolver struct {
	Passphrase []byte
}

// YubikeyResolver delegates K_unlock derivation to the on-card private key.
// The hardware-bound piece (X25519 ECDH on the slot's private key) lives
// behind the `yubikey` build tag in internal/crypto/yubikey; this
// resolver only wires it into the vault open path.
//
// Protocol layer (PROTOCOL.md §3.1):
//
//	encrypted_super_priv = AEAD(K_unlock, super_priv, ...)
//
// At enrollment time the CLI generates a fresh 32-byte K_unlock, AEAD-seals
// super_priv with it, and stores the K_unlock under a libsodium sealed-box
// to the slot's pub. That sealed-box ciphertext rides along in
// public_params (proto.YubikeyPublicParams.SealedKUnlock). On unlock the
// resolver hands the sealed bytes to OpenSealed (which under -tags=yubikey
// runs ParseSealed → on-card ECDH → OpenSealedFromShared) and gets back
// the original K_unlock.
//
// OpenSealed is injected — agent main.go provides a real implementation
// under -tags=yubikey, and a nil callback for the pure-Go build (which
// surfaces a clean error rather than panicking).
type YubikeyResolver struct {
	// OpenSealed runs the libsodium crypto_box_seal_open path against
	// the connected YubiKey. expectedPub is the 32-byte X25519 pubkey
	// recorded in the vault wrap at enrollment time; the implementation
	// MUST verify the connected card's pubkey equals expectedPub
	// before doing the on-card ECDH and surface a clear "wrong card"
	// error if not. Without this check a different YubiKey plugged
	// into the same machine would still drive an ECDH (its private
	// key against our ephemeral pub) and the failure would only show
	// up downstream as an opaque AEAD authentication error.
	//
	// Returns the 32-byte K_unlock on success. Returns a wrapped error
	// explaining what failed (no card, wrong card, wrong PIN, ECDH
	// refused, AEAD authentication failed). Implementations MUST
	// return caller-owned bytes; the resolver wipes them on length
	// error.
	OpenSealed func(expectedPub, sealed []byte) (kUnlock []byte, err error)
}

// MethodType implements vault.MethodResolver.
func (YubikeyResolver) MethodType() string { return proto.AuthYubikey }

// UnlockKey for YubiKey: parses public_params as YubikeyPublicParams and
// hands the embedded sealed-box ciphertext to OpenSealed.
//
// Returns ErrYubikeyNotConfigured when OpenSealed is nil, so callers
// can distinguish "agent built without yubikey support" from "card
// rejected the PIN". The vault layer's resolver loop iterates regardless,
// so the error here just gets stringified into the final
// "no matching auth method" message; an agent that wants a more useful
// error should pre-flight the resolver before calling vault.Open.
func (r YubikeyResolver) UnlockKey(publicParams []byte) ([]byte, error) {
	if r.OpenSealed == nil {
		return nil, ErrYubikeyNotConfigured
	}
	var pp proto.YubikeyPublicParams
	if err := proto.Unmarshal(publicParams, &pp); err != nil {
		return nil, fmt.Errorf("yubikey: parse public_params: %w", err)
	}
	if len(pp.X25519Pub) != 32 {
		return nil, fmt.Errorf("yubikey: public_params x25519_pub is %d bytes, want 32", len(pp.X25519Pub))
	}
	if len(pp.SealedKUnlock) == 0 {
		return nil, errors.New("yubikey: public_params missing sealed K_unlock")
	}
	k, err := r.OpenSealed(pp.X25519Pub, pp.SealedKUnlock)
	if err != nil {
		return nil, err
	}
	if len(k) != 32 {
		crypto.Wipe(k)
		return nil, fmt.Errorf("yubikey: K_unlock has length %d, want 32", len(k))
	}
	return k, nil
}

// ErrYubikeyNotConfigured signals that the agent was built without the
// `yubikey` build tag, so YubiKey-backed unlock cannot run on this
// device. Match with errors.Is to give callers a chance to surface a
// helpful re-build hint.
var ErrYubikeyNotConfigured = errors.New("yubikey: agent built without yubikey support; rebuild fd0-agent with -tags=yubikey")

// MethodType implements vault.MethodResolver.
func (PassphraseResolver) MethodType() string { return proto.AuthPassphrase }

// UnlockKey implements vault.MethodResolver.
//
// SECURITY: validates Argon2 params from the (untrusted) vault
// header before invoking the KDF. Without this, a tampered or
// corrupted vault could supply T=0 / P=0 (panics inside argon2.IDKey)
// or a huge M (process OOM during unlock). DeriveKey now bounds
// these via crypto.ValidateArgon2 (codex audit: 🔴).
func (r PassphraseResolver) UnlockKey(publicParams []byte) ([]byte, error) {
	if len(publicParams) < 16 {
		return nil, errors.New("passphrase: bad public_params")
	}
	salt := publicParams[:16]
	var p proto.Argon2Params
	if err := proto.Unmarshal(publicParams[16:], &p); err != nil {
		return nil, err
	}
	return crypto.DeriveKey(r.Passphrase, salt, crypto.Argon2Params{M: p.M, T: p.T, P: p.P})
}

// NewPassphraseParams builds public_params (salt(16) || cbor(Argon2Params)).
func NewPassphraseParams(salt []byte, p crypto.Argon2Params) ([]byte, error) {
	if len(salt) != 16 {
		return nil, errors.New("salt must be 16 bytes")
	}
	pb, err := proto.Marshal(proto.Argon2Params{M: p.M, T: p.T, P: p.P})
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 16+len(pb))
	out = append(out, salt...)
	out = append(out, pb...)
	return out, nil
}

// EncryptSuperPriv produces the AuthMethod ciphertext layout used inside
// auth.set events:
//
//	encrypted_super_priv = nonce(12) || AEAD(K_unlock, nonce, super_priv,
//	                                          aad = domain || user_super_pub || method_id)
func EncryptSuperPriv(superPriv, userSuperPub []byte, methodID string, unlockKey []byte) ([]byte, error) {
	nonce, err := crypto.Nonce12()
	if err != nil {
		return nil, err
	}
	aad := append([]byte(proto.DomainEncryptedSuperPriv), userSuperPub...)
	aad = append(aad, methodID...)
	ct, err := crypto.AEADSeal(unlockKey, nonce, superPriv, aad)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// DecryptSuperPriv reverses EncryptSuperPriv.
func DecryptSuperPriv(blob, userSuperPub []byte, methodID string, unlockKey []byte) ([]byte, error) {
	if len(blob) < 12 {
		return nil, errors.New("encrypted_super_priv: too short")
	}
	aad := append([]byte(proto.DomainEncryptedSuperPriv), userSuperPub...)
	aad = append(aad, methodID...)
	return crypto.AEADOpen(unlockKey, blob[:12], blob[12:], aad)
}

