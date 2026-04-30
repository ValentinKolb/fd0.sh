package vault

import (
	"errors"

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
// The actual implementation lives in internal/crypto/yubikey behind a build
// tag; this resolver type holds the connector and the per-call sealed blob.
//
// Protocol layer (PROTOCOL.md §3.1):
//
//	encrypted_super_priv = sealed_box(K_unlock, public_params) || AEAD(K_unlock, super_priv, ...)
//
// On unlock the resolver opens the sealed_box on-card to recover K_unlock,
// then the vault layer AEAD-decrypts super_priv with it.
type YubikeyResolver struct {
	// OpenSealed is supplied by callers built with -tags=yubikey. Pure-Go
	// builds leave it nil and UnlockKey returns an error.
	OpenSealed func(sealed []byte) (kUnlock []byte, err error)
}

// MethodType implements vault.MethodResolver.
func (YubikeyResolver) MethodType() string { return proto.AuthYubikey }

// UnlockKey for YubiKey: the wrap layer carries a sealed-box prefix that the
// on-card key opens to reveal K_unlock. public_params is the on-card pub
// (informational here; the sealed bytes self-identify the recipient).
//
// v1 framework only — the actual sealed-box parsing requires further
// integration in the vault wrap path. See PROTOCOL.md §3.1 for the
// finalised shape.
func (r YubikeyResolver) UnlockKey(publicParams []byte) ([]byte, error) {
	if r.OpenSealed == nil {
		return nil, errors.New("yubikey: build fd0 with -tags=yubikey to enable PIV support")
	}
	// publicParams is the on-card X25519 pub for informational purposes.
	// The vault layer should pass the sealed-box ciphertext separately
	// once that wiring lands; until then this returns a placeholder error.
	return nil, errors.New("yubikey: vault wrap integration pending (v1.x)")
}

// MethodType implements vault.MethodResolver.
func (PassphraseResolver) MethodType() string { return proto.AuthPassphrase }

// UnlockKey implements vault.MethodResolver.
func (r PassphraseResolver) UnlockKey(publicParams []byte) ([]byte, error) {
	if len(publicParams) < 16 {
		return nil, errors.New("passphrase: bad public_params")
	}
	salt := publicParams[:16]
	var p proto.Argon2Params
	if err := proto.Unmarshal(publicParams[16:], &p); err != nil {
		return nil, err
	}
	return crypto.DeriveKey(r.Passphrase, salt, crypto.Argon2Params{M: p.M, T: p.T, P: p.P}), nil
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

