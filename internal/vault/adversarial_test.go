package vault

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Adversarial vault tests. Each corresponds to a real bug class
// from the multi-module review (or its near-miss). The pattern:
// build a valid vault, then craft pathological inputs that the
// vault layer MUST reject without panicking, OOM'ing, or silently
// downgrading security.

func mkVault(t *testing.T) (path string, pub ed25519.PublicKey, unlock []byte) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "vault.enc")
	pub2, priv, _ := crypto.GenerateIdentity()
	pass := []byte("anchor-pass-1234")
	salt, _ := crypto.RandomBytes(16)
	pp, _ := NewPassphraseParams(salt, crypto.DefaultArgon2)
	uk, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	body := &proto.VaultBody{
		SuperPriv:        priv.Bytes(),
		AuthTip:          proto.ChainTip{Seq: 0, Hash: bytes.Repeat([]byte{0xAA}, 32)},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := Save(path, pub2.Bytes(), body, []WrapInput{{
		MethodID: "am_x", MethodType: proto.AuthPassphrase,
		PublicParams: pp, UnlockKey: uk,
	}}); err != nil {
		t.Fatal(err)
	}
	return path, pub2.Bytes(), uk
}

// TestAdvVaultRejectsEmptyWraps locks the codex audit fix:
// vault.Save MUST refuse to write a vault with no wraps (would
// be unlockable by nobody).
func TestAdvVaultRejectsEmptyWraps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")
	pub, priv, _ := crypto.GenerateIdentity()
	body := &proto.VaultBody{
		SuperPriv:        priv.Bytes(),
		AuthTip:          proto.ChainTip{},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := Save(path, pub.Bytes(), body, nil); err == nil {
		t.Fatal("Save(empty wraps) accepted — would write unlockable-by-nobody vault")
	}
	if err := Save(path, pub.Bytes(), body, []WrapInput{}); err == nil {
		t.Fatal("Save(zero-len wraps) accepted")
	}
}

// TestAdvPassphraseResolverRejectsBadArgon2 locks the Argon2-params
// validation: an attacker who can mutate vault headers MUST NOT be
// able to feed T=0/P=0 (panic) or huge M (OOM).
func TestAdvPassphraseResolverRejectsBadArgon2(t *testing.T) {
	salt := bytes.Repeat([]byte{0xAB}, 16)
	cases := []proto.Argon2Params{
		{M: 32 * 1024, T: 0, P: 1},       // T==0
		{M: 32 * 1024, T: 1, P: 0},       // P==0
		{M: 0, T: 1, P: 1},               // M too small
		{M: 8 * 1024, T: 1, P: 1},        // M below MinArgon2
		{M: 1024 * 1024 * 4, T: 1, P: 1}, // M=4 GiB, above MaxArgon2
	}
	for i, p := range cases {
		pb, err := proto.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		publicParams := append(append([]byte{}, salt...), pb...)
		r := PassphraseResolver{Passphrase: []byte("doesnt-matter")}
		if _, err := r.UnlockKey(publicParams); err == nil {
			t.Errorf("case %d: PassphraseResolver accepted bad Argon2 %+v", i, p)
		}
	}
}

// TestAdvPassphraseResolverShortPublicParams: public_params
// shorter than 16 bytes (the salt prefix) MUST be rejected without
// panicking on a nil/short slice access.
func TestAdvPassphraseResolverShortPublicParams(t *testing.T) {
	r := PassphraseResolver{Passphrase: []byte("x")}
	for _, n := range []int{0, 1, 8, 15} {
		pp := bytes.Repeat([]byte{0xAB}, n)
		if _, err := r.UnlockKey(pp); err == nil {
			t.Errorf("len=%d: short public_params accepted (no panic check)", n)
		}
	}
}

// TestAdvDecryptSuperPrivShortBlob: a blob shorter than the 12-byte
// nonce prefix MUST be rejected without panicking.
func TestAdvDecryptSuperPrivShortBlob(t *testing.T) {
	uk := bytes.Repeat([]byte{1}, 32)
	pub := bytes.Repeat([]byte{2}, 32)
	for _, n := range []int{0, 1, 11} {
		_, err := DecryptSuperPriv(bytes.Repeat([]byte{3}, n), pub, "am_x", uk)
		if err == nil {
			t.Errorf("len=%d: short blob accepted", n)
		}
	}
}

func TestAdvEncryptedSuperPrivBindsIdentityAndMethod(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	unlockKey := bytes.Repeat([]byte{0x51}, 32)
	blob, err := EncryptSuperPriv(priv.Bytes(), pub.Bytes(), "am_primary", unlockKey)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptSuperPriv(blob, pub.Bytes(), "am_primary", unlockKey)
	if err != nil {
		t.Fatal(err)
	}
	crypto.Wipe(plain)

	wrongPub := pub.Bytes()
	wrongPub[0] ^= 1
	if _, err := DecryptSuperPriv(blob, wrongPub, "am_primary", unlockKey); err == nil {
		t.Fatal("encrypted super key opened under a different identity")
	}
	if _, err := DecryptSuperPriv(blob, pub.Bytes(), "am_other", unlockKey); err == nil {
		t.Fatal("encrypted super key opened under a different auth method")
	}
	if _, err := DecryptSuperPriv(blob, pub.Bytes(), "am_primary", bytes.Repeat([]byte{0x52}, 32)); err == nil {
		t.Fatal("encrypted super key opened under a different unlock key")
	}
}

// TestAdvVaultRejectsTamperedHeader: any single-byte mutation of
// the on-disk vault file MUST cause Open to fail. The Body AAD
// covers the full header, so flipping any byte in the header's
// CBOR encoding invalidates the AEAD tag.
func TestAdvVaultRejectsTamperedHeader(t *testing.T) {
	path, _, uk := mkVault(t)

	// Read original file.
	v, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper UserSuperPub (covered by AAD).
	v2 := *v
	v2.UserSuperPub = append([]byte(nil), v.UserSuperPub...)
	v2.UserSuperPub[0] ^= 0x01
	if _, err := Open(&v2, []MethodResolver{PassphraseResolver{Passphrase: []byte("anchor-pass-1234")}}); err == nil {
		t.Fatal("Open accepted tampered UserSuperPub")
	}

	// Tamper BodyNonce (covered by AAD).
	v3 := *v
	v3.BodyNonce = append([]byte(nil), v.BodyNonce...)
	v3.BodyNonce[0] ^= 0x01
	if _, err := Open(&v3, []MethodResolver{PassphraseResolver{Passphrase: []byte("anchor-pass-1234")}}); err == nil {
		t.Fatal("Open accepted tampered BodyNonce")
	}

	_ = uk
}

// TestAdvVaultRejectsTamperedBody: any byte flip in the encrypted
// body MUST be rejected by AEAD.
func TestAdvVaultRejectsTamperedBody(t *testing.T) {
	path, _, _ := mkVault(t)
	v, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	v2 := *v
	v2.Body = append([]byte(nil), v.Body...)
	v2.Body[len(v2.Body)/2] ^= 0x01
	if _, err := Open(&v2, []MethodResolver{PassphraseResolver{Passphrase: []byte("anchor-pass-1234")}}); err == nil {
		t.Fatal("Open accepted tampered Body")
	}
}

func TestAdvVaultMutationRejectsIdentityChangeWithoutWriting(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(path string, body *proto.VaultBody, payloadKey, wrongPub []byte) error
	}{
		{
			name: "save body",
			mutate: func(path string, body *proto.VaultBody, payloadKey, wrongPub []byte) error {
				return SaveBody(path, wrongPub, body, payloadKey)
			},
		},
		{
			name: "add wrap",
			mutate: func(path string, body *proto.VaultBody, payloadKey, wrongPub []byte) error {
				return AddWrap(path, wrongPub, body, payloadKey, WrapInput{
					MethodID:     "am_new",
					MethodType:   "test",
					PublicParams: []byte("public"),
					UnlockKey:    bytes.Repeat([]byte{0x44}, 32),
				})
			},
		},
		{
			name: "remove wrap",
			mutate: func(path string, body *proto.VaultBody, payloadKey, wrongPub []byte) error {
				return RemoveWrap(path, wrongPub, body, payloadKey, "am_x")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, pub, _ := mkVault(t)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			v, err := Read(path)
			if err != nil {
				t.Fatal(err)
			}
			res, err := Open(v, []MethodResolver{
				PassphraseResolver{Passphrase: []byte("anchor-pass-1234")},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer crypto.Wipe(res.UnlockKey)
			defer crypto.Wipe(res.PayloadKey)

			wrongPub := append([]byte(nil), pub...)
			wrongPub[0] ^= 0x01
			err = tt.mutate(path, res.Body, res.PayloadKey, wrongPub)
			if !errors.Is(err, ErrIdentityMismatch) {
				t.Fatalf("expected ErrIdentityMismatch, got %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("rejected identity change modified the vault file")
			}
		})
	}
}

// TestAdvVaultRejectsWrongPassphrase: wrong passphrase MUST fail
// at AEAD-open time (not silently return a "decrypted" garbage
// VaultBody).
func TestAdvVaultRejectsWrongPassphrase(t *testing.T) {
	path, _, _ := mkVault(t)
	v, _ := Read(path)
	if _, err := Open(v, []MethodResolver{PassphraseResolver{Passphrase: []byte("wrong-pass")}}); err == nil {
		t.Fatal("Open accepted wrong passphrase")
	}
}

// TestAdvSaveBodyRejectsBadPayloadKey: SaveBody MUST require a
// 32-byte payload key. Anything else is a programmer error and
// must not silently AEAD-encrypt under a wrong-size key.
func TestAdvSaveBodyRejectsBadPayloadKey(t *testing.T) {
	path, pub, _ := mkVault(t)
	body := &proto.VaultBody{
		AuthTip:          proto.ChainTip{},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		pk := bytes.Repeat([]byte{1}, n)
		if err := SaveBody(path, pub, body, pk); err == nil {
			t.Errorf("len=%d: SaveBody accepted bad payload key", n)
		}
	}
}

// TestAdvNewPassphraseParamsRejectsBadSalt: salt must be exactly
// 16 bytes. Any other length must error (no silent truncation).
func TestAdvNewPassphraseParamsRejectsBadSalt(t *testing.T) {
	for _, n := range []int{0, 1, 8, 15, 17, 32} {
		salt := bytes.Repeat([]byte{0xAB}, n)
		if _, err := NewPassphraseParams(salt, crypto.DefaultArgon2); err == nil {
			t.Errorf("salt len=%d accepted", n)
		}
	}
}
