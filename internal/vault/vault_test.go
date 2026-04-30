package vault

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestVaultRoundtrip(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery staple")
	salt, _ := crypto.RandomBytes(16)
	pp, err := NewPassphraseParams(salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	unlock := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)

	body := &proto.VaultBody{
		SuperPriv: priv,
		AuthTip:   proto.ChainTip{Seq: 0, Hash: bytes.Repeat([]byte{0xAA}, 32)},
		Scopes:    map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "vault.enc")
	wraps := []WrapInput{{
		MethodID:     "am_passphrase",
		MethodType:   proto.AuthPassphrase,
		PublicParams: pp,
		UnlockKey:    unlock,
	}}
	if err := Save(p, pub, body, wraps); err != nil {
		t.Fatal(err)
	}

	v, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(v, []MethodResolver{PassphraseResolver{Passphrase: pass}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.UnlockKey) != 32 {
		t.Fatal("expected K_unlock 32 bytes")
	}
	if len(got.PayloadKey) != 32 {
		t.Fatal("expected payload_key 32 bytes")
	}
	if !bytes.Equal(got.Body.SuperPriv, priv) {
		t.Fatal("super_priv mismatch")
	}
	if got.Body.AuthTip.Seq != 0 || !bytes.Equal(got.Body.AuthTip.Hash, body.AuthTip.Hash) {
		t.Fatal("auth_tip mismatch")
	}
	// Wrong passphrase fails.
	if _, err := Open(v, []MethodResolver{PassphraseResolver{Passphrase: []byte("nope")}}); err == nil {
		t.Fatal("expected open failure with wrong passphrase")
	}
}
