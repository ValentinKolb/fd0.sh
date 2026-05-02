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
	unlock, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}

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

// TestAddWrapIdempotentOnRetry verifies the crash-recovery property of
// AddWrap: if a previous `auth add` was interrupted between the AddWrap
// vault write and the chain.AppendUser, retrying must not error even
// though the wrap is already on disk.
func TestAddWrapIdempotentOnRetry(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vault.enc")
	pub, priv, _ := crypto.GenerateIdentity()
	salt, _ := crypto.RandomBytes(16)
	pp, _ := NewPassphraseParams(salt, crypto.DefaultArgon2)
	uk, err := crypto.DeriveKey([]byte("pass1"), salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	body := &proto.VaultBody{
		SuperPriv: priv,
		AuthTip:   proto.ChainTip{Seq: 0, Hash: bytes.Repeat([]byte{0xAA}, 32)},
		Scopes:    map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := Save(p, pub, body, []WrapInput{{MethodID: "am_a", MethodType: proto.AuthPassphrase, PublicParams: pp, UnlockKey: uk}}); err != nil {
		t.Fatal(err)
	}
	// Open once to get a stable payload_key.
	v, _ := Read(p)
	res, err := Open(v, []MethodResolver{PassphraseResolver{Passphrase: []byte("pass1")}})
	if err != nil {
		t.Fatal(err)
	}
	salt2, _ := crypto.RandomBytes(16)
	pp2, _ := NewPassphraseParams(salt2, crypto.DefaultArgon2)
	uk2, err := crypto.DeriveKey([]byte("pass2"), salt2, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	// First add succeeds.
	if err := AddWrap(p, pub, body, res.PayloadKey, WrapInput{
		MethodID: "am_b", MethodType: proto.AuthPassphrase, PublicParams: pp2, UnlockKey: uk2,
	}); err != nil {
		t.Fatal(err)
	}
	// Retry with the SAME method_id and SAME UnlockKey: must succeed.
	if err := AddWrap(p, pub, body, res.PayloadKey, WrapInput{
		MethodID: "am_b", MethodType: proto.AuthPassphrase, PublicParams: pp2, UnlockKey: uk2,
	}); err != nil {
		t.Fatalf("idempotent retry must succeed, got %v", err)
	}
	// Retry with the SAME method_id but a DIFFERENT UnlockKey: must error.
	uk3, err := crypto.DeriveKey([]byte("pass3"), salt2, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddWrap(p, pub, body, res.PayloadKey, WrapInput{
		MethodID: "am_b", MethodType: proto.AuthPassphrase, PublicParams: pp2, UnlockKey: uk3,
	}); err == nil {
		t.Fatal("collision on method_id with different credential must error")
	}
}

// TestRemoveWrapIdempotentOnNotFound verifies the crash-recovery
// property of RemoveWrap: if a previous `auth rm` removed the wrap
// but the chain.AppendUser failed, retrying must not error.
func TestRemoveWrapIdempotentOnNotFound(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "vault.enc")
	pub, priv, _ := crypto.GenerateIdentity()
	salt, _ := crypto.RandomBytes(16)
	pp, _ := NewPassphraseParams(salt, crypto.DefaultArgon2)
	uk, err := crypto.DeriveKey([]byte("pass1"), salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	salt2, _ := crypto.RandomBytes(16)
	pp2, _ := NewPassphraseParams(salt2, crypto.DefaultArgon2)
	uk2, err := crypto.DeriveKey([]byte("pass2"), salt2, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	body := &proto.VaultBody{
		SuperPriv: priv,
		AuthTip:   proto.ChainTip{Seq: 0, Hash: bytes.Repeat([]byte{0xAA}, 32)},
		Scopes:    map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := Save(p, pub, body, []WrapInput{
		{MethodID: "am_a", MethodType: proto.AuthPassphrase, PublicParams: pp, UnlockKey: uk},
		{MethodID: "am_b", MethodType: proto.AuthPassphrase, PublicParams: pp2, UnlockKey: uk2},
	}); err != nil {
		t.Fatal(err)
	}
	v, _ := Read(p)
	res, err := Open(v, []MethodResolver{PassphraseResolver{Passphrase: []byte("pass1")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveWrap(p, pub, body, res.PayloadKey, "am_b"); err != nil {
		t.Fatal(err)
	}
	// Retry: the wrap is already gone. Must succeed (idempotent).
	if err := RemoveWrap(p, pub, body, res.PayloadKey, "am_b"); err != nil {
		t.Fatalf("idempotent retry must succeed, got %v", err)
	}
	// Refusing to remove the last wrap is still enforced.
	if err := RemoveWrap(p, pub, body, res.PayloadKey, "am_a"); err == nil {
		t.Fatal("RemoveWrap of last wrap must refuse")
	}
}
