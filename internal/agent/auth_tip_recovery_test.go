package agent

import (
	"bytes"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

func TestAgentUnlockAllowsChainAheadWhenUsedMethodStillLive(t *testing.T) {
	paths, pass, _ := writeAuthTipAheadFixture(t, true)
	resp := (&Server{}).handleUnlock(&UnlockReq{
		VaultPath:     paths.Vault,
		UserChainPath: paths.UserChain,
		MethodType:    proto.AuthPassphrase,
		Passphrase:    pass,
	})
	if resp.Err != "" {
		t.Fatalf("Unlock error: %s", resp.Err)
	}
}

func TestAgentUnlockRejectsChainAheadWhenUsedMethodWasRemoved(t *testing.T) {
	paths, pass, _ := writeAuthTipAheadFixture(t, false)
	resp := (&Server{}).handleUnlock(&UnlockReq{
		VaultPath:     paths.Vault,
		UserChainPath: paths.UserChain,
		MethodType:    proto.AuthPassphrase,
		Passphrase:    pass,
	})
	if resp.Err == "" {
		t.Fatal("expected rollback error")
	}
	if !strings.Contains(resp.Err, "method_id \"am_a\" is no longer active") {
		t.Fatalf("unexpected error: %s", resp.Err)
	}
}

func writeAuthTipAheadFixture(t *testing.T, keepUsedMethod bool) (fdhome.Paths, []byte, crypto.Ed25519Priv) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("FD0_HOME", home)
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { priv.Wipe() })
	passA := []byte("auth-tip-ahead-pass-a")
	saltA := bytes.Repeat([]byte{0xA1}, 16)
	ppA, err := vault.NewPassphraseParams(saltA, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	kA, err := crypto.DeriveKey(passA, saltA, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { crypto.Wipe(kA) })
	encA, err := vault.EncryptSuperPriv(priv.Bytes(), pub.Bytes(), "am_a", kA)
	if err != nil {
		t.Fatal(err)
	}
	methodA := proto.AuthMethod{
		MethodID: "am_a", MethodType: proto.AuthPassphrase, PublicParams: ppA, EncryptedSuperPriv: encA,
	}
	ev0, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), 0, nil, []proto.AuthMethod{methodA})
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.AppendUser(paths.UserChain, ev0); err != nil {
		t.Fatal(err)
	}
	prefix0, err := ev0.PrevHashInput()
	if err != nil {
		t.Fatal(err)
	}
	h0 := proto.HashPrefix(prefix0)
	body := &proto.VaultBody{
		SuperPriv:        priv.Bytes(),
		AuthTip:          proto.ChainTip{Seq: ev0.Seq, Hash: h0[:]},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := vault.Save(paths.Vault, pub.Bytes(), body, []vault.WrapInput{{
		MethodID: "am_a", MethodType: proto.AuthPassphrase, PublicParams: ppA, UnlockKey: kA,
	}}); err != nil {
		t.Fatal(err)
	}

	passB := []byte("auth-tip-ahead-pass-b")
	saltB := bytes.Repeat([]byte{0xB2}, 16)
	ppB, err := vault.NewPassphraseParams(saltB, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	kB, err := crypto.DeriveKey(passB, saltB, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { crypto.Wipe(kB) })
	encB, err := vault.EncryptSuperPriv(priv.Bytes(), pub.Bytes(), "am_b", kB)
	if err != nil {
		t.Fatal(err)
	}
	methodB := proto.AuthMethod{
		MethodID: "am_b", MethodType: proto.AuthPassphrase, PublicParams: ppB, EncryptedSuperPriv: encB,
	}
	active := []proto.AuthMethod{methodB}
	if keepUsedMethod {
		active = []proto.AuthMethod{methodA, methodB}
	}
	ev1, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), ev0.Seq, h0[:], active)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.AppendUser(paths.UserChain, ev1); err != nil {
		t.Fatal(err)
	}
	return paths, append([]byte(nil), passA...), priv
}
