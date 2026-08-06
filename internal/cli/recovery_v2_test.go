package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

func TestRecoveryV2PreservesAuthenticationMethods(t *testing.T) {
	data, pass, pub, wantUser, wantVault, unlockKeys := recoveryV2Fixture(t, true)
	t.Setenv("FD0_HOME", filepath.Join(t.TempDir(), "restored"))

	result, err := ImportRecoveryWithPassphrases(context.Background(), data, pass, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.UserSuperPub, pub) {
		t.Fatal("restored identity changed")
	}
	gotUser, err := os.ReadFile(filepath.Join(os.Getenv("FD0_HOME"), "chains", "user.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	gotVault, err := os.ReadFile(filepath.Join(os.Getenv("FD0_HOME"), "vault.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotUser, wantUser) || !bytes.Equal(gotVault, wantVault) {
		t.Fatal("recovery v2 did not preserve the encrypted bootstrap files")
	}
	state, err := chain.ReplayUser(filepath.Join(os.Getenv("FD0_HOME"), "chains", "user.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if len(state.LatestAuthSet.Payload.Active) != 2 {
		t.Fatalf("got %d auth methods, want passphrase and yubikey", len(state.LatestAuthSet.Payload.Active))
	}
	restoredVault, err := vault.Read(filepath.Join(os.Getenv("FD0_HOME"), "vault.enc"))
	if err != nil {
		t.Fatal(err)
	}
	for methodType, unlockKey := range unlockKeys {
		opened, err := vault.Open(restoredVault, []vault.MethodResolver{fixedRecoveryResolver{
			methodType: methodType,
			unlockKey:  unlockKey,
		}})
		if err != nil {
			t.Fatalf("restored %s method cannot unlock vault: %v", methodType, err)
		}
		derived := ed25519.PrivateKey(opened.Body.SuperPriv).Public().(ed25519.PublicKey)
		if !bytes.Equal(derived, pub) {
			t.Fatalf("restored %s method returned the wrong identity", methodType)
		}
		crypto.Wipe(opened.UnlockKey)
		crypto.Wipe(opened.PayloadKey)
	}
	if err := VerifyRecoveryWithPassphrase(data, pass, pub); err != nil {
		t.Fatalf("verify v2: %v", err)
	}
}

func TestRecoveryV2RejectsTamperingWithoutPartialInstall(t *testing.T) {
	data, pass, _, _, _, _ := recoveryV2Fixture(t, false)
	data[len(data)-1] ^= 0x40
	home := filepath.Join(t.TempDir(), "restored")
	t.Setenv("FD0_HOME", home)

	if _, err := ImportRecoveryWithPassphrases(context.Background(), data, pass, nil); err == nil {
		t.Fatal("tampered recovery file imported")
	}
	for _, path := range []string{filepath.Join(home, "vault.enc"), filepath.Join(home, "chains", "user.cbor")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("partial recovery artifact left at %s", path)
		}
	}
}

func TestInstallRecoveryBootstrapNeverOverwritesConcurrentFiles(t *testing.T) {
	home := filepath.Join(t.TempDir(), "restored")
	t.Setenv("FD0_HOME", home)
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Vault, []byte("concurrent vault"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := installRecoveryBootstrap(paths, []byte("user chain"), []byte("recovery vault")); err == nil {
		t.Fatal("recovery overwrote a vault created concurrently")
	}
	got, err := os.ReadFile(paths.Vault)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "concurrent vault" {
		t.Fatalf("concurrent vault changed to %q", got)
	}
	if _, err := os.Stat(paths.UserChain); !os.IsNotExist(err) {
		t.Fatal("partial user chain remained after the vault commit failed")
	}
}

type fixedRecoveryResolver struct {
	methodType string
	unlockKey  []byte
}

func (r fixedRecoveryResolver) MethodType() string { return r.methodType }
func (r fixedRecoveryResolver) UnlockKey([]byte) ([]byte, error) {
	return append([]byte(nil), r.unlockKey...), nil
}

func recoveryV2Fixture(t *testing.T, withYubikey bool) (data, pass, pub, userData, vaultData []byte, unlockKeys map[string][]byte) {
	t.Helper()
	pubKey, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Wipe()
	pub = pubKey.Bytes()
	pass = []byte("correct horse battery staple")
	unlockKeys = map[string][]byte{proto.AuthPassphrase: bytes.Repeat([]byte{1}, 32)}
	passphraseCiphertext, err := vault.EncryptSuperPriv(priv.Bytes(), pub, "am_passphrase", unlockKeys[proto.AuthPassphrase])
	if err != nil {
		t.Fatal(err)
	}

	methods := []proto.AuthMethod{{
		MethodID: "am_passphrase", MethodType: proto.AuthPassphrase,
		PublicParams: []byte("passphrase-params"), EncryptedSuperPriv: passphraseCiphertext,
	}}
	wraps := []vault.WrapInput{{
		MethodID: "am_passphrase", MethodType: proto.AuthPassphrase,
		PublicParams: []byte("passphrase-params"), UnlockKey: unlockKeys[proto.AuthPassphrase],
	}}
	if withYubikey {
		unlockKeys[proto.AuthYubikey] = bytes.Repeat([]byte{2}, 32)
		yubikeyCiphertext, err := vault.EncryptSuperPriv(priv.Bytes(), pub, "am_yubikey", unlockKeys[proto.AuthYubikey])
		if err != nil {
			t.Fatal(err)
		}
		methods = append(methods, proto.AuthMethod{
			MethodID: "am_yubikey", MethodType: proto.AuthYubikey,
			PublicParams: []byte("yubikey-params"), EncryptedSuperPriv: yubikeyCiphertext,
		})
		wraps = append(wraps, vault.WrapInput{
			MethodID: "am_yubikey", MethodType: proto.AuthYubikey,
			PublicParams: []byte("yubikey-params"), UnlockKey: unlockKeys[proto.AuthYubikey],
		})
	}
	event, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub, 0, nil, methods)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := event.PrevHashInput()
	if err != nil {
		t.Fatal(err)
	}
	tip := proto.HashPrefix(prefix)
	source := t.TempDir()
	userPath := filepath.Join(source, "user.cbor")
	vaultPath := filepath.Join(source, "vault.enc")
	if err := chain.AppendUser(userPath, event); err != nil {
		t.Fatal(err)
	}
	if err := vault.Save(vaultPath, pub, &proto.VaultBody{
		SuperPriv: priv.Bytes(), AuthTip: proto.ChainTip{Seq: 0, Hash: tip[:]},
		Scopes: map[string]proto.ScopeVaultData{}, PinnedIdentities: map[string]proto.PinnedIdentity{},
	}, wraps); err != nil {
		t.Fatal(err)
	}
	userData, err = os.ReadFile(userPath)
	if err != nil {
		t.Fatal(err)
	}
	vaultData, err = os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}

	salt := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab")
	payloadNonce := []byte("abcdefghijkl")
	key, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Wipe(key)
	encryptedPriv, err := crypto.AEADSeal(key, nonce, priv.Bytes(), append([]byte(proto.DomainRecoveryKey), pub...))
	if err != nil {
		t.Fatal(err)
	}
	rf := &proto.RecoveryFile{
		Magic: proto.RecoveryMagic, Version: 2, UserSuperPub: pub, Salt: salt,
		Argon2Params: proto.Argon2Params{M: crypto.DefaultArgon2.M, T: crypto.DefaultArgon2.T, P: crypto.DefaultArgon2.P},
		Nonce:        nonce, EncryptedSuperPriv: encryptedPriv, PayloadNonce: payloadNonce,
	}
	payload, err := proto.Marshal(&proto.RecoveryPayloadV2{UserChain: userData, Vault: vaultData})
	if err != nil {
		t.Fatal(err)
	}
	rf.EncryptedPayload, err = crypto.AEADSeal(key, payloadNonce, payload, recoveryBundleAAD(rf))
	if err != nil {
		t.Fatal(err)
	}
	data, err = proto.Marshal(rf)
	if err != nil {
		t.Fatal(err)
	}
	return data, pass, pub, userData, vaultData, unlockKeys
}
