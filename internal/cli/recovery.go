package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// RunRecoveryExport writes a `RecoveryFile` to outPath. Format per
// PROTOCOL.md §6.3: super_priv encrypted under K_recovery (Argon2id of a
// recovery passphrase), bound to user_super_pub via the AAD.
func RunRecoveryExport(ctx context.Context, outPath string) error {
	if outPath == "" {
		return errors.New("output path required")
	}
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("refuse to overwrite %s", outPath)
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	pass, err := ReadPassphraseConfirm(
		"Recovery passphrase: ",
		"Confirm recovery passphrase: ",
	)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	nonce, err := crypto.Nonce12()
	if err != nil {
		return err
	}
	kRecovery, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		return fmt.Errorf("derive K_recovery: %w", err)
	}
	defer crypto.Wipe(kRecovery)
	// AEAD over super_priv with AAD = "fd0-recovery-key-v1" || user_super_pub
	aad := append([]byte(proto.DomainRecoveryKey), s.UserSuperPub...)
	// We need super_priv plaintext to encrypt. The agent doesn't expose it
	// directly; for export the agent provides a one-shot encrypted blob via
	// a domain-bound Sign on the AAD followed by AEAD performed locally is
	// not safe (we'd need super_priv). Instead: the agent itself produces
	// the recovery ciphertext.
	enc, err := s.Agent.RecoveryExport(kRecovery, salt, nonce, s.UserSuperPub)
	if err != nil {
		return err
	}
	rf := &proto.RecoveryFile{
		Magic:        proto.RecoveryMagic,
		Version:      1,
		UserSuperPub: append([]byte(nil), s.UserSuperPub...),
		Salt:         salt,
		Argon2Params: proto.Argon2Params{
			M: crypto.DefaultArgon2.M,
			T: crypto.DefaultArgon2.T,
			P: crypto.DefaultArgon2.P,
		},
		Nonce:              nonce,
		EncryptedSuperPriv: enc,
	}
	out, err := proto.Marshal(rf)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, out, 0o600); err != nil {
		return err
	}
	_ = aad
	fmt.Fprintf(os.Stderr, "✓ recovery file written to %s\n", outPath)
	fmt.Fprintln(os.Stderr, "  Store it offline. Anyone with the file AND the")
	fmt.Fprintln(os.Stderr, "  recovery passphrase can impersonate this identity.")
	return nil
}

// RunRecoveryImport bootstraps a fresh fd0 home from a RecoveryFile.
//
// Use cases:
//   - Setting up fd0 on a new device with an existing identity.
//   - Disaster recovery after losing a device.
//
// Refuses if a vault already exists. The new device:
//  1. Decrypts super_priv from the recovery file with the recovery passphrase.
//  2. Verifies Ed25519_pub(super_priv) == file.user_super_pub.
//  3. Creates a fresh user.cbor genesis auth.set with one local method
//     (passphrase chosen now).
//  4. Writes vault.enc with super_priv wrapped under the local passphrase.
//
// User MUST then run `fd0 sync` against a server to learn about scopes
// they were a member of.
func RunRecoveryImport(ctx context.Context, inPath string) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	if VaultExists(paths) {
		return fmt.Errorf("vault already exists at %s; remove it first", paths.Vault)
	}
	if _, err := os.Stat(paths.UserChain); err == nil {
		return fmt.Errorf("user chain already exists at %s; remove it first", paths.UserChain)
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	var rf proto.RecoveryFile
	if err := proto.Unmarshal(data, &rf); err != nil {
		return fmt.Errorf("recovery: decode: %w", err)
	}
	if rf.Magic != proto.RecoveryMagic {
		return fmt.Errorf("recovery: bad magic %q", rf.Magic)
	}
	if rf.Version != 1 {
		return fmt.Errorf("recovery: unsupported version %d", rf.Version)
	}
	pass, err := ReadPassphrase("Recovery passphrase: ")
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)
	kRecovery, err := crypto.DeriveKey(pass, rf.Salt, crypto.Argon2Params{
		M: rf.Argon2Params.M, T: rf.Argon2Params.T, P: rf.Argon2Params.P,
	})
	if err != nil {
		return fmt.Errorf("recovery: %w", err)
	}
	defer crypto.Wipe(kRecovery)
	aad := append([]byte(proto.DomainRecoveryKey), rf.UserSuperPub...)
	superPriv, err := crypto.AEADOpen(kRecovery, rf.Nonce, rf.EncryptedSuperPriv, aad)
	if err != nil {
		return fmt.Errorf("recovery: decrypt failed (wrong passphrase?): %w", err)
	}
	defer crypto.Wipe(superPriv)
	if len(superPriv) != ed25519.PrivateKeySize {
		return errors.New("recovery: super_priv length")
	}
	derived := ed25519.PrivateKey(superPriv).Public().(ed25519.PublicKey)
	if !bytesEq(derived, rf.UserSuperPub) {
		return errors.New("recovery: super_priv does not match user_super_pub")
	}
	// Set a new local unlock passphrase for this device.
	newPass, err := ReadPassphraseConfirm(
		"Choose a passphrase for this device: ",
		"Confirm passphrase: ",
	)
	if err != nil {
		return err
	}
	defer crypto.Wipe(newPass)
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	pp, err := vault.NewPassphraseParams(salt, crypto.DefaultArgon2)
	if err != nil {
		return err
	}
	unlockKey, err := crypto.DeriveKey(newPass, salt, crypto.DefaultArgon2)
	if err != nil {
		return fmt.Errorf("derive K_unlock: %w", err)
	}
	defer crypto.Wipe(unlockKey)
	methodID := "am_" + ulid.Make().String()
	encSP, err := vault.EncryptSuperPriv(superPriv, rf.UserSuperPub, methodID, unlockKey)
	if err != nil {
		return err
	}
	// Genesis auth.set on this device.
	g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: superPriv}, rf.UserSuperPub, 0, nil, []proto.AuthMethod{{
		MethodID:           methodID,
		MethodType:         proto.AuthPassphrase,
		PublicParams:       pp,
		EncryptedSuperPriv: encSP,
	}})
	if err != nil {
		return err
	}
	if err := chain.AppendUser(paths.UserChain, g); err != nil {
		return err
	}
	// Two-phase commit: if vault.Save fails, drop the half-written user.cbor
	// so a re-run of `fd0 recovery import` doesn't refuse on the
	// "user chain already exists" guard.
	prefix, err := g.PrevHashInput()
	if err != nil {
		_ = os.Remove(paths.UserChain)
		return err
	}
	authTipHash := proto.HashPrefix(prefix)
	body := &proto.VaultBody{
		SuperPriv:        superPriv,
		AuthTip:          proto.ChainTip{Seq: 0, Hash: authTipHash[:]},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := vault.Save(paths.Vault, rf.UserSuperPub, body, []vault.WrapInput{{
		MethodID:     methodID,
		MethodType:   proto.AuthPassphrase,
		PublicParams: pp,
		UnlockKey:    unlockKey,
	}}); err != nil {
		_ = os.Remove(paths.UserChain)
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ identity restored: %s…\n", b64sub(rf.UserSuperPub))
	fmt.Fprintf(os.Stderr, "✓ vault written to %s\n", paths.Vault)
	fmt.Fprintln(os.Stderr, "Run `fd0 unlock` to start the agent, then `fd0 sync` to fetch scopes.")
	_ = agent.OpStatus // silence unused import in some build configs
	return nil
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
