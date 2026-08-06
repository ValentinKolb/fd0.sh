package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

const maxRecoveryFileSize = 4 * 1024 * 1024

// RunRecoveryExport writes a `RecoveryFile` to outPath. Format per
// PROTOCOL.md §6.3: super_priv and, in version 2, the encrypted bootstrap
// files are protected by K_recovery and bound to user_super_pub via AAD.
func RunRecoveryExport(ctx context.Context, outPath string) error {
	if outPath == "" {
		return errors.New("output path required")
	}
	pass, err := ReadPassphraseConfirm(
		"Recovery passphrase: ",
		"Confirm recovery passphrase: ",
	)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)
	out, err := ExportRecoveryWithPassphrase(ctx, pass)
	if err != nil {
		return err
	}
	if len(out) > maxRecoveryFileSize {
		return errors.New("recovery file exceeds the 4 MB limit")
	}
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refuse to overwrite %s", outPath)
		}
		return err
	}
	written := false
	defer func() {
		if !written {
			_ = os.Remove(outPath)
		}
	}()
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	written = true
	if err := syncRecoveryDir(filepath.Dir(outPath)); err != nil {
		_ = os.Remove(outPath)
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ recovery file written to %s\n", outPath)
	fmt.Fprintln(os.Stderr, "  Store it offline. Anyone with the file AND the")
	fmt.Fprintln(os.Stderr, "  recovery passphrase can impersonate this identity.")
	return nil
}

// ExportRecoveryWithPassphrase returns an encrypted RecoveryFile without
// prompting or writing it. The caller owns pass and the returned bytes.
func ExportRecoveryWithPassphrase(ctx context.Context, pass []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, errors.New("recovery passphrase cannot be empty")
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	userChain, err := os.ReadFile(s.Paths.UserChain)
	if err != nil {
		return nil, fmt.Errorf("recovery: read user chain: %w", err)
	}
	vaultData, err := os.ReadFile(s.Paths.Vault)
	if err != nil {
		return nil, fmt.Errorf("recovery: read vault: %w", err)
	}
	if err := validateRecoveryBootstrap(userChain, vaultData, s.UserSuperPub, s.UserState, &s.Body.AuthTip); err != nil {
		return nil, err
	}
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	payloadNonce, err := crypto.Nonce12()
	if err != nil {
		return nil, err
	}
	nonce, err := crypto.Nonce12()
	if err != nil {
		return nil, err
	}
	kRecovery, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		return nil, fmt.Errorf("derive K_recovery: %w", err)
	}
	defer crypto.Wipe(kRecovery)
	// We need super_priv plaintext to encrypt. The agent doesn't expose it
	// directly; for export the agent provides a one-shot encrypted blob via
	// a domain-bound Sign on the AAD followed by AEAD performed locally is
	// not safe (we'd need super_priv). Instead: the agent itself produces
	// the recovery ciphertext.
	enc, err := s.Agent.RecoveryExport(kRecovery, salt, nonce, s.UserSuperPub)
	if err != nil {
		return nil, err
	}
	rf := &proto.RecoveryFile{
		Magic:        proto.RecoveryMagic,
		Version:      2,
		UserSuperPub: append([]byte(nil), s.UserSuperPub...),
		Salt:         salt,
		Argon2Params: proto.Argon2Params{
			M: crypto.DefaultArgon2.M,
			T: crypto.DefaultArgon2.T,
			P: crypto.DefaultArgon2.P,
		},
		Nonce:              nonce,
		EncryptedSuperPriv: enc,
		PayloadNonce:       payloadNonce,
	}
	payload, err := proto.Marshal(&proto.RecoveryPayloadV2{UserChain: userChain, Vault: vaultData})
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(payload)
	rf.EncryptedPayload, err = crypto.AEADSeal(kRecovery, payloadNonce, payload, recoveryBundleAAD(rf))
	if err != nil {
		return nil, fmt.Errorf("recovery: encrypt bootstrap: %w", err)
	}
	out, err := proto.Marshal(rf)
	if err != nil {
		return nil, err
	}
	if len(out) > maxRecoveryFileSize {
		return nil, errors.New("recovery file exceeds the 4 MB limit")
	}
	return out, nil
}

// VerifyRecoveryWithPassphrase decrypts and validates a recovery artifact
// without changing local state.
func VerifyRecoveryWithPassphrase(data, pass, expectedPub []byte) error {
	if len(data) == 0 || len(data) > maxRecoveryFileSize {
		return errors.New("recovery file is empty or exceeds the 4 MB limit")
	}
	var rf proto.RecoveryFile
	if err := proto.Unmarshal(data, &rf); err != nil {
		return fmt.Errorf("recovery: decode: %w", err)
	}
	if rf.Magic != proto.RecoveryMagic || (rf.Version != 1 && rf.Version != 2) {
		return errors.New("recovery: unsupported recovery file")
	}
	if !bytesEq(rf.UserSuperPub, expectedPub) {
		return errors.New("recovery: identity does not match current vault")
	}
	kRecovery, err := recoveryKey(pass, &rf)
	if err != nil {
		return fmt.Errorf("recovery: %w", err)
	}
	defer crypto.Wipe(kRecovery)
	superPriv, err := openRecoverySuperPriv(&rf, kRecovery)
	if err != nil {
		return fmt.Errorf("recovery: verify decrypt: %w", err)
	}
	defer crypto.Wipe(superPriv)
	if len(superPriv) != ed25519.PrivateKeySize {
		return errors.New("recovery: super_priv length")
	}
	derived := ed25519.PrivateKey(superPriv).Public().(ed25519.PublicKey)
	if !bytesEq(derived, expectedPub) {
		return errors.New("recovery: private identity does not match public identity")
	}
	if rf.Version == 2 {
		payload, err := openRecoveryPayload(&rf, kRecovery)
		if err != nil {
			return fmt.Errorf("recovery: verify bootstrap: %w", err)
		}
		defer crypto.Wipe(payload.UserChain)
		defer crypto.Wipe(payload.Vault)
		if err := validateRecoveryBootstrap(payload.UserChain, payload.Vault, expectedPub, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// RunRecoveryImport bootstraps a fresh fd0 home from a RecoveryFile.
//
// Use cases:
//   - Setting up fd0 on a new device with an existing identity.
//   - Disaster recovery after losing a device.
//
// Refuses if a vault already exists. Version 2 restores the signed user chain
// and encrypted vault snapshot byte-for-byte, retaining every authentication
// method present at export. Legacy version 1 creates one new local passphrase.
//
// User MUST then run `fd0 sync` against a server to learn about scopes
// they were a member of.
func RunRecoveryImport(ctx context.Context, inPath string, yes bool) error {
	paths, err := recoveryImportTarget()
	if err != nil {
		return err
	}
	if err := confirmDanger(yes, fmt.Sprintf("Bootstrap %s from recovery file %s?", paths.Home, inPath)); err != nil {
		return err
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	if len(data) > maxRecoveryFileSize {
		return errors.New("recovery file exceeds the 4 MB limit")
	}
	pass, err := ReadPassphrase("Recovery passphrase: ")
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)
	version, err := RecoveryVersion(data)
	if err != nil {
		return err
	}
	var newPass []byte
	if version == 1 {
		newPass, err = ReadPassphraseConfirm(
			"Choose a passphrase for this device: ",
			"Confirm passphrase: ",
		)
		if err != nil {
			return err
		}
		defer crypto.Wipe(newPass)
	}
	result, err := ImportRecoveryWithPassphrases(ctx, data, pass, newPass)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ identity restored: %s…\n", b64sub(result.UserSuperPub))
	fmt.Fprintf(os.Stderr, "✓ vault written to %s\n", result.VaultPath)
	fmt.Fprintln(os.Stderr, "Run `fd0 unlock`, then `fd0 sync` to refresh your vaults.")
	return nil
}

// RecoveryImportResult describes a restored identity without exposing private
// key material.
type RecoveryImportResult struct {
	UserSuperPub []byte
	VaultPath    string
}

// ImportRecoveryWithPassphrases restores a fresh fd0 home from recovery data.
// It refuses to overwrite an existing vault or user chain. The caller owns and
// must wipe both passphrases.
func ImportRecoveryWithPassphrases(ctx context.Context, data, recoveryPass, newPass []byte) (*RecoveryImportResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(recoveryPass) == 0 {
		return nil, errors.New("recovery passphrase is required")
	}
	if len(data) == 0 || len(data) > maxRecoveryFileSize {
		return nil, errors.New("recovery file is empty or exceeds the 4 MB limit")
	}
	paths, err := recoveryImportTarget()
	if err != nil {
		return nil, err
	}
	var rf proto.RecoveryFile
	if err := proto.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("recovery: decode: %w", err)
	}
	if rf.Magic != proto.RecoveryMagic {
		return nil, fmt.Errorf("recovery: bad magic %q", rf.Magic)
	}
	if rf.Version == 2 {
		return importRecoveryV2(paths, &rf, recoveryPass)
	}
	if rf.Version != 1 {
		return nil, fmt.Errorf("recovery: unsupported version %d", rf.Version)
	}
	if len(newPass) == 0 {
		return nil, errors.New("legacy recovery files require a new local passphrase")
	}
	kRecovery, err := crypto.DeriveKey(recoveryPass, rf.Salt, crypto.Argon2Params{
		M: rf.Argon2Params.M, T: rf.Argon2Params.T, P: rf.Argon2Params.P,
	})
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}
	defer crypto.Wipe(kRecovery)
	aad := append([]byte(proto.DomainRecoveryKey), rf.UserSuperPub...)
	superPriv, err := crypto.AEADOpen(kRecovery, rf.Nonce, rf.EncryptedSuperPriv, aad)
	if err != nil {
		return nil, fmt.Errorf("recovery: decrypt failed (wrong passphrase?): %w", err)
	}
	defer crypto.Wipe(superPriv)
	if len(superPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("recovery: super_priv length")
	}
	derived := ed25519.PrivateKey(superPriv).Public().(ed25519.PublicKey)
	if !bytesEq(derived, rf.UserSuperPub) {
		return nil, errors.New("recovery: super_priv does not match user_super_pub")
	}
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	pp, err := vault.NewPassphraseParams(salt, crypto.DefaultArgon2)
	if err != nil {
		return nil, err
	}
	unlockKey, err := crypto.DeriveKey(newPass, salt, crypto.DefaultArgon2)
	if err != nil {
		return nil, fmt.Errorf("derive K_unlock: %w", err)
	}
	defer crypto.Wipe(unlockKey)
	methodID := "am_" + ulid.Make().String()
	encSP, err := vault.EncryptSuperPriv(superPriv, rf.UserSuperPub, methodID, unlockKey)
	if err != nil {
		return nil, err
	}
	// Genesis auth.set on this device. Wave C-3': parse the
	// recovery-decrypted priv into the typed Ed25519Priv before
	// handing it to LocalSigner. ParseEd25519Priv re-derives the
	// public half from the seed and rejects on mismatch — a
	// corrupted recovery file produces a clean error rather than
	// the silent-bad-signing-failure that the old code would
	// emit.
	signerPriv, perr := crypto.ParseEd25519Priv(superPriv)
	if perr != nil {
		return nil, fmt.Errorf("recovery: parse super_priv: %w", perr)
	}
	// Codex Wave-C-3' review fix: ParseEd25519Priv allocates a
	// second 64-byte copy of the decrypted super_priv. The
	// signer is one-shot (genesis auth.set then discarded) so
	// wipe via the typed Wipe (which delegates to crypto.Wipe
	// with the runtime.KeepAlive safeguard).
	defer signerPriv.Wipe()
	g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: signerPriv}, rf.UserSuperPub, 0, nil, []proto.AuthMethod{{
		MethodID:           methodID,
		MethodType:         proto.AuthPassphrase,
		PublicParams:       pp,
		EncryptedSuperPriv: encSP,
	}})
	if err != nil {
		return nil, err
	}
	if err := chain.AppendUser(paths.UserChain, g); err != nil {
		return nil, err
	}
	// Two-phase commit: if vault.Save fails, drop the half-written user.cbor
	// so a re-run of `fd0 recovery import` doesn't refuse on the
	// "user chain already exists" guard.
	prefix, err := g.PrevHashInput()
	if err != nil {
		_ = os.Remove(paths.UserChain)
		return nil, err
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
		return nil, err
	}
	_ = agent.OpStatus // silence unused import in some build configs
	return &RecoveryImportResult{
		UserSuperPub: append([]byte(nil), rf.UserSuperPub...),
		VaultPath:    paths.Vault,
	}, nil
}

// RecoveryVersion reports the on-disk recovery format without decrypting it.
func RecoveryVersion(data []byte) (uint8, error) {
	if len(data) == 0 || len(data) > maxRecoveryFileSize {
		return 0, errors.New("recovery file is empty or exceeds the 4 MB limit")
	}
	var rf proto.RecoveryFile
	if err := proto.Unmarshal(data, &rf); err != nil {
		return 0, fmt.Errorf("recovery: decode: %w", err)
	}
	if rf.Magic != proto.RecoveryMagic || (rf.Version != 1 && rf.Version != 2) {
		return 0, errors.New("recovery: unsupported recovery file")
	}
	return rf.Version, nil
}

func importRecoveryV2(paths fdhome.Paths, rf *proto.RecoveryFile, recoveryPass []byte) (*RecoveryImportResult, error) {
	kRecovery, err := recoveryKey(recoveryPass, rf)
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}
	defer crypto.Wipe(kRecovery)
	superPriv, err := openRecoverySuperPriv(rf, kRecovery)
	if err != nil {
		return nil, fmt.Errorf("recovery: decrypt failed (wrong passphrase?): %w", err)
	}
	defer crypto.Wipe(superPriv)
	if len(superPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("recovery: super_priv length")
	}
	derived := ed25519.PrivateKey(superPriv).Public().(ed25519.PublicKey)
	if !bytesEq(derived, rf.UserSuperPub) {
		return nil, errors.New("recovery: super_priv does not match user_super_pub")
	}
	payload, err := openRecoveryPayload(rf, kRecovery)
	if err != nil {
		return nil, fmt.Errorf("recovery: decrypt bootstrap: %w", err)
	}
	defer crypto.Wipe(payload.UserChain)
	defer crypto.Wipe(payload.Vault)
	if err := validateRecoveryBootstrap(payload.UserChain, payload.Vault, rf.UserSuperPub, nil, nil); err != nil {
		return nil, err
	}
	if err := installRecoveryBootstrap(paths, payload.UserChain, payload.Vault); err != nil {
		return nil, err
	}
	return &RecoveryImportResult{
		UserSuperPub: append([]byte(nil), rf.UserSuperPub...),
		VaultPath:    paths.Vault,
	}, nil
}

func recoveryKey(pass []byte, rf *proto.RecoveryFile) ([]byte, error) {
	if len(rf.Salt) != 16 || len(rf.Nonce) != 12 {
		return nil, errors.New("invalid salt or nonce")
	}
	return crypto.DeriveKey(pass, rf.Salt, crypto.Argon2Params{
		M: rf.Argon2Params.M, T: rf.Argon2Params.T, P: rf.Argon2Params.P,
	})
}

func openRecoverySuperPriv(rf *proto.RecoveryFile, key []byte) ([]byte, error) {
	aad := append([]byte(proto.DomainRecoveryKey), rf.UserSuperPub...)
	return crypto.AEADOpen(key, rf.Nonce, rf.EncryptedSuperPriv, aad)
}

func recoveryBundleAAD(rf *proto.RecoveryFile) []byte {
	aad := append([]byte(proto.DomainRecoveryBundle), rf.UserSuperPub...)
	aad = append(aad, rf.Nonce...)
	aad = append(aad, rf.EncryptedSuperPriv...)
	return aad
}

func openRecoveryPayload(rf *proto.RecoveryFile, key []byte) (*proto.RecoveryPayloadV2, error) {
	if len(rf.PayloadNonce) != 12 || len(rf.EncryptedPayload) == 0 {
		return nil, errors.New("missing bootstrap payload")
	}
	plain, err := crypto.AEADOpen(key, rf.PayloadNonce, rf.EncryptedPayload, recoveryBundleAAD(rf))
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(plain)
	var payload proto.RecoveryPayloadV2
	if err := proto.Unmarshal(plain, &payload); err != nil {
		return nil, fmt.Errorf("decode bootstrap: %w", err)
	}
	if len(payload.UserChain) == 0 || len(payload.Vault) == 0 || len(payload.UserChain)+len(payload.Vault) > 4*1024*1024 {
		return nil, errors.New("bootstrap payload is empty or too large")
	}
	return &payload, nil
}

func validateRecoveryBootstrap(userData, vaultData, expectedPub []byte, expectedState *chain.UserState, expectedTip *proto.ChainTip) error {
	tmp, err := os.CreateTemp("", "fd0-recovery-user-*.cbor")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(userData); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	state, err := chain.ReplayUser(tmpPath)
	if err != nil {
		return fmt.Errorf("recovery: invalid user chain: %w", err)
	}
	if info, err := os.Stat(tmpPath); err != nil || info.Size() != int64(len(userData)) {
		return errors.New("recovery: user chain has an incomplete tail")
	}
	if state == nil || state.LatestAuthSet == nil || !bytes.Equal(state.UserSuperPub, expectedPub) {
		return errors.New("recovery: user chain identity mismatch")
	}
	if expectedState != nil && (state.TipSeq != expectedState.TipSeq || !bytes.Equal(state.TipHash, expectedState.TipHash)) {
		return errors.New("recovery: user chain changed during export")
	}
	if expectedTip != nil && (state.TipSeq != expectedTip.Seq || !bytes.Equal(state.TipHash, expectedTip.Hash)) {
		return errors.New("recovery: vault authentication tip is stale")
	}
	var vf proto.VaultFile
	if err := proto.Unmarshal(vaultData, &vf); err != nil {
		return fmt.Errorf("recovery: invalid vault: %w", err)
	}
	if vf.Magic != proto.VaultMagic || vf.Version != 1 || !bytes.Equal(vf.UserSuperPub, expectedPub) || len(vf.BodyNonce) != 12 || len(vf.Body) < 16 {
		return errors.New("recovery: invalid vault header")
	}
	active := state.LatestAuthSet.Payload.Active
	if len(active) != len(vf.WrappedPayloadKeys) {
		return errors.New("recovery: authentication methods do not match vault wraps")
	}
	wraps := make(map[string]proto.WrappedKey, len(vf.WrappedPayloadKeys))
	for _, wrap := range vf.WrappedPayloadKeys {
		if wrap.MethodID == "" || len(wrap.WrapNonce) != 12 || len(wrap.Wrapped) < 16 {
			return errors.New("recovery: invalid vault wrap")
		}
		if _, duplicate := wraps[wrap.MethodID]; duplicate {
			return errors.New("recovery: duplicate vault wrap")
		}
		wraps[wrap.MethodID] = wrap
	}
	for _, method := range active {
		wrap, ok := wraps[method.MethodID]
		if !ok || wrap.MethodType != method.MethodType || !bytes.Equal(wrap.PublicParams, method.PublicParams) {
			return errors.New("recovery: authentication method does not match vault wrap")
		}
	}
	return nil
}

func installRecoveryBootstrap(paths fdhome.Paths, userData, vaultData []byte) error {
	userTmp, err := writeRecoveryTemp(paths.UserChain, userData)
	if err != nil {
		return err
	}
	defer os.Remove(userTmp)
	vaultTmp, err := writeRecoveryTemp(paths.Vault, vaultData)
	if err != nil {
		return err
	}
	defer os.Remove(vaultTmp)
	// Hard-linking staged files gives us an atomic no-overwrite commit on the
	// supported Unix platforms. os.Rename would silently replace a vault that
	// appeared after recoveryImportTarget checked it.
	if err := os.Link(userTmp, paths.UserChain); err != nil {
		return fmt.Errorf("recovery: install user chain: %w", err)
	}
	if err := os.Link(vaultTmp, paths.Vault); err != nil {
		_ = os.Remove(paths.UserChain)
		return fmt.Errorf("recovery: install vault: %w", err)
	}
	if err := syncRecoveryDir(paths.Chains); err != nil {
		_ = os.Remove(paths.UserChain)
		_ = os.Remove(paths.Vault)
		return err
	}
	if err := syncRecoveryDir(paths.Home); err != nil {
		_ = os.Remove(paths.UserChain)
		_ = os.Remove(paths.Vault)
		return err
	}
	return nil
}

func writeRecoveryTemp(target string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(target), ".fd0-recovery-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func syncRecoveryDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func recoveryImportTarget() (fdhome.Paths, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return fdhome.Paths{}, err
	}
	if err := paths.EnsureDirs(); err != nil {
		return fdhome.Paths{}, err
	}
	if VaultExists(paths) {
		return fdhome.Paths{}, fmt.Errorf("vault already exists at %s; remove it first", paths.Vault)
	}
	if _, err := os.Stat(paths.UserChain); err == nil {
		return fdhome.Paths{}, fmt.Errorf("user chain already exists at %s; remove it first", paths.UserChain)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fdhome.Paths{}, err
	}
	return paths, nil
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
