// Package vault implements the encrypted on-disk vault (PROTOCOL.md §6).
//
// Layout:
//
//	VaultFile ← AES-GCM-encrypted body wrapped with one or more WrappedKeys.
//	Each WrappedKey carries a method-specific public_params and a 32-byte
//	payload_key encrypted under K_unlock derived from a credential.
//
// The vault binds chain tips (auth_tip, per-scope chain_tip) so single-file
// rollback of either the chain or the vault is detected on open.
//
// Re-seal generates a fresh payload_key on every save (per-version forward
// secrecy: an attacker who recovers an old vault file does not learn future
// content).
package vault

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// MethodResolver resolves a WrappedKey's K_unlock from a credential available
// on this device. Implemented by the unlock backends (passphrase, yubikey).
type MethodResolver interface {
	// MethodType reports which auth-method type this resolver handles.
	MethodType() string
	// UnlockKey derives K_unlock from the WrappedKey's public_params.
	UnlockKey(publicParams []byte) ([]byte, error)
}

// Read reads and parses the vault file header, returning the on-disk
// representation. Body is still encrypted.
func Read(path string) (*proto.VaultFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v proto.VaultFile
	if err := proto.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("vault: decode: %w", err)
	}
	if v.Magic != proto.VaultMagic {
		return nil, fmt.Errorf("vault: bad magic %q", v.Magic)
	}
	if v.Version != 1 {
		return nil, fmt.Errorf("vault: unsupported version %d", v.Version)
	}
	return &v, nil
}

// OpenResult bundles everything an Unlock returns.
type OpenResult struct {
	Body       *proto.VaultBody  // decoded plaintext
	UsedWrap   *proto.WrappedKey // wrap whose K_unlock worked
	UnlockKey  []byte            // 32 B K_unlock for UsedWrap (caller wipes)
	PayloadKey []byte            // 32 B (caller wipes); stable across re-seals
}

// Open unwraps a vault using one of resolvers. payload_key and unlock_key are
// returned to the caller so the agent can cache them; both are sensitive and
// must be wiped after they're persisted into mlocked memory.
func Open(v *proto.VaultFile, resolvers []MethodResolver) (OpenResult, error) {
	var zero OpenResult
	wk, payloadKey, unlockKey, err := unwrapPayloadKey(v, resolvers)
	if err != nil {
		return zero, err
	}
	bodyAAD, err := bodyAAD(v)
	if err != nil {
		crypto.Wipe(payloadKey)
		crypto.Wipe(unlockKey)
		return zero, err
	}
	if len(v.Body) < 16 {
		crypto.Wipe(payloadKey)
		crypto.Wipe(unlockKey)
		return zero, errors.New("vault: body too short")
	}
	plain, err := crypto.AEADOpen(payloadKey, v.BodyNonce, v.Body, bodyAAD)
	if err != nil {
		crypto.Wipe(payloadKey)
		crypto.Wipe(unlockKey)
		return zero, fmt.Errorf("vault: decrypt body (method=%s): %w", wk.MethodID, err)
	}
	defer crypto.Wipe(plain)
	var body proto.VaultBody
	if err := proto.Unmarshal(plain, &body); err != nil {
		crypto.Wipe(payloadKey)
		crypto.Wipe(unlockKey)
		return zero, fmt.Errorf("vault: decode body: %w", err)
	}
	return OpenResult{Body: &body, UsedWrap: wk, UnlockKey: unlockKey, PayloadKey: payloadKey}, nil
}

// Save re-seals the vault. wraps lists every (method, public_params,
// unlock_key) the new vault should be unlockable by — typically one entry per
// active AuthMethod. A fresh payload_key is generated per save.
//
// SECURITY: empty wraps would write a vault that no auth method can
// open — silently bricking the user. Reject before encrypting
// (codex audit: 🟡).
func Save(path string, userSuperPub []byte, body *proto.VaultBody, wraps []WrapInput) error {
	if len(wraps) == 0 {
		return errors.New("vault: refusing to save with empty wrap list (would be unlockable by nobody)")
	}
	plain, err := proto.Marshal(body)
	if err != nil {
		return err
	}
	defer crypto.Wipe(plain)

	payloadKey, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	defer crypto.Wipe(payloadKey)

	bodyNonce, err := crypto.Nonce12()
	if err != nil {
		return err
	}

	// Build wrapped_payload_keys.
	wrapped := make([]proto.WrappedKey, 0, len(wraps))
	for _, w := range wraps {
		wrapNonce, err := crypto.Nonce12()
		if err != nil {
			return err
		}
		hdr := proto.WrappedKeyHeader{
			MethodID:     w.MethodID,
			MethodType:   w.MethodType,
			PublicParams: w.PublicParams,
			WrapNonce:    wrapNonce,
		}
		hdrBytes, err := proto.Marshal(hdr)
		if err != nil {
			return err
		}
		aad := append([]byte(proto.DomainVaultWrap), userSuperPub...)
		aad = append(aad, hdrBytes...)
		ct, err := crypto.AEADSeal(w.UnlockKey, wrapNonce, payloadKey, aad)
		if err != nil {
			return err
		}
		wrapped = append(wrapped, proto.WrappedKey{
			MethodID:     w.MethodID,
			MethodType:   w.MethodType,
			PublicParams: w.PublicParams,
			WrapNonce:    wrapNonce,
			Wrapped:      ct,
		})
	}

	header := proto.VaultFileHeader{
		Magic:              proto.VaultMagic,
		Version:            1,
		UserSuperPub:       userSuperPub,
		WrappedPayloadKeys: wrapped,
		BodyNonce:          bodyNonce,
	}
	headerBytes, err := proto.Marshal(header)
	if err != nil {
		return err
	}
	bodyAAD := append([]byte(proto.DomainVaultBody), headerBytes...)
	ct, err := crypto.AEADSeal(payloadKey, bodyNonce, plain, bodyAAD)
	if err != nil {
		return err
	}
	v := proto.VaultFile{
		Magic:              proto.VaultMagic,
		Version:            1,
		UserSuperPub:       userSuperPub,
		WrappedPayloadKeys: wrapped,
		BodyNonce:          bodyNonce,
		Body:               ct,
	}
	out, err := proto.Marshal(&v)
	if err != nil {
		return err
	}
	return atomicWrite(path, out)
}

// WrapInput describes one auth-method's contribution to a re-seal.
type WrapInput struct {
	MethodID     string
	MethodType   string
	PublicParams []byte
	UnlockKey    []byte // K_unlock; 32 bytes; caller wipes after Save
}

// SaveBody re-encrypts only the body using the caller-supplied stable
// payloadKey, leaving the existing wraps on disk unchanged. Used by the
// agent for routine vault updates between credential rotations.
//
// AAD includes the wraps array, so changing nothing but body still produces
// fresh ciphertext (we regenerate body_nonce). That keeps the AEAD safe
// without perturbing wrap entries (which would invalidate K_unlocks the
// agent doesn't hold for non-active methods).
//
// SECURITY: this path keeps `payloadKey` STABLE across saves. The
// codex audit (🔴) flagged that PROTOCOL.md previously claimed
// "fresh payload_key per save" provides forward secrecy, but that
// property is unattainable here without re-wrapping under EVERY
// auth method's K_unlock — which the agent does not hold (only the
// currently-active method's). The spec was amended to acknowledge:
// fresh payload_key happens on credential rotation (Save), routine
// updates (SaveBody) keep the stable key. An attacker who recovers
// BOTH an old vault snapshot AND the K_unlock for any active wrap
// can decrypt all subsequent body snapshots until the next
// credential rotation. v2 may add a per-body DEK chain to close
// this gap without per-save user interaction.
func SaveBody(path string, userSuperPub []byte, body *proto.VaultBody, payloadKey []byte) error {
	if len(payloadKey) != 32 {
		return errors.New("vault: SaveBody requires 32-byte payload_key")
	}
	v, err := Read(path)
	if err != nil {
		return err
	}
	plain, err := proto.Marshal(body)
	if err != nil {
		return err
	}
	defer crypto.Wipe(plain)
	bodyNonce, err := crypto.Nonce12()
	if err != nil {
		return err
	}
	header := proto.VaultFileHeader{
		Magic:              proto.VaultMagic,
		Version:            1,
		UserSuperPub:       userSuperPub,
		WrappedPayloadKeys: v.WrappedPayloadKeys,
		BodyNonce:          bodyNonce,
	}
	hb, err := proto.Marshal(header)
	if err != nil {
		return err
	}
	aad := append([]byte(proto.DomainVaultBody), hb...)
	ct, err := crypto.AEADSeal(payloadKey, bodyNonce, plain, aad)
	if err != nil {
		return err
	}
	out := proto.VaultFile{
		Magic:              proto.VaultMagic,
		Version:            1,
		UserSuperPub:       userSuperPub,
		WrappedPayloadKeys: v.WrappedPayloadKeys,
		BodyNonce:          bodyNonce,
		Body:               ct,
	}
	enc, err := proto.Marshal(&out)
	if err != nil {
		return err
	}
	return atomicWrite(path, enc)
}

// AddWrap encrypts the caller-supplied stable payloadKey under newWrap's
// UnlockKey, appends it to the on-disk wraps list, and re-encrypts the body
// (because the body AAD covers the wraps array).
//
// Idempotent on duplicate method_id: if a wrap with that method_id already
// exists AND its payload-key decryption matches under the supplied
// UnlockKey, the call is a no-op (= success). This supports crash recovery
// when a previous `auth add` was interrupted between AddWrap and the
// chain.AppendUser write — retrying must not error.
//
// If a wrap with the same method_id exists but with a DIFFERENT
// UnlockKey (genuine collision: random ulid duplicated, or programmer
// error), the call still returns an explicit error so we don't silently
// replace a credential.
func AddWrap(path string, userSuperPub []byte, body *proto.VaultBody, payloadKey []byte, newWrap WrapInput) error {
	if len(payloadKey) != 32 || len(newWrap.UnlockKey) != 32 {
		return errors.New("vault: AddWrap requires 32-byte keys")
	}
	v, err := Read(path)
	if err != nil {
		return err
	}
	for _, w := range v.WrappedPayloadKeys {
		if w.MethodID != newWrap.MethodID {
			continue
		}
		// Same method_id present already. Verify the existing wrap
		// decrypts to the same payload_key under the caller's
		// UnlockKey — if so, this is a retry of an earlier
		// (interrupted) AddWrap and we treat it as success. If not,
		// the method_id collides with a different credential; refuse.
		hdr := proto.WrappedKeyHeader{
			MethodID: w.MethodID, MethodType: w.MethodType,
			PublicParams: w.PublicParams, WrapNonce: w.WrapNonce,
		}
		hb, err := proto.Marshal(hdr)
		if err != nil {
			return err
		}
		aad := append([]byte(proto.DomainVaultWrap), userSuperPub...)
		aad = append(aad, hb...)
		got, err := crypto.AEADOpen(newWrap.UnlockKey, w.WrapNonce, w.Wrapped, aad)
		if err != nil {
			return fmt.Errorf("vault: method_id %q already exists with a different credential", newWrap.MethodID)
		}
		// crypto.Wipe handles slices we no longer need.
		match := len(got) == len(payloadKey) && subtle.ConstantTimeCompare(got, payloadKey) == 1
		crypto.Wipe(got)
		if !match {
			return fmt.Errorf("vault: method_id %q exists but wraps a different payload_key", newWrap.MethodID)
		}
		// Truly a no-op retry. Caller's chain step can proceed.
		return nil
	}
	wrapNonce, err := crypto.Nonce12()
	if err != nil {
		return err
	}
	hdr := proto.WrappedKeyHeader{
		MethodID: newWrap.MethodID, MethodType: newWrap.MethodType,
		PublicParams: newWrap.PublicParams, WrapNonce: wrapNonce,
	}
	hb, err := proto.Marshal(hdr)
	if err != nil {
		return err
	}
	wrapAAD := append([]byte(proto.DomainVaultWrap), userSuperPub...)
	wrapAAD = append(wrapAAD, hb...)
	wct, err := crypto.AEADSeal(newWrap.UnlockKey, wrapNonce, payloadKey, wrapAAD)
	if err != nil {
		return err
	}
	newWraps := append([]proto.WrappedKey(nil), v.WrappedPayloadKeys...)
	newWraps = append(newWraps, proto.WrappedKey{
		MethodID: newWrap.MethodID, MethodType: newWrap.MethodType,
		PublicParams: newWrap.PublicParams, WrapNonce: wrapNonce, Wrapped: wct,
	})
	return saveWithWraps(path, userSuperPub, body, payloadKey, newWraps)
}

// RemoveWrap drops the wrap whose method_id matches and re-encrypts the
// body. Refuses to leave the vault with zero wraps.
//
// Idempotent on "method_id not found": this supports crash recovery from
// an interrupted `auth rm` (where the wrap was removed but the chain
// append failed). Returning success in that case lets the user retry
// `auth rm` without manual repair.
func RemoveWrap(path string, userSuperPub []byte, body *proto.VaultBody, payloadKey []byte, methodID string) error {
	if len(payloadKey) != 32 {
		return errors.New("vault: RemoveWrap requires 32-byte payload_key")
	}
	v, err := Read(path)
	if err != nil {
		return err
	}
	newWraps := make([]proto.WrappedKey, 0, len(v.WrappedPayloadKeys))
	found := false
	for _, w := range v.WrappedPayloadKeys {
		if w.MethodID == methodID {
			found = true
			continue
		}
		newWraps = append(newWraps, w)
	}
	if !found {
		// Already gone; treat as success so retries after a partial
		// `auth rm` complete cleanly.
		return nil
	}
	if len(newWraps) == 0 {
		return errors.New("vault: refusing to remove the last wrap (would lock you out)")
	}
	return saveWithWraps(path, userSuperPub, body, payloadKey, newWraps)
}

// saveWithWraps re-writes the vault with explicit wraps + a stable
// payloadKey. Body is re-encrypted under the new header AAD.
func saveWithWraps(path string, userSuperPub []byte, body *proto.VaultBody, payloadKey []byte, wraps []proto.WrappedKey) error {
	plain, err := proto.Marshal(body)
	if err != nil {
		return err
	}
	defer crypto.Wipe(plain)
	bodyNonce, err := crypto.Nonce12()
	if err != nil {
		return err
	}
	header := proto.VaultFileHeader{
		Magic:              proto.VaultMagic,
		Version:            1,
		UserSuperPub:       userSuperPub,
		WrappedPayloadKeys: wraps,
		BodyNonce:          bodyNonce,
	}
	hb, err := proto.Marshal(header)
	if err != nil {
		return err
	}
	aad := append([]byte(proto.DomainVaultBody), hb...)
	ct, err := crypto.AEADSeal(payloadKey, bodyNonce, plain, aad)
	if err != nil {
		return err
	}
	out := proto.VaultFile{
		Magic:              proto.VaultMagic,
		Version:            1,
		UserSuperPub:       userSuperPub,
		WrappedPayloadKeys: wraps,
		BodyNonce:          bodyNonce,
		Body:               ct,
	}
	enc, err := proto.Marshal(&out)
	if err != nil {
		return err
	}
	return atomicWrite(path, enc)
}

// unwrapPayloadKey iterates resolvers, finds the WrappedKey whose K_unlock
// successfully decrypts the payload_key, and returns it together with that
// K_unlock. Caller wipes the returned unlockKey when done.
//
// On full failure we surface the LAST resolver error rather than a generic
// "no matching auth method" — otherwise a YubiKey parse / PIN / card error
// gets swallowed and the user sees a misleading message. The fallback
// "no matching auth method" only fires when no wrap matched any
// resolver's MethodType (i.e. mismatched build, not credential failure).
func unwrapPayloadKey(v *proto.VaultFile, resolvers []MethodResolver) (*proto.WrappedKey, []byte, []byte, error) {
	var lastErr error
	for _, r := range resolvers {
		mt := r.MethodType()
		for i, w := range v.WrappedPayloadKeys {
			if w.MethodType != mt {
				continue
			}
			uk, err := r.UnlockKey(w.PublicParams)
			if err != nil {
				lastErr = err
				continue
			}
			hdr := proto.WrappedKeyHeader{
				MethodID:     w.MethodID,
				MethodType:   w.MethodType,
				PublicParams: w.PublicParams,
				WrapNonce:    w.WrapNonce,
			}
			hb, err := proto.Marshal(hdr)
			if err != nil {
				crypto.Wipe(uk)
				return nil, nil, nil, err
			}
			aad := append([]byte(proto.DomainVaultWrap), v.UserSuperPub...)
			aad = append(aad, hb...)
			pk, err := crypto.AEADOpen(uk, w.WrapNonce, w.Wrapped, aad)
			if err != nil {
				crypto.Wipe(uk)
				lastErr = fmt.Errorf("vault: AEAD-open wrap %s: %w", w.MethodID, err)
				continue
			}
			wk := v.WrappedPayloadKeys[i]
			return &wk, pk, uk, nil
		}
	}
	if lastErr != nil {
		return nil, nil, nil, lastErr
	}
	return nil, nil, nil, errors.New("vault: no matching auth method or wrong credential")
}

// bodyAAD = domain || cbor(VaultFileHeader).
func bodyAAD(v *proto.VaultFile) ([]byte, error) {
	hdr := proto.VaultFileHeader{
		Magic:              v.Magic,
		Version:            v.Version,
		UserSuperPub:       v.UserSuperPub,
		WrappedPayloadKeys: v.WrappedPayloadKeys,
		BodyNonce:          v.BodyNonce,
	}
	hb, err := proto.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	return append([]byte(proto.DomainVaultBody), hb...), nil
}

// atomicWrite writes data to path via a tmp file with fsync + rename + dir fsync.
//
// SECURITY (codex security audit 🟠): O_NOFOLLOW on the tmp file
// prevents a same-UID attacker from planting a symlink at
// `<path>.tmp` to redirect the vault write into an attacker-
// chosen location. fd0's threat model assumes the home dir is
// 0700-owned by the user, but defense-in-depth is cheap.
func atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// fsync parent so the rename is durable across power-loss.
	// Codex audit (🟡): the previous version swallowed Open/Sync/
	// Close errors, so atomicWrite could report success after
	// rename even though the directory entry was not durable —
	// violating the STORAGE.md crash-safety contract.
	dir := filepath.Dir(path)
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("vault: open parent dir for fsync: %w", err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return fmt.Errorf("vault: fsync parent dir: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("vault: close parent dir: %w", closeErr)
	}
	return nil
}
