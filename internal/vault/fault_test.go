package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/test/iofault"
)

// Filesystem fault injection tests. Verify that vault writes fail
// CLEANLY (no panic, no half-written state) when the target dir
// becomes read-only / errors during fsync / etc.

// TestFaultSaveRejectsReadOnlyDir confirms that vault.Save returns
// an error (not a panic, not a partial write) when the target
// directory is read-only. STORAGE.md crash-safety contract:
// atomicWrite should propagate the underlying I/O error.
func TestFaultSaveRejectsReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := crypto.GenerateIdentity()
	salt, _ := crypto.RandomBytes(16)
	pp, _ := NewPassphraseParams(salt, crypto.DefaultArgon2)
	uk, err := crypto.DeriveKey([]byte("p"), salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	body := &proto.VaultBody{
		SuperPriv: priv.Bytes(), AuthTip: proto.ChainTip{},
		Scopes: map[string]proto.ScopeVaultData{}, PinnedIdentities: map[string]proto.PinnedIdentity{},
	}

	// First save into a writable dir to confirm baseline works.
	pathOK := filepath.Join(dir, "vault.enc")
	if err := Save(pathOK, pub.Bytes(), body, []WrapInput{{
		MethodID: "am_x", MethodType: proto.AuthPassphrase,
		PublicParams: pp, UnlockKey: uk,
	}}); err != nil {
		t.Fatal(err)
	}

	// Now make the dir read-only and try to overwrite — must fail.
	if err := iofault.MakeReadOnly(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = iofault.MakeWritable(dir) })
	// Codex test audit: verify the chmod ACTUALLY works on this
	// filesystem. macOS+SIP / certain Linux containers silently
	// ignore chmod 0500 on tmpfs — would let a Save succeed and
	// the test pass for the wrong reason.
	if probe := os.WriteFile(filepath.Join(dir, ".probe"), []byte{1}, 0o600); probe == nil {
		t.Skip("filesystem doesn't honor chmod 0500 (macOS SIP / unusual mount?); test cannot exercise read-only contract")
	}

	err = Save(pathOK, pub.Bytes(), body, []WrapInput{{
		MethodID: "am_x", MethodType: proto.AuthPassphrase,
		PublicParams: pp, UnlockKey: uk,
	}})
	if err == nil {
		t.Fatal("Save into read-only dir succeeded unexpectedly")
	}
}

// TestFaultSaveBodyOnReadOnlyDirRollback: verify that a failed
// SaveBody does NOT corrupt the existing on-disk vault. The
// previous (good) state must remain readable.
func TestFaultSaveBodyOnReadOnlyDirRollback(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := crypto.GenerateIdentity()
	salt, _ := crypto.RandomBytes(16)
	pp, _ := NewPassphraseParams(salt, crypto.DefaultArgon2)
	uk, err := crypto.DeriveKey([]byte("p"), salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	body := &proto.VaultBody{
		SuperPriv: priv.Bytes(), AuthTip: proto.ChainTip{},
		Scopes: map[string]proto.ScopeVaultData{}, PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	path := filepath.Join(dir, "vault.enc")
	if err := Save(path, pub.Bytes(), body, []WrapInput{{
		MethodID: "am_x", MethodType: proto.AuthPassphrase,
		PublicParams: pp, UnlockKey: uk,
	}}); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Open to get the payload key for SaveBody.
	v, _ := Read(path)
	res, err := Open(v, []MethodResolver{PassphraseResolver{Passphrase: []byte("p")}})
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Wipe(res.UnlockKey)
	defer crypto.Wipe(res.PayloadKey)

	// Read-only dir → SaveBody must fail.
	if err := iofault.MakeReadOnly(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = iofault.MakeWritable(dir) })

	body.AuthTip = proto.ChainTip{Seq: 99, Hash: bytes.Repeat([]byte{0xCC}, 32)}
	if err := SaveBody(path, pub.Bytes(), body, res.PayloadKey); err == nil {
		t.Fatal("SaveBody on read-only dir succeeded unexpectedly")
	}

	// Vault file MUST still be the ORIGINAL bytes (atomicWrite's
	// tmp file failed before rename, so the rename never ran).
	if err := iofault.MakeWritable(dir); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatalf("SaveBody failure corrupted on-disk vault (was %d bytes, now %d)",
			len(original), len(after))
	}
}
