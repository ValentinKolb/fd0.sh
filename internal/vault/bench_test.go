package vault

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// bench_test.go — vault open / save / wrap performance baselines.
// Run: `go test -bench=. -benchmem ./internal/vault`.
//
// The dominant cost is Argon2id (DefaultArgon2: M=64MiB, T=3,
// P=1) which by design is slow. Anything sub-second per unlock
// is on-spec; we want to know the actual number so an
// accidentally-weakened parameter set (codex audit hazard) is
// caught by a benchmark drift.

func benchSetup(b *testing.B, pass string) (path, vaultPath string, body *proto.VaultBody, ukSalt []byte) {
	b.Helper()
	dir := b.TempDir()
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		b.Fatal(err)
	}
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		b.Fatal(err)
	}
	pp, err := NewPassphraseParams(salt, crypto.DefaultArgon2)
	if err != nil {
		b.Fatal(err)
	}
	uk, err := crypto.DeriveKey([]byte(pass), salt, crypto.DefaultArgon2)
	if err != nil {
		b.Fatal(err)
	}
	body = &proto.VaultBody{
		SuperPriv:        priv.Bytes(),
		AuthTip:          proto.ChainTip{Seq: 0, Hash: bytes.Repeat([]byte{0xAA}, 32)},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	vaultPath = filepath.Join(dir, "vault.enc")
	if err := Save(vaultPath, pub.Bytes(), body, []WrapInput{{
		MethodID: "am_bench", MethodType: proto.AuthPassphrase,
		PublicParams: pp, UnlockKey: uk,
	}}); err != nil {
		b.Fatal(err)
	}
	return dir, vaultPath, body, salt
}

// BenchmarkVaultOpenPassphrase measures the unlock-from-disk cost.
// Argon2id KDF dominates; the AEAD body decrypt is comparatively
// negligible. This is the user-facing latency for `fd0 unlock`.
func BenchmarkVaultOpenPassphrase(b *testing.B) {
	const pass = "bench-passphrase-correct-horse"
	_, vaultPath, _, _ := benchSetup(b, pass)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v, err := Read(vaultPath)
		if err != nil {
			b.Fatal(err)
		}
		res, err := Open(v, []MethodResolver{PassphraseResolver{Passphrase: []byte(pass)}})
		if err != nil {
			b.Fatal(err)
		}
		crypto.Wipe(res.PayloadKey)
		crypto.Wipe(res.UnlockKey)
	}
}

// BenchmarkVaultDeriveKeyOnly isolates Argon2id cost so we can
// see how much of Open is KDF vs the rest.
func BenchmarkVaultDeriveKeyOnly(b *testing.B) {
	salt, _ := crypto.RandomBytes(16)
	pass := []byte("bench-passphrase-correct-horse")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		uk, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
		if err != nil {
			b.Fatal(err)
		}
		crypto.Wipe(uk)
	}
}

// BenchmarkVaultSave measures the full re-seal path (after a
// vault edit). Argon2id is NOT re-run on save — only AEAD reseal
// + fsync — so this should be << Open.
func BenchmarkVaultSave(b *testing.B) {
	const pass = "bench-passphrase-correct-horse"
	dir, _, body, salt := benchSetup(b, pass)
	uk, _ := crypto.DeriveKey([]byte(pass), salt, crypto.DefaultArgon2)
	pp, _ := NewPassphraseParams(salt, crypto.DefaultArgon2)
	pub, _, _ := crypto.GenerateIdentity()
	wraps := []WrapInput{{
		MethodID: "am_bench", MethodType: proto.AuthPassphrase,
		PublicParams: pp, UnlockKey: uk,
	}}
	out := filepath.Join(dir, "vault-resave.enc")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Save(out, pub.Bytes(), body, wraps); err != nil {
			b.Fatal(err)
		}
	}
}
