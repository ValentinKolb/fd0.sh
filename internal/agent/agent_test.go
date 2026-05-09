package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

func TestAgentRoundtrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FD0_HOME", dir)
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	// Build a small vault.
	pub, priv, _ := crypto.GenerateIdentity()
	pass := []byte("secret-pass")
	salt, _ := crypto.RandomBytes(16)
	pp, _ := vault.NewPassphraseParams(salt, crypto.DefaultArgon2)
	uk, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	// Modern vaults always have a 32-byte AuthTip.Hash from the
	// genesis auth.set event. The agent's new rollback check
	// (Wave 2.4 codex security fix) rejects zero-hash AuthTips
	// to detect legacy/rolled-back vaults.
	authTipHash := bytes.Repeat([]byte{0xCC}, 32)
	body := &proto.VaultBody{
		SuperPriv: priv.Bytes(),
		AuthTip:   proto.ChainTip{Seq: 0, Hash: authTipHash},
		Scopes:    map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := vault.Save(paths.Vault, pub.Bytes(), body, []vault.WrapInput{{
		MethodID: "am_p", MethodType: proto.AuthPassphrase,
		PublicParams: pp, UnlockKey: uk,
	}}); err != nil {
		t.Fatal(err)
	}
	// Start agent.
	srv, err := Listen(paths, Config{IdleTimeout: time.Hour, MaxLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)
	defer srv.Close()
	cli := NewClient(paths.AgentSock)
	// Initially locked.
	st, err := cli.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Unlocked {
		t.Fatal("expected locked")
	}
	// Unlock.
	// Pass empty UserChainPath to skip the rollback-detection
	// check — this unit test fixture builds a vault without the
	// matching user.cbor chain, which the production-path check
	// would (correctly) reject. Integration tests cover the
	// real path.
	ur, err := cli.Unlock(paths.Vault, "", proto.AuthPassphrase, UnlockCredential{Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if len(ur.UserSuperPub) != 32 {
		t.Fatal("bad super pub")
	}
	// Sign roundtrip.
	msg := []byte("hello-fd0")
	sig, err := cli.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !crypto.Verify(pub, msg, sig) {
		t.Fatal("sign verify failed")
	}
	// OpenSeal: seal something to our X25519 pub and ask agent to open it.
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	want := []byte("oek_payload_32_bytes_aaaaaaaaaaa")[:32]
	sealed, err := crypto.SealAnonymous(want, xPub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cli.OpenSeal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	// Lock.
	if err := cli.Lock(); err != nil {
		t.Fatal(err)
	}
	st, _ = cli.Status()
	if st.Unlocked {
		t.Fatal("expected locked after Lock")
	}
	// Verify socket file persists.
	if _, err := os.Stat(filepath.Join(dir, "agent.sock")); err != nil {
		t.Fatal(err)
	}
}
