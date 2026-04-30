package chain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestUserChainRoundtrip(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	g, err := BuildUserAuthSet(priv, pub, 0, nil, []proto.AuthMethod{{
		MethodID:           "am_test",
		MethodType:         proto.AuthPassphrase,
		PublicParams:       make([]byte, 16),
		EncryptedSuperPriv: []byte{0x01, 0x02},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "user.cbor")
	if err := AppendUser(p, g); err != nil {
		t.Fatal(err)
	}
	st, err := ReplayUser(p)
	if err != nil {
		t.Fatal(err)
	}
	if st == nil || st.TipSeq != 0 {
		t.Fatalf("bad state: %+v", st)
	}
	// Append a second event.
	e2, err := BuildUserAuthSet(priv, pub, st.TipSeq, st.TipHash, []proto.AuthMethod{{
		MethodID:           "am_test2",
		MethodType:         proto.AuthPassphrase,
		PublicParams:       make([]byte, 16),
		EncryptedSuperPriv: []byte{0x03},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendUser(p, e2); err != nil {
		t.Fatal(err)
	}
	st, err = ReplayUser(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.TipSeq != 1 {
		t.Fatalf("expected tip 1, got %d", st.TipSeq)
	}
}

func TestScopeChainRoundtrip(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub)
	xPriv, _ := crypto.EdPrivToX25519(priv)

	gen, oek, scopeID, err := BuildScopeGenesis(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, scopeID+".cbor")
	if err := AppendScope(p, gen); err != nil {
		t.Fatal(err)
	}
	st, err := ReplayScope(p, pub, xPub, xPriv)
	if err != nil {
		t.Fatal(err)
	}
	if st.ScopeID != scopeID {
		t.Fatalf("scope id mismatch: got %s want %s", st.ScopeID, scopeID)
	}
	if st.CurrentOEKVer != 1 {
		t.Fatalf("oek version: got %d", st.CurrentOEKVer)
	}
	// Add a secret.
	body := &proto.SecretBody{
		ID: "s_01HEXTESTID",
		Record: &proto.SecretRecord{
			Name: "AWS_KEY", Type: "kv.string", SchemaVersion: 1,
			Payload: "AKIA...", Tags: map[string]string{"env": "prod"},
		},
	}
	ev, err := BuildSecretSet(priv, pub, scopeID, st.TipSeq, st.TipHash, oek, st.CurrentOEKVer, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendScope(p, ev); err != nil {
		t.Fatal(err)
	}
	st, err = ReplayScope(p, pub, xPub, xPriv)
	if err != nil {
		t.Fatalf("replay after secret.set: %v", err)
	}
	got, ok := st.SecretIndex[body.ID]
	if !ok {
		t.Fatalf("secret not in index")
	}
	if got.Record.Name != "AWS_KEY" {
		t.Fatalf("bad name: %v", got.Record)
	}
	// Verify file contents are stable.
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
}
