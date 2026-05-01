package chain

import (
	"bytes"
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
	g, err := BuildUserAuthSet(LocalSigner{Priv: priv}, pub, 0, nil, []proto.AuthMethod{{
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
	e2, err := BuildUserAuthSet(LocalSigner{Priv: priv}, pub, st.TipSeq, st.TipHash, []proto.AuthMethod{{
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

	gen, oek, scopeID, err := BuildScopeGenesis(LocalSigner{Priv: priv}, pub)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, scopeID+".cbor")
	if err := AppendScope(p, gen); err != nil {
		t.Fatal(err)
	}
	st, err := ReplayScope(p, pub, xPub, LocalOpener{Pub: xPub, Priv: xPriv})
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
	ev, err := BuildSecretSet(LocalSigner{Priv: priv}, pub, scopeID, st.TipSeq, st.TipHash, oek, st.CurrentOEKVer, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendScope(p, ev); err != nil {
		t.Fatal(err)
	}
	st, err = ReplayScope(p, pub, xPub, LocalOpener{Pub: xPub, Priv: xPriv})
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

// TestLocalOnlyEvents verifies the pure set-diff used by sync's
// reconcile path. Identifies events present in the local chain but
// missing on the server, by content-addressed event_id (NOT by slice
// index — slice indexing breaks when one side is compacted).
func TestLocalOnlyEvents(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	signer := LocalSigner{Priv: priv}
	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub)
	if err != nil {
		t.Fatal(err)
	}
	// Compute genesis tip.
	genPrefix, _ := gen.PrevHashInput()
	genHash := proto.HashPrefix(genPrefix)

	// Build three secret.sets at successive seqs.
	mk := func(seq uint64, prevHash []byte, value string) *proto.ScopeEvent {
		body := &proto.SecretBody{
			ID: "s_" + value, Record: &proto.SecretRecord{Name: value, Type: "kv.string", SchemaVersion: 1, Payload: value, Tags: map[string]string{}},
		}
		ev, err := BuildSecretSet(signer, pub, scopeID, seq-1, prevHash, oek, 1, body)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	s1 := mk(1, genHash[:], "v1")
	s1Prefix, _ := s1.PrevHashInput()
	s1Hash := proto.HashPrefix(s1Prefix)
	s2 := mk(2, s1Hash[:], "v2")
	s2Prefix, _ := s2.PrevHashInput()
	s2Hash := proto.HashPrefix(s2Prefix)
	s3 := mk(3, s2Hash[:], "v3")

	// Server sees gen, s1, s2 only. Local sees all four.
	server := []proto.ScopeEvent{*gen, *s1, *s2}
	local := []proto.ScopeEvent{*gen, *s1, *s2, *s3}

	out := LocalOnlyEvents(local, server)
	if len(out) != 1 {
		t.Fatalf("want 1 local-only event, got %d", len(out))
	}
	got, _ := out[0].PrevHashInput()
	want, _ := s3.PrevHashInput()
	if proto.EventID(got) != proto.EventID(want) {
		t.Fatalf("local-only event mismatch")
	}
}

// TestLocalOnlyEventsCompactedLocal confirms the helper handles a
// compacted local chain (gaps in seq) — naive slice-index diffing
// would mis-pair events here.
func TestLocalOnlyEventsCompactedLocal(t *testing.T) {
	pub, priv, _ := crypto.GenerateIdentity()
	signer := LocalSigner{Priv: priv}
	gen, oek, scopeID, _ := BuildScopeGenesis(signer, pub)
	genPrefix, _ := gen.PrevHashInput()
	genHash := proto.HashPrefix(genPrefix)
	mk := func(seq uint64, prevHash []byte, name string) *proto.ScopeEvent {
		body := &proto.SecretBody{
			ID: "s_" + name, Record: &proto.SecretRecord{Name: name, Type: "kv.string", SchemaVersion: 1, Payload: name, Tags: map[string]string{}},
		}
		ev, _ := BuildSecretSet(signer, pub, scopeID, seq-1, prevHash, oek, 1, body)
		return ev
	}
	s1 := mk(1, genHash[:], "v1")
	s1Prefix, _ := s1.PrevHashInput()
	s1Hash := proto.HashPrefix(s1Prefix)
	s2 := mk(2, s1Hash[:], "v2")

	// Server has gen + s1 + s2 (full). Local has gen + s2 (compacted —
	// s1 was dropped to save space, only the latest secret remains).
	// LocalOnlyEvents must return [] — both events on local are also
	// on the server. A slice-index diff would have flagged s2 as
	// "local-only" because the indices don't line up.
	server := []proto.ScopeEvent{*gen, *s1, *s2}
	local := []proto.ScopeEvent{*gen, *s2}
	out := LocalOnlyEvents(local, server)
	if len(out) != 0 {
		t.Fatalf("compacted local with no real divergence: want 0 local-only, got %d", len(out))
	}
}

// TestLocalOnlyEventsPreservesOrder ensures the returned slice keeps
// local-side ordering — sync's reconcile rebuilds events in this
// order, so a shuffle would change the rebuilt seq sequence.
func TestLocalOnlyEventsPreservesOrder(t *testing.T) {
	mkEv := func(payloadID string) proto.ScopeEvent {
		// Use distinct PrevHash bytes per event so event_ids differ.
		return proto.ScopeEvent{
			SignedPrefix: proto.SignedPrefix{
				Kind:     proto.KindSecretSet,
				Scope:    proto.ScopePtr("s_test"),
				PrevHash: bytes.Repeat([]byte(payloadID), 16),
				Author:   bytes.Repeat([]byte{0xAA}, 32),
				Seq:      1,
				Payload:  proto.Payload{EncBody: bytes.Repeat([]byte(payloadID), 13)},
			},
		}
	}
	a, b, c := mkEv("A"), mkEv("B"), mkEv("C")
	local := []proto.ScopeEvent{a, b, c}
	server := []proto.ScopeEvent{} // none on server
	out := LocalOnlyEvents(local, server)
	if len(out) != 3 {
		t.Fatalf("expected 3 local-only events, got %d", len(out))
	}
	for i, want := range []proto.ScopeEvent{a, b, c} {
		gotPref, _ := out[i].PrevHashInput()
		wantPref, _ := want.PrevHashInput()
		if proto.EventID(gotPref) != proto.EventID(wantPref) {
			t.Fatalf("order mismatch at index %d", i)
		}
	}
}
