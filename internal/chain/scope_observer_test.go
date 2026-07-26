package chain

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// observedVersion is what the tests record per observer callback.
type observedVersion struct {
	id string
	v  SecretVersion
}

func collectVersions(out *[]observedVersion) SecretObserver {
	return func(secretID string, v SecretVersion) {
		*out = append(*out, observedVersion{id: secretID, v: v})
	}
}

// TestReplayScopeObservedYieldsEverySecretSetInOrder covers the base case:
// a chain of secret.set events must be reported once each, in chain order,
// with the payload of that version (not the final one).
func TestReplayScopeObservedYieldsEverySecretSetInOrder(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	xPriv, _ := crypto.EdPrivToX25519(priv.Bytes())
	signer := LocalSigner{Priv: priv}
	opener := LocalOpener{Pub: xPub, Priv: xPriv}

	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	st, err := ReplayScope(path, pub.Bytes(), xPub, opener)
	if err != nil {
		t.Fatal(err)
	}
	appendSet := func(id, name, payload string) {
		t.Helper()
		var record *proto.SecretRecord
		if payload != "" {
			record = &proto.SecretRecord{
				Name: name, Type: "kv.string", SchemaVersion: 1,
				Payload: payload, Tags: map[string]string{},
			}
		}
		ev, err := BuildSecretSet(signer, pub.Bytes(), scopeID, st.TipSeq, st.TipHash,
			oek, st.CurrentOEKVer, &proto.SecretBody{ID: id, Record: record})
		if err != nil {
			t.Fatal(err)
		}
		if err := AppendScope(path, ev); err != nil {
			t.Fatal(err)
		}
		st, err = ReplayScope(path, pub.Bytes(), xPub, opener)
		if err != nil {
			t.Fatal(err)
		}
	}
	appendSet("s_alpha", "ALPHA", "v1")
	appendSet("s_beta", "BETA", "b1")
	appendSet("s_alpha", "ALPHA", "v2")
	appendSet("s_alpha", "ALPHA", "") // tombstone

	var seen []observedVersion
	observedState, err := ReplayScopeObserved(path, pub.Bytes(), xPub, opener, collectVersions(&seen))
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 4 {
		t.Fatalf("observed %d versions, want 4: %+v", len(seen), seen)
	}
	want := []struct {
		id      string
		seq     uint64
		payload any
	}{
		{"s_alpha", 1, "v1"},
		{"s_beta", 2, "b1"},
		{"s_alpha", 3, "v2"},
		{"s_alpha", 4, nil},
	}
	for i, expected := range want {
		got := seen[i]
		if got.id != expected.id || got.v.Seq != expected.seq {
			t.Fatalf("version %d: id=%q seq=%d, want id=%q seq=%d", i, got.id, got.v.Seq, expected.id, expected.seq)
		}
		if expected.payload == nil {
			if got.v.Record != nil {
				t.Fatalf("version %d: expected tombstone, got %+v", i, got.v.Record)
			}
			continue
		}
		if got.v.Record == nil || got.v.Record.Payload != expected.payload {
			t.Fatalf("version %d: record=%+v, want payload %v", i, got.v.Record, expected.payload)
		}
		if !bytes.Equal(got.v.Author, pub.Bytes()) {
			t.Fatalf("version %d: author mismatch", i)
		}
		if got.v.EventID == "" {
			t.Fatalf("version %d: missing event id", i)
		}
	}
	// The observer must not change the state the plain replay produces.
	plainState, err := ReplayScope(path, pub.Bytes(), xPub, opener)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateEquivalent(observedState, plainState); err != nil {
		t.Fatalf("observed replay diverged from plain replay: %v", err)
	}
}

// TestReplayScopeObservedIgnoresProjectionRebuild pins the rule that a
// member.change re-encrypts existing records under a new OEK but is NOT a
// user edit: it must not add history entries. Without this, adding one
// member would fabricate a "version" for every secret in the vault.
func TestReplayScopeObservedIgnoresProjectionRebuild(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	xPriv, _ := crypto.EdPrivToX25519(priv.Bytes())
	signer := LocalSigner{Priv: priv}
	opener := LocalOpener{Pub: xPub, Priv: xPriv}

	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	st, err := ReplayScope(path, pub.Bytes(), xPub, opener)
	if err != nil {
		t.Fatal(err)
	}
	set, err := BuildSecretSet(signer, pub.Bytes(), scopeID, st.TipSeq, st.TipHash, oek, st.CurrentOEKVer,
		&proto.SecretBody{ID: "s_alpha", Record: &proto.SecretRecord{
			Name: "ALPHA", Type: "kv.string", SchemaVersion: 1, Payload: "v1", Tags: map[string]string{},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendScope(path, set); err != nil {
		t.Fatal(err)
	}
	st, err = ReplayScope(path, pub.Bytes(), xPub, opener)
	if err != nil {
		t.Fatal(err)
	}
	// Adding a member rebuilds SecretIndex wholesale from the projection.
	add, _, err := BuildMemberChange(signer, pub.Bytes(), scopeID, st.TipSeq, st.TipHash,
		st.CurrentOEKVer, proto.OpAdd, other.Bytes(), st.MemberSet, buildProjection(st))
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendScope(path, add); err != nil {
		t.Fatal(err)
	}

	var seen []observedVersion
	st, err = ReplayScopeObserved(path, pub.Bytes(), xPub, opener, collectVersions(&seen))
	if err != nil {
		t.Fatal(err)
	}
	if st.SecretIndex["s_alpha"].Record == nil {
		t.Fatal("projection rebuild lost the record — fixture is wrong")
	}
	if len(seen) != 1 {
		t.Fatalf("observed %d versions, want exactly the one secret.set: %+v", len(seen), seen)
	}
	if seen[0].id != "s_alpha" || seen[0].v.Seq != 1 {
		t.Fatalf("unexpected version: %+v", seen[0])
	}
}

// TestReplayScopeObservedSkipsPreAdmitVersions checks the discovery case: a
// member who joins later replays events from an OEK era they never held.
// applySecretSet skips those, and the observer must skip them identically —
// a version we cannot decrypt must never surface as a phantom entry.
func TestReplayScopeObservedSkipsPreAdmitVersions(t *testing.T) {
	ownerPub, ownerPriv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	joinerPub, joinerPriv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerXPub, _ := crypto.EdPubToX25519(ownerPub.Bytes())
	ownerXPriv, _ := crypto.EdPrivToX25519(ownerPriv.Bytes())
	joinerXPub, _ := crypto.EdPubToX25519(joinerPub.Bytes())
	joinerXPriv, _ := crypto.EdPrivToX25519(joinerPriv.Bytes())
	signer := LocalSigner{Priv: ownerPriv}
	ownerOpener := LocalOpener{Pub: ownerXPub, Priv: ownerXPriv}
	joinerOpener := LocalOpener{Pub: joinerXPub, Priv: joinerXPriv}

	gen, oek, scopeID, err := BuildScopeGenesis(signer, ownerPub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	st, err := ReplayScope(path, ownerPub.Bytes(), ownerXPub, ownerOpener)
	if err != nil {
		t.Fatal(err)
	}
	// Two secret.sets in the owner-only OEK era — invisible to the joiner.
	for _, payload := range []string{"pre-1", "pre-2"} {
		ev, err := BuildSecretSet(signer, ownerPub.Bytes(), scopeID, st.TipSeq, st.TipHash, oek, st.CurrentOEKVer,
			&proto.SecretBody{ID: "s_alpha", Record: &proto.SecretRecord{
				Name: "ALPHA", Type: "kv.string", SchemaVersion: 1, Payload: payload, Tags: map[string]string{},
			}})
		if err != nil {
			t.Fatal(err)
		}
		if err := AppendScope(path, ev); err != nil {
			t.Fatal(err)
		}
		st, err = ReplayScope(path, ownerPub.Bytes(), ownerXPub, ownerOpener)
		if err != nil {
			t.Fatal(err)
		}
	}
	add, newOEK, err := BuildMemberChange(signer, ownerPub.Bytes(), scopeID, st.TipSeq, st.TipHash,
		st.CurrentOEKVer, proto.OpAdd, joinerPub.Bytes(), st.MemberSet, buildProjection(st))
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendScope(path, add); err != nil {
		t.Fatal(err)
	}
	st, err = ReplayScope(path, ownerPub.Bytes(), ownerXPub, ownerOpener)
	if err != nil {
		t.Fatal(err)
	}
	// One post-admit write, which the joiner CAN decrypt.
	post, err := BuildSecretSet(signer, ownerPub.Bytes(), scopeID, st.TipSeq, st.TipHash, newOEK, st.CurrentOEKVer,
		&proto.SecretBody{ID: "s_alpha", Record: &proto.SecretRecord{
			Name: "ALPHA", Type: "kv.string", SchemaVersion: 1, Payload: "post-1", Tags: map[string]string{},
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendScope(path, post); err != nil {
		t.Fatal(err)
	}

	var joinerSeen []observedVersion
	if _, err := ReplayScopeObserved(path, joinerPub.Bytes(), joinerXPub, joinerOpener, collectVersions(&joinerSeen)); err != nil {
		t.Fatal(err)
	}
	if len(joinerSeen) != 1 {
		t.Fatalf("joiner observed %d versions, want only the post-admit one: %+v", len(joinerSeen), joinerSeen)
	}
	if joinerSeen[0].v.Record == nil || joinerSeen[0].v.Record.Payload != "post-1" {
		t.Fatalf("joiner observed the wrong version: %+v", joinerSeen[0].v.Record)
	}
	// The owner, who holds every OEK era, still sees all three.
	var ownerSeen []observedVersion
	if _, err := ReplayScopeObserved(path, ownerPub.Bytes(), ownerXPub, ownerOpener, collectVersions(&ownerSeen)); err != nil {
		t.Fatal(err)
	}
	if len(ownerSeen) != 3 {
		t.Fatalf("owner observed %d versions, want 3: %+v", len(ownerSeen), ownerSeen)
	}
}

// TestReplayScopeObservedRecordsSurviveBufferWipe guards the aliasing hazard
// applyMemberChange already documents: replay wipes each event's plaintext
// buffer, so a record handed to an observer must be an independent copy.
func TestReplayScopeObservedRecordsSurviveBufferWipe(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	xPriv, _ := crypto.EdPrivToX25519(priv.Bytes())
	signer := LocalSigner{Priv: priv}
	opener := LocalOpener{Pub: xPub, Priv: xPriv}

	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	st, err := ReplayScope(path, pub.Bytes(), xPub, opener)
	if err != nil {
		t.Fatal(err)
	}
	for i, payload := range []string{"first-payload-value", "second-payload-value"} {
		ev, err := BuildSecretSet(signer, pub.Bytes(), scopeID, st.TipSeq, st.TipHash, oek, st.CurrentOEKVer,
			&proto.SecretBody{ID: "s_alpha", Record: &proto.SecretRecord{
				Name: "ALPHA", Type: "kv.string", SchemaVersion: 1, Payload: payload, Tags: map[string]string{},
			}})
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		if err := AppendScope(path, ev); err != nil {
			t.Fatal(err)
		}
		st, err = ReplayScope(path, pub.Bytes(), xPub, opener)
		if err != nil {
			t.Fatal(err)
		}
	}
	var seen []observedVersion
	if _, err := ReplayScopeObserved(path, pub.Bytes(), xPub, opener, collectVersions(&seen)); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("observed %d versions, want 2", len(seen))
	}
	// Read the FIRST version after replay finished and wiped its buffer.
	if seen[0].v.Record.Payload != "first-payload-value" {
		t.Fatalf("first version was corrupted after replay: %+v", seen[0].v.Record)
	}
	if seen[1].v.Record.Payload != "second-payload-value" {
		t.Fatalf("second version was corrupted after replay: %+v", seen[1].v.Record)
	}
}
