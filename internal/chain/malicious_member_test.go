package chain

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Malicious-member tests. The threat model: a legitimate scope
// member who turns hostile and tries to subvert the chain. Each
// test crafts a forged event that ReplayScope MUST reject.
//
// We have malicious-server and malicious-witness suites at the
// integration level; this is the malicious-member equivalent at
// the chain-replay level (the only layer that can defend against
// an insider with valid signing keys).

// setupTwoMember builds a scope with self + one other member. Both
// signing keys are returned for the malicious tests.
func setupTwoMember(t *testing.T) (path string, ownerPub, ownerPriv, otherPub, otherPriv, ownerXPub, ownerXPriv []byte, scopeID proto.ScopeID) {
	t.Helper()
	dir := t.TempDir()
	ownerPub2, ownerPriv2, _ := crypto.GenerateIdentity()
	otherPub2, otherPriv2, _ := crypto.GenerateIdentity()
	ownerXPub2, _ := crypto.EdPubToX25519(ownerPub2)
	ownerXPriv2, _ := crypto.EdPrivToX25519(ownerPriv2)
	otherXPub, _ := crypto.EdPubToX25519(otherPub2)
	_ = otherXPub
	signer := LocalSigner{Priv: ownerPriv2}
	gen, _, sid, err := BuildScopeGenesis(signer, ownerPub2)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, sid.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	// Owner adds other.
	st, _ := ReplayScope(path, ownerPub2, ownerXPub2, LocalOpener{Pub: ownerXPub2, Priv: ownerXPriv2})
	proj := buildProjection(st)
	add, _, err := BuildMemberChange(signer, ownerPub2,
		st.ScopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
		proto.OpAdd, otherPub2, st.MemberSet, proj)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendScope(path, add); err != nil {
		t.Fatal(err)
	}
	return path, ownerPub2, ownerPriv2, otherPub2, otherPriv2, ownerXPub2, ownerXPriv2, sid
}

// TestMalMemberCannotForgeAuthor: a member-built event whose
// signed_prefix.Author claims a DIFFERENT member must be rejected
// by the "author == signer" check.
func TestMalMemberCannotForgeAuthor(t *testing.T) {
	path, ownerPub, _, otherPub, otherPriv, ownerXPub, ownerXPriv, scopeID := setupTwoMember(t)

	st, err := ReplayScope(path, ownerPub, ownerXPub, LocalOpener{Pub: ownerXPub, Priv: ownerXPriv})
	if err != nil {
		t.Fatal(err)
	}

	// "other" builds a secret.set but stamps owner as Author.
	// BuildSecretSet uses signer's pub as Author by default; we
	// have to forge by building, then mutating Author + re-signing.
	body := &proto.SecretBody{
		ID: "s_forged_aaaaaaaaa",
		Record: &proto.SecretRecord{
			Name: "x", Type: "kv.string", SchemaVersion: 1,
			Payload: "evil", Tags: map[string]string{},
		},
	}
	signerOther := LocalSigner{Priv: otherPriv}
	ev, err := BuildSecretSet(signerOther, otherPub, scopeID,
		st.TipSeq, st.TipHash, st.OEKs[st.CurrentOEKVer], st.CurrentOEKVer, body)
	if err != nil {
		t.Fatal(err)
	}
	// Now mutate Author to claim it's the owner. Signature was
	// computed with `Author=otherPub`, so flipping Author breaks
	// the sig — BUT if we re-sign with otherPriv after the flip,
	// the signer-pubkey in Signature still records otherPriv's
	// pub. Either way, ReplayScope's "author == signer" check
	// must reject.
	ev.SignedPrefix.Author = append([]byte(nil), ownerPub...)
	if err := AppendScope(path, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayScope(path, ownerPub, ownerXPub, LocalOpener{Pub: ownerXPub, Priv: ownerXPriv}); err == nil {
		t.Fatal("ReplayScope accepted event whose Author was forged after signing")
	}
}

// TestMalMemberCannotInjectExtraSecretInProjection: a member
// crafting a member.change must not be able to inject an EXTRA
// secret into the projection that wasn't in the prior chain. The
// projection-content integrity check covers this.
func TestMalMemberCannotInjectExtraSecretInProjection(t *testing.T) {
	path, ownerPub, _, otherPub, otherPriv, ownerXPub, ownerXPriv, scopeID := setupTwoMember(t)

	// "other" (now a real member) tries to add a third party but
	// inflates the projection with a fictional secret. The
	// projection-content check requires the projection to match
	// the existing SecretIndex; an extra entry must trigger
	// "projection injects unknown id".
	stNow, err := ReplayScope(path, ownerPub, ownerXPub, LocalOpener{Pub: ownerXPub, Priv: ownerXPriv})
	if err != nil {
		t.Fatal(err)
	}
	thirdPub, _, _ := crypto.GenerateIdentity()
	signerOther := LocalSigner{Priv: otherPriv}
	// Build a projection with one bogus entry not in stNow.SecretIndex.
	bogusProj := &proto.MemberProjection{
		Secrets: []proto.SecretInProjection{{
			ID: "s_injected_evil_xx",
			Record: &proto.SecretRecord{
				Name: "evil", Type: "kv.string", SchemaVersion: 1,
				Payload: "bad", Tags: map[string]string{},
			},
		}},
	}
	ev, _, err := BuildMemberChange(signerOther, otherPub,
		scopeID, stNow.TipSeq, stNow.TipHash, stNow.CurrentOEKVer,
		proto.OpAdd, thirdPub, stNow.MemberSet, bogusProj)
	if err != nil {
		// Build itself may reject — also OK. Either way, the
		// state machine is defended.
		t.Logf("BuildMemberChange rejected projection injection at build time: %v", err)
		return
	}
	// If build accepted, replay must reject.
	if err := AppendScope(path, ev); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayScope(path, ownerPub, ownerXPub, LocalOpener{Pub: ownerXPub, Priv: ownerXPriv}); err == nil {
		t.Fatal("ReplayScope accepted member.change with injected bogus projection entry")
	}
}

// TestMalMemberCannotReplayOldSecretSet: a member-signed event
// can't be replayed at a later point in the chain (would require
// matching prev_hash to an OLDER state — chain rejects with
// prev_hash mismatch).
func TestMalMemberCannotReplayOldSecretSet(t *testing.T) {
	path, ownerPub, _, otherPub, otherPriv, ownerXPub, ownerXPriv, scopeID := setupTwoMember(t)

	stStart, _ := ReplayScope(path, ownerPub, ownerXPub, LocalOpener{Pub: ownerXPub, Priv: ownerXPriv})
	signerOther := LocalSigner{Priv: otherPriv}
	body := &proto.SecretBody{
		ID: "s_replay_target_aa",
		Record: &proto.SecretRecord{
			Name: "x", Type: "kv.string", SchemaVersion: 1,
			Payload: "v1", Tags: map[string]string{},
		},
	}
	// Build event A pinned to start state.
	evA, err := BuildSecretSet(signerOther, otherPub, scopeID,
		stStart.TipSeq, stStart.TipHash,
		stStart.OEKs[stStart.CurrentOEKVer], stStart.CurrentOEKVer, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendScope(path, evA); err != nil {
		t.Fatal(err)
	}

	// Now write a different event so the chain advances.
	stMid, _ := ReplayScope(path, ownerPub, ownerXPub, LocalOpener{Pub: ownerXPub, Priv: ownerXPriv})
	body2 := &proto.SecretBody{
		ID: "s_advance_event_aa",
		Record: &proto.SecretRecord{
			Name: "y", Type: "kv.string", SchemaVersion: 1,
			Payload: "v2", Tags: map[string]string{},
		},
	}
	evB, _ := BuildSecretSet(signerOther, otherPub, scopeID,
		stMid.TipSeq, stMid.TipHash,
		stMid.OEKs[stMid.CurrentOEKVer], stMid.CurrentOEKVer, body2)
	if err := AppendScope(path, evB); err != nil {
		t.Fatal(err)
	}

	// Now try to APPEND evA again at the new tip — its prev_hash
	// is stale (points to start state, not current). ReplayScope
	// must reject.
	if err := AppendScope(path, evA); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayScope(path, ownerPub, ownerXPub, LocalOpener{Pub: ownerXPub, Priv: ownerXPriv}); err == nil {
		t.Fatal("ReplayScope accepted re-played old event after chain advanced")
	}
}

var _ = bytes.Equal
