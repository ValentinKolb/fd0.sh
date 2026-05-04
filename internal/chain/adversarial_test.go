package chain

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Adversarial tests for chain.ReplayScope. Beyond the property
// tests, these construct SPECIFIC pathological chain files that
// correspond to real bug classes from the multi-module review.

// mkScope builds a fresh single-event scope chain on disk and
// returns (path, ownPub, opener) for replay/append testing.
func mkScopeAdv(t *testing.T) (path string, ownPub []byte, opener Opener) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, _ := crypto.GenerateIdentity()
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	xPriv, _ := crypto.EdPrivToX25519(priv.Bytes())
	signer := LocalSigner{Priv: priv}
	gen, _, scopeID, err := BuildScopeGenesis(signer, pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	return path, pub.Bytes(), LocalOpener{Pub: xPub, Priv: xPriv}
}

// TestAdvReplayRejectsNonMonotoneSeq locks the codex audit fix:
// any event with seq <= TipSeq MUST be rejected. The previous
// gap-tolerant code accepted seq == TipSeq (replay of the last
// event) and seq < TipSeq (replay of an older event), letting a
// tampered local file shuffle history while still ending at the
// vault-bound tip.
func TestAdvReplayRejectsNonMonotoneSeq(t *testing.T) {
	path, pub, opener := mkScopeAdv(t)
	lo := opener.(LocalOpener)

	// Read the genesis event back and append a copy of it (seq=0
	// again) — replay must reject.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayScope(path, pub, lo.Pub, opener); err == nil {
		t.Fatal("ReplayScope accepted duplicated genesis (seq=0 twice)")
	}
}

// TestAdvReplayRejectsScopeMismatch: a non-genesis event whose
// signed_prefix.scope is non-nil but != st.ScopeID MUST be
// rejected. Our spec embeds the scope id in every successor's
// signed prefix; without this check, an attacker could splice in
// a signed event from a different scope.
func TestAdvReplayRejectsScopeMismatch(t *testing.T) {
	// Build two scopes; mix events between them.
	dirA := t.TempDir()
	pubA, privA, _ := crypto.GenerateIdentity()
	xPubA, _ := crypto.EdPubToX25519(pubA.Bytes())
	xPrivA, _ := crypto.EdPrivToX25519(privA.Bytes())
	openerA := LocalOpener{Pub: xPubA, Priv: xPrivA}
	signerA := LocalSigner{Priv: privA}

	genA, oekA, scopeAID, _ := BuildScopeGenesis(signerA, pubA.Bytes())
	pathA := filepath.Join(dirA, scopeAID.String()+".cbor")
	_ = AppendScope(pathA, genA)

	// Build a secret.set under scope B (different ID), signed by
	// the same author. Then splice it into A's chain file.
	dirB := t.TempDir()
	genB, _, scopeBID, _ := BuildScopeGenesis(signerA, pubA.Bytes())
	pathB := filepath.Join(dirB, scopeBID.String()+".cbor")
	_ = AppendScope(pathB, genB)
	stB, _ := ReplayScope(pathB, pubA.Bytes(), xPubA, openerA)

	body := &proto.SecretBody{
		ID: "s_evil_id_aaa",
		Record: &proto.SecretRecord{
			Name: "evil", Type: "kv.string", SchemaVersion: 1,
			Payload: "x", Tags: map[string]string{},
		},
	}
	_ = oekA
	evB, err := BuildSecretSet(signerA, pubA.Bytes(), scopeBID, stB.TipSeq, stB.TipHash, stB.OEKs[stB.CurrentOEKVer], stB.CurrentOEKVer, body)
	if err != nil {
		t.Fatal(err)
	}
	// Splice evB onto chain A → replay must reject scope mismatch.
	if err := AppendScope(pathA, evB); err != nil {
		t.Fatal(err)
	}
	_, err = ReplayScope(pathA, pubA.Bytes(), xPubA, openerA)
	if err == nil {
		t.Fatal("ReplayScope accepted event from sibling scope spliced into chain")
	}
	// Codex test audit: pin the SPECIFIC rejection reason. The
	// spliced event has both wrong scope AND wrong prev_hash —
	// previously the test passed for either reason. We require
	// the scope-mismatch reason specifically because that's the
	// invariant under test.
	if !contains(err.Error(), "scope mismatch") {
		t.Fatalf("expected 'scope mismatch' rejection, got: %v", err)
	}
}

// TestAdvReplayRejectsTruncatedFile: a file truncated to a
// non-event boundary MUST error rather than panic or silently
// accept a truncated last event.
func TestAdvReplayRejectsTruncatedFile(t *testing.T) {
	path, pub, opener := mkScopeAdv(t)
	lo := opener.(LocalOpener)

	raw, _ := os.ReadFile(path)
	for _, n := range []int{1, 5, len(raw) - 1} {
		if n < 0 {
			continue
		}
		if err := os.WriteFile(path, raw[:n], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReplayScope(path, pub, lo.Pub, opener); err == nil {
			t.Errorf("truncated to %d bytes: ReplayScope succeeded", n)
		}
	}
}

// TestAdvReplayRejectsBitFlipInGenesisSig: any single-bit flip
// inside the signature region of the genesis event MUST be
// rejected. Same for any signature on any event.
func TestAdvReplayRejectsBitFlipInGenesisSig(t *testing.T) {
	path, pub, opener := mkScopeAdv(t)
	lo := opener.(LocalOpener)

	raw, _ := os.ReadFile(path)
	// Flip the last byte (signature). The signature is at the END of
	// the CBOR-encoded event (it's the last cbor field per layout).
	tampered := append([]byte(nil), raw...)
	tampered[len(tampered)-1] ^= 0x01
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayScope(path, pub, lo.Pub, opener); err == nil {
		t.Fatal("ReplayScope accepted bit-flipped signature")
	}
}

// TestAdvReplayRejectsForeignAuthor: a successor event whose
// author isn't in the member set MUST be rejected. Forge a
// secret.set signed by a NON-MEMBER and splice it into the chain;
// ReplayScope must reject ("author not in member set").
//
// Codex test audit 🔴: the previous version of this test never
// reached ReplayScope — it only logged whether BuildMemberChange
// rejected and returned. Now the test actually splices a forged
// event onto the chain and verifies ReplayScope is the gate.
func TestAdvReplayRejectsForeignAuthor(t *testing.T) {
	path, pubOwner, opener := mkScopeAdv(t)
	lo := opener.(LocalOpener)

	stOwner, err := ReplayScope(path, pubOwner, lo.Pub, opener)
	if err != nil {
		t.Fatal(err)
	}
	// We need access to the OEK to construct a valid-by-signature
	// secret.set under a foreign author. The owner's state has
	// it; we use it to sign a forged event.
	foreignPub, foreignPriv, _ := crypto.GenerateIdentity()
	signerForeign := LocalSigner{Priv: foreignPriv}

	body := &proto.SecretBody{
		ID: "s_foreign_event_aa",
		Record: &proto.SecretRecord{
			Name: "evil", Type: "kv.string", SchemaVersion: 1,
			Payload: "x", Tags: map[string]string{},
		},
	}
	// foreignPub signs but is NOT in MemberSet (only owner is).
	ev, err := BuildSecretSet(signerForeign, foreignPub.Bytes(),
		stOwner.ScopeID, stOwner.TipSeq, stOwner.TipHash,
		stOwner.OEKs[stOwner.CurrentOEKVer], stOwner.CurrentOEKVer, body)
	if err != nil {
		t.Fatalf("BuildSecretSet for foreign author: %v", err)
	}
	if err := AppendScope(path, ev); err != nil {
		t.Fatal(err)
	}
	// Replay MUST reject — author not in member set.
	_, err = ReplayScope(path, pubOwner, lo.Pub, opener)
	if err == nil {
		t.Fatal("ReplayScope accepted secret.set from non-member author")
	}
	// Specific reason: must mention "member set" or "author".
	msg := err.Error()
	if !contains(msg, "member set") && !contains(msg, "author") {
		t.Fatalf("ReplayScope rejected for unrelated reason: %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestAdvAppendRawAtomic: appending an event MUST be either
// fully present or absent in the file. (We don't have a public
// hook for partial-write injection, but this test verifies
// post-condition: file size grows by exactly the marshaled length
// after a successful AppendRaw.)
func TestAdvAppendRawAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.cbor")
	payload := bytes.Repeat([]byte{0xAB}, 100)
	if err := AppendRaw(path, payload); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != int64(len(payload)) {
		t.Fatalf("AppendRaw did not write exactly %d bytes (file is %d)", len(payload), st.Size())
	}
}

// (Stale-state CompactScope guard is covered directly by
// TestCompactScopeRefusesStaleSnapshot in chain_test.go. We don't
// re-test here — the codex test audit flagged the previous skip
// stub as zero-coverage inflation.)
