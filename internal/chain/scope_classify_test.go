package chain

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// scopeFixture builds a real, fully signed scope chain of 1 genesis + n
// secret.set events and returns the path plus the decoded events. Fixtures
// are real chains rather than hand-rolled structs so the classifier is
// exercised against exactly the bytes the client writes.
type scopeFixture struct {
	path    string
	events  []*proto.ScopeEvent
	tip     proto.ChainTip
	scopeID proto.ScopeID
}

func buildScopeFixture(t *testing.T, sets int) scopeFixture {
	t.Helper()
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	xPriv, _ := crypto.EdPrivToX25519(priv.Bytes())
	signer := LocalSigner{Priv: priv}
	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	opener := LocalOpener{Pub: xPub, Priv: xPriv}
	st, err := ReplayScope(path, pub.Bytes(), xPub, opener)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sets; i++ {
		ev, err := BuildSecretSet(signer, pub.Bytes(), scopeID, st.TipSeq, st.TipHash, oek, st.CurrentOEKVer,
			&proto.SecretBody{
				ID: "s_fixture",
				Record: &proto.SecretRecord{
					Name: "s_fixture", Type: "kv.string", SchemaVersion: 1,
					Payload: "v", Tags: map[string]string{},
				},
			})
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
	events, err := ReadScopeEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	return scopeFixture{
		path:    path,
		events:  events,
		tip:     proto.ChainTip{Seq: st.TipSeq, Hash: append([]byte(nil), st.TipHash...)},
		scopeID: scopeID,
	}
}

func rewriteScope(t *testing.T, path string, events []*proto.ScopeEvent) {
	t.Helper()
	raws := make([][]byte, 0, len(events))
	for _, ev := range events {
		raw, err := proto.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	if err := WriteAll(path, raws); err != nil {
		t.Fatal(err)
	}
}

func classify(t *testing.T, path string) ScopeChainClassification {
	t.Helper()
	got, err := ClassifyScopeChain(path)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	return got
}

func TestClassifyScopeChainContiguous(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	got := classify(t, fx.path)
	if got.Shape != ScopeShapeContiguous {
		t.Fatalf("shape = %q (%s), want contiguous", got.Shape, got.Reason)
	}
	if got.Events != 5 {
		t.Fatalf("events = %d, want 5", got.Events)
	}
	if got.Tip.Seq != fx.tip.Seq || !bytes.Equal(got.Tip.Hash, fx.tip.Hash) {
		t.Fatalf("tip = %d/%x, want %d/%x", got.Tip.Seq, got.Tip.Hash, fx.tip.Seq, fx.tip.Hash)
	}
}

// A single-event chain is a freshly created scope: genesis and nothing else.
// It is contiguous by definition and must never be mistaken for a compacted
// window (a migration there would have nothing to bridge).
func TestClassifyScopeChainSingleEvent(t *testing.T) {
	fx := buildScopeFixture(t, 0)
	got := classify(t, fx.path)
	if got.Shape != ScopeShapeContiguous {
		t.Fatalf("shape = %q (%s), want contiguous", got.Shape, got.Reason)
	}
	if got.Events != 1 || !got.HasTip || got.Tip.Seq != 0 {
		t.Fatalf("unexpected classification %+v", got)
	}
}

func TestClassifyScopeChainEmpty(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "s_missing.cbor")
	got := classify(t, missing)
	if got.Shape != ScopeShapeEmpty || got.HasTip {
		t.Fatalf("missing file: %+v, want empty", got)
	}
	blank := filepath.Join(dir, "s_blank.cbor")
	if err := os.WriteFile(blank, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := classify(t, blank); got.Shape != ScopeShapeEmpty {
		t.Fatalf("zero-byte file: %+v, want empty", got)
	}
}

// The retired v1 compactor's exact output: genesis kept verbatim, a recent
// window kept verbatim, everything between deleted.
func TestClassifyScopeChainLegacyCompacted(t *testing.T) {
	fx := buildScopeFixture(t, 6)
	kept := append([]*proto.ScopeEvent{fx.events[0]}, fx.events[len(fx.events)-2:]...)
	rewriteScope(t, fx.path, kept)

	got := classify(t, fx.path)
	if got.Shape != ScopeShapeLegacyCompacted {
		t.Fatalf("shape = %q (%s), want legacy-compacted", got.Shape, got.Reason)
	}
	if got.RetainedFrom != kept[1].SignedPrefix.Seq {
		t.Fatalf("RetainedFrom = %d, want %d", got.RetainedFrom, kept[1].SignedPrefix.Seq)
	}
	// The tip the compactor left behind is still the real final tip — which
	// is exactly why the vault binding is a usable anchor for migration.
	if got.Tip.Seq != fx.tip.Seq || !bytes.Equal(got.Tip.Hash, fx.tip.Hash) {
		t.Fatalf("compaction changed the committed tip: %+v", got.Tip)
	}
	// Compacting again narrows the window without changing the shape.
	rewriteScope(t, fx.path, []*proto.ScopeEvent{kept[0], kept[len(kept)-1]})
	if again := classify(t, fx.path); again.Shape != ScopeShapeLegacyCompacted {
		t.Fatalf("re-compacted shape = %q (%s), want legacy-compacted", again.Shape, again.Reason)
	}
}

// The vault binding is not an input to classification: a chain can be
// perfectly well-formed and still disagree with the tip the vault sealed.
// The classifier reports the shape AND the tip; deciding what the mismatch
// means is the migration's job, not the classifier's.
func TestClassifyScopeChainTipDisagreesWithVaultBinding(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	vaultTip := proto.ChainTip{Seq: fx.tip.Seq, Hash: bytes.Repeat([]byte{0x5A}, 32)}

	got := classify(t, fx.path)
	if got.Shape != ScopeShapeContiguous {
		t.Fatalf("shape = %q (%s), want contiguous", got.Shape, got.Reason)
	}
	if bytes.Equal(got.Tip.Hash, vaultTip.Hash) {
		t.Fatal("fixture accidentally matches the bogus vault tip")
	}

	// Same for a legacy-compacted file whose tip no longer matches.
	kept := append([]*proto.ScopeEvent{fx.events[0]}, fx.events[len(fx.events)-2:]...)
	rewriteScope(t, fx.path, kept)
	legacy := classify(t, fx.path)
	if legacy.Shape != ScopeShapeLegacyCompacted {
		t.Fatalf("shape = %q (%s), want legacy-compacted", legacy.Shape, legacy.Reason)
	}
	if bytes.Equal(legacy.Tip.Hash, vaultTip.Hash) {
		t.Fatal("fixture accidentally matches the bogus vault tip")
	}
}

// A file truncated from the front has no genesis. The scope id is derived
// from genesis, so nothing local anchors the history — never migratable.
func TestClassifyScopeChainTruncatedFront(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	rewriteScope(t, fx.path, fx.events[1:])
	got := classify(t, fx.path)
	if got.Shape != ScopeShapeMalformed {
		t.Fatalf("shape = %q, want malformed", got.Shape)
	}
	if got.Reason == "" {
		t.Fatal("malformed verdict without a reason")
	}
}

// A file truncated at the tail is still contiguous — it is a rollback, which
// the vault tip binding catches (chain.ErrRollback), not a compaction.
func TestClassifyScopeChainTruncatedTailIsContiguous(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	rewriteScope(t, fx.path, fx.events[:3])
	got := classify(t, fx.path)
	if got.Shape != ScopeShapeContiguous {
		t.Fatalf("shape = %q (%s), want contiguous", got.Shape, got.Reason)
	}
	if got.Tip.Seq != 2 {
		t.Fatalf("tip seq = %d, want 2", got.Tip.Seq)
	}
}

func TestClassifyScopeChainReordered(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	shuffled := []*proto.ScopeEvent{fx.events[0], fx.events[2], fx.events[1], fx.events[3], fx.events[4]}
	rewriteScope(t, fx.path, shuffled)
	got := classify(t, fx.path)
	if got.Shape != ScopeShapeMalformed {
		t.Fatalf("shape = %q, want malformed", got.Shape)
	}
	if got.Reason == "" {
		t.Fatal("malformed verdict without a reason")
	}
}

func TestClassifyScopeChainDuplicatedEvent(t *testing.T) {
	fx := buildScopeFixture(t, 3)
	dup := []*proto.ScopeEvent{fx.events[0], fx.events[1], fx.events[1], fx.events[2], fx.events[3]}
	rewriteScope(t, fx.path, dup)
	if got := classify(t, fx.path); got.Shape != ScopeShapeMalformed {
		t.Fatalf("shape = %q, want malformed", got.Shape)
	}
}

// A gap away from genesis is still compaction. An earlier rule required the
// single cut to sit immediately after genesis, which described one compactor
// run rather than its cumulative effect and refused every real vault.
func TestClassifyScopeChainMidHistoryGapIsLegacy(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	kept := []*proto.ScopeEvent{fx.events[0], fx.events[1], fx.events[2], fx.events[4]}
	rewriteScope(t, fx.path, kept)
	got := classify(t, fx.path)
	if got.Shape != ScopeShapeLegacyCompacted {
		t.Fatalf("shape = %q, want legacy-compacted", got.Shape)
	}
	if got.Gaps != 1 {
		t.Fatalf("gaps = %d, want 1", got.Gaps)
	}
}

// Repeated compaction leaves several windows and therefore several gaps. This
// is the shape measured on a production vault (27 retained events, 5 gaps,
// tip 1372), so recognising it is the whole point of the classifier.
//
// Accepting it is safe because classification only decides whether to ATTEMPT
// a migration: the refetched history still has to verify against the
// transparency log and replay to the tip sealed in the vault, which an
// attacker who drops events cannot move.
func TestClassifyScopeChainMultipleGapsIsLegacy(t *testing.T) {
	fx := buildScopeFixture(t, 6)
	kept := []*proto.ScopeEvent{fx.events[0], fx.events[2], fx.events[4], fx.events[6]}
	rewriteScope(t, fx.path, kept)
	got := classify(t, fx.path)
	if got.Shape != ScopeShapeLegacyCompacted {
		t.Fatalf("shape = %q, want legacy-compacted", got.Shape)
	}
	if got.Gaps != 3 {
		t.Fatalf("gaps = %d, want 3", got.Gaps)
	}
	// The oldest retained window is what a migration has to bridge back to.
	if got.RetainedFrom != fx.events[2].SignedPrefix.Seq {
		t.Fatalf("retainedFrom = %d, want %d", got.RetainedFrom, fx.events[2].SignedPrefix.Seq)
	}
}

// Seq advances by one but the hash link is broken: an event was substituted,
// not dropped. Re-fetching would paper over tampering.
func TestClassifyScopeChainBrokenLinkWithoutGap(t *testing.T) {
	fx := buildScopeFixture(t, 3)
	tampered := *fx.events[2]
	tampered.SignedPrefix.PrevHash = bytes.Repeat([]byte{0x11}, 32)
	rewriteScope(t, fx.path, []*proto.ScopeEvent{fx.events[0], fx.events[1], &tampered, fx.events[3]})
	got := classify(t, fx.path)
	if got.Shape != ScopeShapeMalformed {
		t.Fatalf("shape = %q, want malformed", got.Shape)
	}
}

// A forward jump with no prev_hash link at all is not a compaction either.
func TestClassifyScopeChainGapWithoutLink(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	stripped := *fx.events[3]
	stripped.SignedPrefix.PrevHash = nil
	rewriteScope(t, fx.path, []*proto.ScopeEvent{fx.events[0], &stripped, fx.events[4]})
	if got := classify(t, fx.path); got.Shape != ScopeShapeMalformed {
		t.Fatalf("shape = %q, want malformed", got.Shape)
	}
}

// ClassifyScopeChain must never rewrite what it inspects.
func TestClassifyScopeChainDoesNotMutate(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	kept := append([]*proto.ScopeEvent{fx.events[0]}, fx.events[3:]...)
	rewriteScope(t, fx.path, kept)
	before, err := os.ReadFile(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if got := classify(t, fx.path); got.Shape != ScopeShapeLegacyCompacted {
			t.Fatalf("shape = %q, want legacy-compacted", got.Shape)
		}
	}
	after, err := os.ReadFile(fx.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("classification modified the chain file")
	}
}

// ValidateScopeEventContinuity must agree with the on-disk validator.
func TestValidateScopeEventContinuityMatchesFileValidator(t *testing.T) {
	fx := buildScopeFixture(t, 4)
	values := make([]proto.ScopeEvent, len(fx.events))
	for i, ev := range fx.events {
		values[i] = *ev
	}
	if err := ValidateScopeEventContinuity(values); err != nil {
		t.Fatalf("contiguous history rejected: %v", err)
	}
	if err := ValidateScopeContinuity(fx.path); err != nil {
		t.Fatalf("file validator disagreed: %v", err)
	}
	gapped := append([]proto.ScopeEvent{values[0]}, values[2:]...)
	if err := ValidateScopeEventContinuity(gapped); err == nil {
		t.Fatal("gapped candidate accepted")
	}
}
