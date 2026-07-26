package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// legacyFixture is a real, fully signed scope chain plus the Session state a
// migration reads: the sealed vault tip, the local (compacted) chain file,
// and the full history a server would return.
type legacyFixture struct {
	session   *Session
	scopeID   string
	scope     proto.ScopeID
	path      string
	opener    chain.Opener
	signer    chain.Signer
	superPub  []byte
	oek       []byte
	fullChain []proto.ScopeEvent // genesis + every secret.set, contiguous
	vaultTip  proto.ChainTip     // the tip sealed BEFORE compaction
	vaultFile string
}

// forkAt returns a history that shares fullChain[:at] and then diverges: the
// same author, the same scope, valid signatures and hash links throughout —
// only the contents differ. This is what a hostile or buggy server would have
// to produce to slip a different history past the migration, and it is the
// case the vault tip anchor exists to catch.
func (f *legacyFixture) forkAt(t *testing.T, at int) []proto.ScopeEvent {
	t.Helper()
	forked := append([]proto.ScopeEvent(nil), f.fullChain[:at]...)
	prev := forked[len(forked)-1]
	prefix, err := prev.PrevHashInput()
	if err != nil {
		t.Fatal(err)
	}
	hash := proto.HashPrefix(prefix)
	tipSeq, tipHash := prev.SignedPrefix.Seq, hash[:]
	for i := at; i < len(f.fullChain); i++ {
		ev, err := chain.BuildSecretSet(f.signer, f.superPub, f.scope, tipSeq, tipHash, f.oek, 1,
			&proto.SecretBody{
				ID: "s_fixture",
				Record: &proto.SecretRecord{
					Name: "s_fixture", Type: "kv.string", SchemaVersion: 1,
					Payload: "forked", Tags: map[string]string{},
				},
			})
		if err != nil {
			t.Fatal(err)
		}
		forked = append(forked, *ev)
		nextPrefix, err := ev.PrevHashInput()
		if err != nil {
			t.Fatal(err)
		}
		nextHash := proto.HashPrefix(nextPrefix)
		tipSeq, tipHash = ev.SignedPrefix.Seq, nextHash[:]
	}
	return forked
}

func newLegacyFixture(t *testing.T, sets int) *legacyFixture {
	t.Helper()
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	xPriv, _ := crypto.EdPrivToX25519(priv.Bytes())
	opener := chain.LocalOpener{Pub: xPub, Priv: xPriv}
	signer := chain.LocalSigner{Priv: priv}

	home := t.TempDir()
	paths := fdhome.Paths{
		Home:      home,
		Vault:     filepath.Join(home, "vault.enc"),
		Config:    filepath.Join(home, "config.toml"),
		Chains:    filepath.Join(home, "chains"),
		UserChain: filepath.Join(home, "chains", "user.cbor"),
	}
	if err := os.MkdirAll(paths.Chains, 0o700); err != nil {
		t.Fatal(err)
	}
	// A stand-in vault file so a test can assert byte-identity. The
	// migration must never touch it.
	if err := os.WriteFile(paths.Vault, []byte("sealed-vault-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	gen, oek, scopeID, err := chain.BuildScopeGenesis(signer, pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	path := paths.ScopeChain(scopeID)
	if err := chain.AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	st, err := chain.ReplayScope(path, pub.Bytes(), xPub, opener)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sets; i++ {
		ev, err := chain.BuildSecretSet(signer, pub.Bytes(), scopeID, st.TipSeq, st.TipHash, oek, st.CurrentOEKVer,
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
		if err := chain.AppendScope(path, ev); err != nil {
			t.Fatal(err)
		}
		if st, err = chain.ReplayScope(path, pub.Bytes(), xPub, opener); err != nil {
			t.Fatal(err)
		}
	}
	ptrs, err := chain.ReadScopeEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	full := make([]proto.ScopeEvent, len(ptrs))
	for i, ev := range ptrs {
		full[i] = *ev
	}
	vaultTip := proto.ChainTip{Seq: st.TipSeq, Hash: append([]byte(nil), st.TipHash...)}

	session := &Session{
		Paths:         paths,
		UserSuperPub:  pub.Bytes(),
		UserX25519Pub: xPub,
		Body: &proto.VaultBody{
			Scopes: map[string]proto.ScopeVaultData{
				scopeID.String(): {ChainTip: vaultTip},
			},
		},
	}
	return &legacyFixture{
		session:   session,
		scopeID:   scopeID.String(),
		scope:     scopeID,
		path:      path,
		opener:    opener,
		signer:    signer,
		superPub:  pub.Bytes(),
		oek:       append([]byte(nil), oek...),
		fullChain: full,
		vaultTip:  vaultTip,
		vaultFile: paths.Vault,
	}
}

// compact rewrites the chain file the way the retired v1 compactor did:
// genesis plus the last `keep` events.
func (f *legacyFixture) compact(t *testing.T, keep int) {
	t.Helper()
	kept := append([]proto.ScopeEvent{f.fullChain[0]}, f.fullChain[len(f.fullChain)-keep:]...)
	raws := make([][]byte, 0, len(kept))
	for i := range kept {
		raw, err := proto.Marshal(&kept[i])
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	if err := chain.WriteAll(f.path, raws); err != nil {
		t.Fatal(err)
	}
	if cls, err := chain.ClassifyScopeChain(f.path); err != nil || cls.Shape != chain.ScopeShapeLegacyCompacted {
		t.Fatalf("fixture is not legacy-compacted: %+v (%v)", cls, err)
	}
}

func (f *legacyFixture) snapshot(t *testing.T) (chainBytes, vaultBytes []byte) {
	t.Helper()
	c, err := os.ReadFile(f.path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := os.ReadFile(f.vaultFile)
	if err != nil {
		t.Fatal(err)
	}
	return c, v
}

func (f *legacyFixture) assertUnchanged(t *testing.T, chainBytes, vaultBytes []byte, scope proto.ScopeVaultData) {
	t.Helper()
	nowChain, nowVault := f.snapshot(t)
	if !bytes.Equal(chainBytes, nowChain) {
		t.Fatal("failed migration rewrote the chain file")
	}
	if !bytes.Equal(vaultBytes, nowVault) {
		t.Fatal("failed migration rewrote the vault file")
	}
	after := f.session.Body.Scopes[f.scopeID]
	if after.ChainTip.Seq != scope.ChainTip.Seq || !bytes.Equal(after.ChainTip.Hash, scope.ChainTip.Hash) {
		t.Fatalf("failed migration moved the sealed chain tip: %d/%x → %d/%x",
			scope.ChainTip.Seq, scope.ChainTip.Hash, after.ChainTip.Seq, after.ChainTip.Hash)
	}
}

func serve(events []proto.ScopeEvent) func() ([]proto.ScopeEvent, error) {
	return func() ([]proto.ScopeEvent, error) { return events, nil }
}

// The happy path: a compacted chain is restored to the full history, the
// result is contiguous, and the vault is not touched at all.
func TestMigrateLegacyScopeChainRestoresHistory(t *testing.T) {
	f := newLegacyFixture(t, 5)
	f.compact(t, 2)
	_, vaultBefore := f.snapshot(t)

	if err := f.session.migrateLegacyScopeChainFrom(f.scopeID, serve(f.fullChain), f.opener); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	cls, err := chain.ClassifyScopeChain(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if cls.Shape != chain.ScopeShapeContiguous {
		t.Fatalf("post-migration shape = %q (%s)", cls.Shape, cls.Reason)
	}
	if cls.Events != len(f.fullChain) {
		t.Fatalf("restored %d events, want %d", cls.Events, len(f.fullChain))
	}
	if cls.Tip.Seq != f.vaultTip.Seq || !bytes.Equal(cls.Tip.Hash, f.vaultTip.Hash) {
		t.Fatal("migration changed the committed tip")
	}
	if _, vaultAfter := f.snapshot(t); !bytes.Equal(vaultBefore, vaultAfter) {
		t.Fatal("migration wrote to the vault")
	}
	// Idempotent: a second run is a no-op and does not need the server.
	if err := f.session.migrateLegacyScopeChainFrom(f.scopeID, func() ([]proto.ScopeEvent, error) {
		t.Fatal("second migration hit the network")
		return nil, nil
	}, f.opener); err != nil {
		t.Fatalf("second migration: %v", err)
	}
}

// The core security property: a server history that does not replay to the
// tip the vault already sealed is REFUSED, and nothing is written.
//
// The forgery here is the realistic one — a server that returns a
// self-consistent, fully signed history whose contents differ from what this
// device accepted (an extra event spliced in below our tip). Every signature
// verifies; only the tip hash gives it away.
func TestMigrateLegacyScopeChainRefusesTipMismatch(t *testing.T) {
	f := newLegacyFixture(t, 5)
	f.compact(t, 2)
	scopeBefore := f.session.Body.Scopes[f.scopeID].Clone()
	chainBefore, vaultBefore := f.snapshot(t)

	// Same author, same scope, same length, valid signatures and hash links
	// end to end — but forked below our sealed tip, so it replays to a
	// different tip hash.
	forged := f.forkAt(t, 3)
	if len(forged) != len(f.fullChain) {
		t.Fatalf("fork changed the history length: %d vs %d", len(forged), len(f.fullChain))
	}
	if err := chain.ValidateScopeEventContinuity(forged); err != nil {
		t.Fatalf("fork is not internally contiguous, the test would prove nothing: %v", err)
	}

	err := f.session.migrateLegacyScopeChainFrom(f.scopeID, serve(forged), f.opener)
	if err == nil {
		t.Fatal("migration accepted a history that does not match the vault tip")
	}
	if !errors.Is(err, ErrLegacyScopeHistoryUnverifiable) {
		t.Fatalf("error = %v, want ErrLegacyScopeHistoryUnverifiable", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("divergence")) {
		t.Fatalf("refusal does not name the cause: %v", err)
	}
	f.assertUnchanged(t, chainBefore, vaultBefore, scopeBefore)
}

// Same refusal when the server's history is a genuine prefix of ours: it is
// behind our sealed tip, so there is nothing to anchor against.
func TestMigrateLegacyScopeChainRefusesServerBehindVaultTip(t *testing.T) {
	f := newLegacyFixture(t, 5)
	f.compact(t, 2)
	scopeBefore := f.session.Body.Scopes[f.scopeID].Clone()
	chainBefore, vaultBefore := f.snapshot(t)

	behind := f.fullChain[:len(f.fullChain)-2]
	err := f.session.migrateLegacyScopeChainFrom(f.scopeID, serve(behind), f.opener)
	if !errors.Is(err, ErrLegacyScopeHistoryUnverifiable) {
		t.Fatalf("error = %v, want ErrLegacyScopeHistoryUnverifiable", err)
	}
	f.assertUnchanged(t, chainBefore, vaultBefore, scopeBefore)
}

// A server that is AHEAD is fine, but migration adopts only the prefix up to
// the sealed tip — it restores history, it never advances it. The rest is the
// ordinary cursor-based pull's job, with its ordinary verification.
func TestMigrateLegacyScopeChainAdoptsOnlyUpToSealedTip(t *testing.T) {
	f := newLegacyFixture(t, 7)
	// Seal the vault two events short of the file's real tip, then compact.
	f.vaultTip = proto.ChainTip{Seq: f.fullChain[len(f.fullChain)-3].SignedPrefix.Seq}
	shortInput, err := f.fullChain[len(f.fullChain)-3].PrevHashInput()
	if err != nil {
		t.Fatal(err)
	}
	shortHash := proto.HashPrefix(shortInput)
	f.vaultTip.Hash = append([]byte(nil), shortHash[:]...)
	f.session.Body.Scopes[f.scopeID] = proto.ScopeVaultData{ChainTip: f.vaultTip}
	// Local file: genesis + the window ending at the sealed tip.
	local := append([]proto.ScopeEvent{f.fullChain[0]}, f.fullChain[len(f.fullChain)-4:len(f.fullChain)-2]...)
	raws := make([][]byte, 0, len(local))
	for i := range local {
		raw, mErr := proto.Marshal(&local[i])
		if mErr != nil {
			t.Fatal(mErr)
		}
		raws = append(raws, raw)
	}
	if err := chain.WriteAll(f.path, raws); err != nil {
		t.Fatal(err)
	}

	if err := f.session.migrateLegacyScopeChainFrom(f.scopeID, serve(f.fullChain), f.opener); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	cls, err := chain.ClassifyScopeChain(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if cls.Shape != chain.ScopeShapeContiguous {
		t.Fatalf("post-migration shape = %q (%s)", cls.Shape, cls.Reason)
	}
	if cls.Tip.Seq != f.vaultTip.Seq {
		t.Fatalf("adopted up to seq %d, want the sealed tip %d", cls.Tip.Seq, f.vaultTip.Seq)
	}
}

// A server copy that is itself gapped must be rejected BEFORE the commit —
// not adopted and then rejected on the next read.
func TestMigrateLegacyScopeChainRefusesGappedServerHistory(t *testing.T) {
	f := newLegacyFixture(t, 5)
	f.compact(t, 2)
	scopeBefore := f.session.Body.Scopes[f.scopeID].Clone()
	chainBefore, vaultBefore := f.snapshot(t)

	gapped := append([]proto.ScopeEvent{f.fullChain[0]}, f.fullChain[2:]...)
	err := f.session.migrateLegacyScopeChainFrom(f.scopeID, serve(gapped), f.opener)
	if !errors.Is(err, ErrLegacyScopeHistoryUnverifiable) {
		t.Fatalf("error = %v, want ErrLegacyScopeHistoryUnverifiable", err)
	}
	f.assertUnchanged(t, chainBefore, vaultBefore, scopeBefore)
}

// Offline / unreachable server: the failure must be reported, not swallowed,
// and must leave the chain file and vault byte-identical.
func TestMigrateLegacyScopeChainOfflineLeavesStateIdentical(t *testing.T) {
	f := newLegacyFixture(t, 5)
	f.compact(t, 2)
	scopeBefore := f.session.Body.Scopes[f.scopeID].Clone()
	chainBefore, vaultBefore := f.snapshot(t)

	err := f.session.migrateLegacyScopeChainFrom(f.scopeID, func() ([]proto.ScopeEvent, error) {
		return nil, errors.New("dial tcp 127.0.0.1:14061: connect: connection refused")
	}, f.opener)
	if !errors.Is(err, ErrLegacyScopeHistoryNeedsServer) {
		t.Fatalf("error = %v, want ErrLegacyScopeHistoryNeedsServer", err)
	}
	// The message has to tell the user what happened and that retrying is safe.
	for _, want := range []string{"older version of fd0", "one-time history repair", "retrying is safe"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Fatalf("offline message %q is missing %q", err, want)
		}
	}
	f.assertUnchanged(t, chainBefore, vaultBefore, scopeBefore)

	// Retry is safe: with the server back, the same call succeeds.
	if err := f.session.migrateLegacyScopeChainFrom(f.scopeID, serve(f.fullChain), f.opener); err != nil {
		t.Fatalf("retry after outage failed: %v", err)
	}
}

// A local-only event must never be dropped. Here the server's history stops
// one event short of the tip this device sealed — i.e. our newest write never
// reached it. Migration must refuse rather than adopt a history that would
// erase that write from disk.
func TestMigrateLegacyScopeChainRefusesToDropLocalOnlyEvents(t *testing.T) {
	f := newLegacyFixture(t, 5)
	f.compact(t, 2)
	scopeBefore := f.session.Body.Scopes[f.scopeID].Clone()
	chainBefore, vaultBefore := f.snapshot(t)

	withoutTail := f.fullChain[:len(f.fullChain)-1]
	err := f.session.migrateLegacyScopeChainFrom(f.scopeID, serve(withoutTail), f.opener)
	if err == nil {
		t.Fatal("migration dropped a local-only event")
	}
	if !errors.Is(err, ErrLegacyScopeHistoryUnverifiable) {
		t.Fatalf("error = %v, want ErrLegacyScopeHistoryUnverifiable", err)
	}
	f.assertUnchanged(t, chainBefore, vaultBefore, scopeBefore)
}

// Non-legacy shapes are never migrated, even when the server would happily
// serve a replacement.
//
// A gap is not the discriminator — repeated compaction leaves several, and a
// production vault carried five. What separates compaction from tampering is
// that compaction only ever DROPS events, leaving the surviving links intact.
// A broken link with no gap means an event was substituted, and re-fetching
// would paper over exactly that.
func TestMigrateLegacyScopeChainIgnoresNonLegacyShapes(t *testing.T) {
	f := newLegacyFixture(t, 5)
	tampered := append([]proto.ScopeEvent{}, f.fullChain...)
	tampered[2].SignedPrefix.PrevHash = bytes.Repeat([]byte{0x11}, 32)
	raws := make([][]byte, 0, len(tampered))
	for i := range tampered {
		raw, err := proto.Marshal(&tampered[i])
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	if err := chain.WriteAll(f.path, raws); err != nil {
		t.Fatal(err)
	}
	chainBefore, vaultBefore := f.snapshot(t)
	scopeBefore := f.session.Body.Scopes[f.scopeID].Clone()

	if err := f.session.migrateLegacyScopeChainFrom(f.scopeID, func() ([]proto.ScopeEvent, error) {
		t.Fatal("migration fetched a replacement for a non-legacy shape")
		return nil, nil
	}, f.opener); err != nil {
		t.Fatalf("migration should be a silent no-op, got %v", err)
	}
	f.assertUnchanged(t, chainBefore, vaultBefore, scopeBefore)
	if f.session.HasLegacyCompactedScopes() {
		t.Fatal("a mid-history gap was classified as legacy-compacted")
	}
}

// A contiguous vault needs no migration and must not touch the network.
func TestMigrateLegacyScopeChainsNoOpOnHealthyVault(t *testing.T) {
	f := newLegacyFixture(t, 3)
	if f.session.HasLegacyCompactedScopes() {
		t.Fatal("healthy vault reported as legacy-compacted")
	}
	if err := f.session.MigrateLegacyScopeChains(t.Context()); err != nil {
		t.Fatalf("no-op migration returned %v", err)
	}
}
