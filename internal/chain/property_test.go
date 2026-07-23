package chain

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Property tests for chain replay invariants. Unlike the focused
// roundtrip tests in chain_test.go, these exercise the algebra of
// replay over RANDOMLY-GENERATED chains:
//
//   - Determinism: ReplayScope is a pure function of the chain bytes
//     + the opener; running it twice yields the byte-identical state.
//   - Pure: replay does NOT mutate the chain file (file bytes
//     unchanged across multiple replays).
//   - Removing any interior event makes replay fail closed.
//   - LocalOnlyEvents preserves the local-side order.
//
// Each property runs N iterations with a fixed seed sequence so a
// failure is reproducible by re-running with the printed seed.

const propIterations = 30

// makeChain builds a random scope chain on disk and returns the path
// + opener + signing identity. Chain shape is more diverse than the
// focused tests:
//
//   - Genesis (member.change op=add, author=self)
//   - Several add-member events (NEVER touching self)
//   - Several remove-member events (NEVER targeting self — that
//     would set st.Left and abort replay; covered separately)
//   - Several secret.set events with potential duplicate IDs to
//     exercise the supersede path
//
// The generator is seeded so failures are reproducible.
func makeChain(t *testing.T, dir string, seed int64, nMembers, nSecrets int) (path string, pub []byte, opener Opener) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))

	pubT, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pub = pubT.Bytes()
	xPub, _ := crypto.EdPubToX25519(pub)
	xPriv, _ := crypto.EdPrivToX25519(priv.Bytes())
	signer := LocalSigner{Priv: priv}
	opener = LocalOpener{Pub: xPub, Priv: xPriv}

	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}

	currentOEK := oek
	currentOEKVer := uint64(1)

	// Generate `nMembers` other identities; some get added then
	// removed to exercise both branches of the member.change OEK
	// rotation. We never touch self so replay stays in the active
	// branch.
	others := make([][]byte, nMembers)
	for i := range others {
		op, _, err := crypto.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		others[i] = op.Bytes()
	}

	// Add all members.
	for _, ot := range others {
		st, err := ReplayScope(path, pub, xPub, opener)
		if err != nil {
			t.Fatalf("seed=%d: replay before add: %v", seed, err)
		}
		proj := buildProjection(st)
		ev, newOEK, err := BuildMemberChange(signer, pub,
			scopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
			proto.OpAdd, ot, st.MemberSet, proj)
		if err != nil {
			t.Fatalf("seed=%d: member add: %v", seed, err)
		}
		if err := AppendScope(path, ev); err != nil {
			t.Fatal(err)
		}
		currentOEK = newOEK
		currentOEKVer++
	}

	// Pool of secret IDs — some get reused for supersedes.
	idPool := []string{
		"s_" + randomString(r, 8),
		"s_" + randomString(r, 8),
		"s_" + randomString(r, 8),
		"s_" + randomString(r, 8),
		"s_" + randomString(r, 8),
	}
	// Track how many supersedes/tombstones we've emitted — caller
	// uses these to assert generator coverage when needed.
	for i := 0; i < nSecrets; i++ {
		st, err := ReplayScope(path, pub, xPub, opener)
		if err != nil {
			t.Fatalf("seed=%d: replay before secret #%d: %v", seed, i, err)
		}
		// Reuse an existing id ~40% of the time to exercise supersedes.
		// Tombstone ~15% of those reuses.
		var id string
		var record *proto.SecretRecord
		if r.Intn(100) < 40 && len(idPool) > 0 {
			id = idPool[r.Intn(len(idPool))]
			if r.Intn(100) < 15 {
				record = nil // tombstone — covers delete path
			} else {
				record = &proto.SecretRecord{
					Name:          randomString(r, 6),
					Type:          "kv.string",
					SchemaVersion: 1,
					Payload:       randomString(r, 8+r.Intn(60)),
					Tags:          map[string]string{},
				}
			}
		} else {
			id = "s_" + randomString(r, 8)
			idPool = append(idPool, id)
			record = &proto.SecretRecord{
				Name:          randomString(r, 6),
				Type:          "kv.string",
				SchemaVersion: 1,
				Payload:       randomString(r, 8+r.Intn(60)),
				Tags:          map[string]string{},
			}
		}
		body := &proto.SecretBody{ID: id, Record: record}
		ev, err := BuildSecretSet(signer, pub, scopeID,
			st.TipSeq, st.TipHash, currentOEK, currentOEKVer, body)
		if err != nil {
			t.Fatalf("seed=%d: secret.set #%d: %v", seed, i, err)
		}
		if err := AppendScope(path, ev); err != nil {
			t.Fatal(err)
		}
	}

	// Remove a couple of OTHER members to exercise the remove
	// branch. Never targeting self. After removal we ALSO write
	// one secret.set under the rotated OEK — bugs that mishandle
	// the post-rotation key would surface as a replay failure.
	if nMembers >= 2 {
		st, err := ReplayScope(path, pub, xPub, opener)
		if err != nil {
			t.Fatalf("seed=%d: replay before remove: %v", seed, err)
		}
		// Pick an actual current member from MemberSet that isn't us.
		for _, m := range st.MemberSet {
			if !bytes.Equal(m, pub) {
				proj := buildProjection(st)
				ev, _, err := BuildMemberChange(signer, pub,
					scopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
					proto.OpRemove, m, st.MemberSet, proj)
				if err != nil {
					t.Fatalf("seed=%d: member remove: %v", seed, err)
				}
				if err := AppendScope(path, ev); err != nil {
					t.Fatal(err)
				}
				// Refresh OEK after rotation.
				newSt, err := ReplayScope(path, pub, xPub, opener)
				if err != nil {
					t.Fatalf("seed=%d: replay after remove: %v", seed, err)
				}
				currentOEK = newSt.OEKs[newSt.CurrentOEKVer]
				currentOEKVer = newSt.CurrentOEKVer

				// Post-rotation write: catches bugs that try to
				// reuse the pre-rotation OEK or fail to emit/use
				// the new version.
				postBody := &proto.SecretBody{
					ID: "s_post_" + randomString(r, 6),
					Record: &proto.SecretRecord{
						Name: "post-rotation", Type: "kv.string",
						SchemaVersion: 1, Payload: "after-remove",
						Tags: map[string]string{},
					},
				}
				postEv, err := BuildSecretSet(signer, pub, scopeID,
					newSt.TipSeq, newSt.TipHash, currentOEK, currentOEKVer, postBody)
				if err != nil {
					t.Fatalf("seed=%d: post-rotation secret.set: %v", seed, err)
				}
				if err := AppendScope(path, postEv); err != nil {
					t.Fatal(err)
				}
				break
			}
		}
	}

	return path, pub, opener
}

func randomString(r *rand.Rand, n int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}

// buildProjection returns a MemberProjection of the current secret
// index — required by BuildMemberChange to satisfy projection-content
// integrity (every existing secret must appear in the new projection).
func buildProjection(st *ScopeState) *proto.MemberProjection {
	proj := &proto.MemberProjection{Secrets: make([]proto.SecretInProjection, 0, len(st.SecretIndex))}
	for id, cur := range st.SecretIndex {
		if cur.Record == nil {
			continue
		}
		proj.Secrets = append(proj.Secrets, proto.SecretInProjection{ID: id, Record: cur.Record})
	}
	return proj
}

// stateEquivalent compares two ScopeStates field-by-field except
// for the OEKs map (per-replay decoding produces equivalent but
// distinct slice headers — semantic equality is "same versions
// pointing to same key bytes").
func stateEquivalent(a, b *ScopeState) error {
	if a == nil || b == nil {
		if a != b {
			return fmt.Errorf("one state is nil, the other isn't")
		}
		return nil
	}
	if a.ScopeID != b.ScopeID {
		return fmt.Errorf("ScopeID drift: %s vs %s", a.ScopeID, b.ScopeID)
	}
	if a.TipSeq != b.TipSeq {
		return fmt.Errorf("TipSeq drift: %d vs %d", a.TipSeq, b.TipSeq)
	}
	if !bytes.Equal(a.TipHash, b.TipHash) {
		return fmt.Errorf("TipHash drift")
	}
	if a.CurrentOEKVer != b.CurrentOEKVer {
		return fmt.Errorf("CurrentOEKVer drift: %d vs %d", a.CurrentOEKVer, b.CurrentOEKVer)
	}
	if a.Left != b.Left {
		return fmt.Errorf("Left drift: %v vs %v", a.Left, b.Left)
	}
	// MemberSet — sorted bytes, compare each.
	if len(a.MemberSet) != len(b.MemberSet) {
		return fmt.Errorf("MemberSet len drift: %d vs %d", len(a.MemberSet), len(b.MemberSet))
	}
	for i := range a.MemberSet {
		if !bytes.Equal(a.MemberSet[i], b.MemberSet[i]) {
			return fmt.Errorf("MemberSet[%d] drift", i)
		}
	}
	// OEKs — same keys + same bytes per version.
	if len(a.OEKs) != len(b.OEKs) {
		return fmt.Errorf("OEKs map len drift: %d vs %d", len(a.OEKs), len(b.OEKs))
	}
	for v, k := range a.OEKs {
		k2, ok := b.OEKs[v]
		if !ok {
			return fmt.Errorf("OEK v%d in A but not B", v)
		}
		if !bytes.Equal(k, k2) {
			return fmt.Errorf("OEK v%d byte drift", v)
		}
	}
	// SecretIndex — same id set + same record contents.
	if len(a.SecretIndex) != len(b.SecretIndex) {
		return fmt.Errorf("SecretIndex len drift: %d vs %d", len(a.SecretIndex), len(b.SecretIndex))
	}
	for id, sa := range a.SecretIndex {
		sb, ok := b.SecretIndex[id]
		if !ok {
			return fmt.Errorf("secret %s in A but not B", id)
		}
		if sa.EventID != sb.EventID {
			return fmt.Errorf("secret %s EventID drift", id)
		}
		// Compare records via reflect.DeepEqual (Tags is a map).
		if !reflect.DeepEqual(sa.Record, sb.Record) {
			return fmt.Errorf("secret %s Record drift", id)
		}
	}
	return nil
}

// TestPropertyReplayDeterministic asserts ReplayScope is a pure
// function of (chain bytes, opener): two replays of the same chain
// yield byte-identical state. Failures print the seed for repro.
func TestPropertyReplayDeterministic(t *testing.T) {
	for i := 0; i < propIterations; i++ {
		seed := int64(0x1000 + i)
		dir := t.TempDir()
		path, pub, opener := makeChain(t, dir, seed, 1+i%4, 1+i%5)
		lo := opener.(LocalOpener)
		st1, err := ReplayScope(path, pub, lo.Pub, opener)
		if err != nil {
			t.Fatalf("seed=%d: first replay: %v", seed, err)
		}
		st2, err := ReplayScope(path, pub, lo.Pub, opener)
		if err != nil {
			t.Fatalf("seed=%d: second replay: %v", seed, err)
		}
		if err := stateEquivalent(st1, st2); err != nil {
			t.Fatalf("seed=%d: replay non-deterministic: %v", seed, err)
		}
	}
}

// TestPropertyReplayDoesNotMutateChain asserts the chain file bytes
// are unchanged after multiple replays. A regression here would be
// a side effect that subtly extends or rewrites the chain on read.
func TestPropertyReplayDoesNotMutateChain(t *testing.T) {
	for i := 0; i < propIterations; i++ {
		seed := int64(0x2000 + i)
		dir := t.TempDir()
		path, pub, opener := makeChain(t, dir, seed, 2, 4)
		lo := opener.(LocalOpener)

		preBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 5; j++ {
			if _, err := ReplayScope(path, pub, lo.Pub, opener); err != nil {
				t.Fatalf("seed=%d iter=%d: %v", seed, j, err)
			}
		}
		postBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(preBytes, postBytes) {
			t.Fatalf("seed=%d: chain bytes mutated by replay (len pre=%d post=%d)",
				seed, len(preBytes), len(postBytes))
		}
	}
}

func TestPropertyReplayRejectsInteriorEventRemoval(t *testing.T) {
	for i := 0; i < propIterations; i++ {
		seed := int64(0x3000 + i)
		dir := t.TempDir()
		path, pub, opener := makeChain(t, dir, seed, 1, 12)
		lo := opener.(LocalOpener)
		events, err := ReadScopeEvents(path)
		if err != nil {
			t.Fatal(err)
		}
		drop := 1 + i%(len(events)-2)
		kept := make([][]byte, 0, len(events)-1)
		for index, event := range events {
			if index == drop {
				continue
			}
			raw, err := proto.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			kept = append(kept, raw)
		}
		if err := WriteAll(path, kept); err != nil {
			t.Fatal(err)
		}
		if _, err := ReplayScope(path, pub, lo.Pub, opener); !errors.Is(err, ErrScopeHistoryNonContiguous) {
			t.Fatalf("seed=%d drop=%d: expected continuity rejection, got %v", seed, drop, err)
		}
	}
}

// TestPropertyLocalOnlyEventsCollidesOnSeqOnly: a buggy
// LocalOnlyEvents that keyed on Seq instead of EventID would
// silently drop a local event whose Seq matches an unrelated
// server event. This test constructs that exact collision: local
// and server share a Seq value but have different EventID — the
// local event MUST appear in the result.
func TestPropertyLocalOnlyEventsCollidesOnSeqOnly(t *testing.T) {
	mk := func(seq uint64, marker byte) proto.ScopeEvent {
		return proto.ScopeEvent{
			SignedPrefix: proto.SignedPrefix{
				Kind:     proto.KindSecretSet,
				Scope:    proto.ScopePtr(proto.MustParseScopeID("s_aaaaaaaaaaaaaaaaaaaaaaaaaa")),
				PrevHash: bytes.Repeat([]byte{marker}, 32),
				Author:   bytes.Repeat([]byte{0xAA}, 32),
				Seq:      seq,
				Payload:  proto.Payload{EncBody: bytes.Repeat([]byte{marker}, 13)},
			},
		}
	}
	// Local has seqs {1, 2, 3} with marker 'L'.
	local := []proto.ScopeEvent{mk(1, 'L'), mk(2, 'L'), mk(3, 'L')}
	// Server has DIFFERENT events at the SAME seqs (different marker
	// → different EventID). A correct implementation must return ALL
	// three local events as "local-only"; a Seq-keyed bug returns 0.
	server := []proto.ScopeEvent{mk(1, 'S'), mk(2, 'S'), mk(3, 'S')}
	got := LocalOnlyEvents(local, server)
	if len(got) != 3 {
		t.Fatalf("Seq-collision: expected 3 local-only, got %d (Seq-keyed bug?)", len(got))
	}
	for i, ev := range got {
		gp, _ := ev.PrevHashInput()
		ep, _ := local[i].PrevHashInput()
		if proto.EventID(gp) != proto.EventID(ep) {
			t.Fatalf("Seq-collision: index %d returned wrong event", i)
		}
	}
}

// TestPropertyLocalOnlyEventsPreservesOrder: LocalOnlyEvents must
// return events in their LOCAL-side order. Sync's reconcile rebuilds
// these in sequence; a shuffle would change the rebuilt seq order.
func TestPropertyLocalOnlyEventsPreservesOrder(t *testing.T) {
	for i := 0; i < propIterations; i++ {
		seed := int64(0x4000 + i)
		r := rand.New(rand.NewSource(seed))

		n := 3 + r.Intn(7)
		local := make([]proto.ScopeEvent, n)
		for j := range local {
			local[j] = proto.ScopeEvent{
				SignedPrefix: proto.SignedPrefix{
					Kind:     proto.KindSecretSet,
					Scope:    proto.ScopePtr(proto.MustParseScopeID("s_aaaaaaaaaaaaaaaaaaaaaaaaaa")),
					PrevHash: bytes.Repeat([]byte{byte(seed) ^ byte(j)}, 32),
					Author:   bytes.Repeat([]byte{0xAA}, 32),
					Seq:      uint64(j),
					Payload:  proto.Payload{EncBody: bytes.Repeat([]byte{byte(j)}, 13)},
				},
			}
		}

		var server []proto.ScopeEvent
		var expectLocalOnly []proto.ScopeEvent
		for _, ev := range local {
			if r.Intn(2) == 0 {
				server = append(server, ev)
			} else {
				expectLocalOnly = append(expectLocalOnly, ev)
			}
		}

		got := LocalOnlyEvents(local, server)
		if len(got) != len(expectLocalOnly) {
			t.Fatalf("seed=%d: got %d local-only, expected %d", seed, len(got), len(expectLocalOnly))
		}
		for k := range got {
			gp, _ := got[k].PrevHashInput()
			ep, _ := expectLocalOnly[k].PrevHashInput()
			if proto.EventID(gp) != proto.EventID(ep) {
				t.Fatalf("seed=%d: order/identity mismatch at index %d", seed, k)
			}
		}
	}
}
