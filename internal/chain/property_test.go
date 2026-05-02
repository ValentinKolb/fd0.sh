package chain

import (
	"bytes"
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
//   - Compaction commutes with replay for live secrets.
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

	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub)
	xPriv, _ := crypto.EdPrivToX25519(priv)
	signer := LocalSigner{Priv: priv}
	opener = LocalOpener{Pub: xPub, Priv: xPriv}

	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, scopeID+".cbor")
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
		others[i] = op
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
		// Reuse an existing id ~40% of the time so compaction has
		// something to drop. Tombstone ~15% of those reuses.
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

// TestPropertyCompactionPreservesLiveState: after CompactScope,
// replaying the chain MUST yield a SecretIndex with the same live
// (non-tombstone) records as before compaction. Compacted chains
// have non-contiguous seq/prev_hash, so the replay tolerates gaps —
// this property catches a regression that would drop live secrets
// during compaction.
//
// Stronger than just count+payload: we compare full SecretRecord
// (Name, Type, SchemaVersion, Payload, Tags) and EventID. We ALSO
// require that compaction actually dropped at least one event in
// total across all iterations; without that guarantee the test
// would silently pass if CompactScope became a no-op.
func TestPropertyCompactionPreservesLiveState(t *testing.T) {
	totalDropped := 0
	for i := 0; i < propIterations; i++ {
		seed := int64(0x3000 + i)
		dir := t.TempDir()
		// Force enough secrets that supersede + tombstone produce
		// drop candidates; nSecrets=12 with 40% reuse yields several.
		path, pub, opener := makeChain(t, dir, seed, 1, 12)
		lo := opener.(LocalOpener)

		stPre, err := ReplayScope(path, pub, lo.Pub, opener)
		if err != nil {
			t.Fatalf("seed=%d: pre-compact replay: %v", seed, err)
		}
		_, dropped, err := CompactScope(path, stPre)
		if err != nil {
			t.Fatalf("seed=%d: compact: %v", seed, err)
		}
		totalDropped += len(dropped)
		stPost, err := ReplayScope(path, pub, lo.Pub, opener)
		if err != nil {
			t.Fatalf("seed=%d: post-compact replay: %v", seed, err)
		}

		// Live records must agree byte-for-byte. Iterate pre→post
		// AND post→pre to catch additions in either direction.
		livePre := map[string]ScopeSecret{}
		livePost := map[string]ScopeSecret{}
		for id, e := range stPre.SecretIndex {
			if e.Record != nil {
				livePre[id] = e
			}
		}
		for id, e := range stPost.SecretIndex {
			if e.Record != nil {
				livePost[id] = e
			}
		}
		if len(livePre) != len(livePost) {
			t.Fatalf("seed=%d: live count drift: pre=%d post=%d", seed, len(livePre), len(livePost))
		}
		for id, prev := range livePre {
			post, ok := livePost[id]
			if !ok {
				t.Fatalf("seed=%d: live id %s lost across compaction", seed, id)
			}
			if !reflect.DeepEqual(prev.Record, post.Record) {
				t.Fatalf("seed=%d: id %s record drift across compaction:\n pre=%+v\npost=%+v",
					seed, id, prev.Record, post.Record)
			}
			if prev.EventID != post.EventID {
				t.Fatalf("seed=%d: id %s EventID drift: pre=%s post=%s", seed, id, prev.EventID, post.EventID)
			}
		}
		// Member set + OEK + tip semantics survive compaction.
		if len(stPre.MemberSet) != len(stPost.MemberSet) {
			t.Fatalf("seed=%d: MemberSet len drift: pre=%d post=%d",
				seed, len(stPre.MemberSet), len(stPost.MemberSet))
		}
		if stPre.CurrentOEKVer != stPost.CurrentOEKVer {
			t.Fatalf("seed=%d: CurrentOEKVer drift: pre=%d post=%d",
				seed, stPre.CurrentOEKVer, stPost.CurrentOEKVer)
		}
	}
	// Sanity: across 30 iterations with supersedes + tombstones,
	// CompactScope MUST have dropped at least one event total. A
	// no-op compactor would pass every per-iter check above.
	if totalDropped == 0 {
		t.Fatalf("CompactScope dropped 0 events across %d iterations — either generator broken or compaction is a no-op", propIterations)
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
				Scope:    proto.ScopePtr("s_test"),
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
					Scope:    proto.ScopePtr("s_test"),
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
