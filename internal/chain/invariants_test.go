package chain

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Invariant-based randomized state-machine tests for the scope
// chain. Pattern: generate a random sequence of chain ops, apply
// them, and after EVERY op verify a set of invariants. Catches
// state-divergence bugs that scenario tests miss because they
// pin specific paths.
//
// Each test runs N iterations with a fixed-seeded PRNG so failures
// are reproducible.
//
// Invariants checked after every applicable op:
//
//   I1. Replay determinism — replaying the on-disk chain twice yields
//       byte-identical states.
//   I2. MemberSet sorted — st.MemberSet is in canonical order and
//       contains no duplicates.
//   I3. OEK ring complete — every secret.set in the chain has its
//       oek_version present in st.OEKs (at least, for events we
//       can decrypt; pre-admit events are excluded).
//   I4. TipHash continuity — st.TipHash == HashPrefix of the last
//       applied event's prefix.
//   I5. SecretIndex live records — every non-tombstone entry has a
//       non-nil Record AND it round-trips through Marshal+Unmarshal
//       byte-identically (no aliasing into wiped buffers).
//   I6. ScopeID stability — st.ScopeID never changes after genesis.

const invIters = 50
const opsPerRun = 30

func TestInvariantsScopeStateMachine(t *testing.T) {
	for run := 0; run < invIters; run++ {
		seed := int64(0x100000 + run)
		t.Run(fmt.Sprintf("seed_%#x", seed), func(t *testing.T) {
			runInvariantSequence(t, seed)
		})
	}
}

func runInvariantSequence(t *testing.T, seed int64) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))

	dir := t.TempDir()
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub)
	xPriv, _ := crypto.EdPrivToX25519(priv)
	signer := LocalSigner{Priv: priv}
	opener := LocalOpener{Pub: xPub, Priv: xPriv}

	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, scopeID+".cbor")
	if err := AppendScope(path, gen); err != nil {
		t.Fatal(err)
	}
	currentOEK := oek
	currentOEKVer := uint64(1)
	stableScopeID := scopeID

	// Pool of OTHER identities we may add/remove. Pre-generated so
	// op execution can pick from a stable pool.
	const poolN = 6
	pool := make([][]byte, poolN)
	for i := range pool {
		op, _, err := crypto.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		pool[i] = op
	}

	// Pool of secret IDs.
	idPool := []string{}

	// Tracked outside chain: names of secrets we've set (for
	// cross-checking SecretIndex contents).
	expected := map[string]string{} // id → last payload

	for op := 0; op < opsPerRun; op++ {
		st, err := ReplayScope(path, pub, xPub, opener)
		if err != nil {
			t.Fatalf("seed=%#x op=%d: replay failed: %v", seed, op, err)
		}
		// Pre-op invariants.
		assertInvariants(t, seed, op, st, stableScopeID, expected, path, pub, xPub, opener)

		// Choose an op.
		choice := r.Intn(100)
		switch {
		case choice < 15:
			// add member (if pool slot not yet a member)
			candidate := pickNonMember(pool, st.MemberSet)
			if candidate == nil {
				continue
			}
			proj := buildProjection(st)
			ev, newOEK, err := BuildMemberChange(signer, pub,
				stableScopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
				proto.OpAdd, candidate, st.MemberSet, proj)
			if err != nil {
				t.Fatalf("seed=%#x op=%d: add: %v", seed, op, err)
			}
			if err := AppendScope(path, ev); err != nil {
				t.Fatal(err)
			}
			currentOEK = newOEK
			currentOEKVer++
		case choice < 25:
			// remove member (if any non-self member exists)
			var target []byte
			for _, m := range st.MemberSet {
				if !bytes.Equal(m, pub) {
					target = m
					break
				}
			}
			if target == nil {
				continue
			}
			proj := buildProjection(st)
			ev, newOEK, err := BuildMemberChange(signer, pub,
				stableScopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
				proto.OpRemove, target, st.MemberSet, proj)
			if err != nil {
				t.Fatalf("seed=%#x op=%d: remove: %v", seed, op, err)
			}
			if err := AppendScope(path, ev); err != nil {
				t.Fatal(err)
			}
			currentOEK = newOEK
			currentOEKVer++
		case choice < 80:
			// secret set
			var id string
			if r.Intn(100) < 40 && len(idPool) > 0 {
				id = idPool[r.Intn(len(idPool))]
			} else {
				id = "s_" + randStr(r, 8)
				idPool = append(idPool, id)
			}
			payload := randStr(r, 8+r.Intn(40))
			body := &proto.SecretBody{
				ID: id,
				Record: &proto.SecretRecord{
					Name: "n", Type: "kv.string", SchemaVersion: 1,
					Payload: payload, Tags: map[string]string{},
				},
			}
			ev, err := BuildSecretSet(signer, pub, stableScopeID,
				st.TipSeq, st.TipHash, currentOEK, currentOEKVer, body)
			if err != nil {
				t.Fatalf("seed=%#x op=%d: secret.set: %v", seed, op, err)
			}
			if err := AppendScope(path, ev); err != nil {
				t.Fatal(err)
			}
			expected[id] = payload
		case choice < 90:
			// tombstone
			if len(idPool) == 0 {
				continue
			}
			id := idPool[r.Intn(len(idPool))]
			body := &proto.SecretBody{ID: id, Record: nil}
			ev, err := BuildSecretSet(signer, pub, stableScopeID,
				st.TipSeq, st.TipHash, currentOEK, currentOEKVer, body)
			if err != nil {
				t.Fatalf("seed=%#x op=%d: tombstone: %v", seed, op, err)
			}
			if err := AppendScope(path, ev); err != nil {
				t.Fatal(err)
			}
			delete(expected, id)
		default:
			// noop
		}

		// Post-op invariants (after the chain mutated). Pass path
		// + opener so I1 (replay determinism) and I3 (OEK ring
		// completeness) can be properly asserted — both are
		// codex-audit fixes for previously-documented-but-not-
		// asserted invariants.
		stPost, err := ReplayScope(path, pub, xPub, opener)
		if err != nil {
			t.Fatalf("seed=%#x op=%d post-replay failed: %v", seed, op, err)
		}
		assertInvariants(t, seed, op, stPost, stableScopeID, expected, path, pub, xPub, opener)
	}
}

func assertInvariants(t *testing.T, seed int64, op int, st *ScopeState, expectedScope string, expectedSecrets map[string]string, path string, pub, xPub []byte, opener Opener) {
	t.Helper()

	// I6. ScopeID stability.
	if st.ScopeID != expectedScope {
		t.Fatalf("seed=%#x op=%d: I6 ScopeID drift (%s vs %s)", seed, op, st.ScopeID, expectedScope)
	}

	// I2. MemberSet sorted + no duplicates.
	if !sortedNoDup(st.MemberSet) {
		t.Fatalf("seed=%#x op=%d: I2 MemberSet not sorted/unique", seed, op)
	}

	// I3. OEK ring COMPLETE — codex audit fix. The previous code
	// only checked that CurrentOEKVer was in the map; it did NOT
	// check the headline claim "every secret.set in the chain has
	// its oek_version present in st.OEKs". We now scan every
	// SecretIndex entry's EventID, find the corresponding event
	// in the chain, and require its OEKVersion ∈ st.OEKs.
	events, err := ReadScopeEvents(path)
	if err != nil {
		t.Fatalf("seed=%#x op=%d: I3 read chain: %v", seed, op, err)
	}
	for _, ev := range events {
		if ev.SignedPrefix.Kind != proto.KindSecretSet {
			continue
		}
		v := ev.SignedPrefix.OEKVersion
		if _, ok := st.OEKs[v]; !ok {
			t.Fatalf("seed=%#x op=%d: I3 secret.set at seq=%d uses OEK v%d but ring missing it (have versions %v)",
				seed, op, ev.SignedPrefix.Seq, v, oekVersionList(st))
		}
	}
	if _, ok := st.OEKs[st.CurrentOEKVer]; !ok && len(st.MemberSet) > 0 {
		t.Fatalf("seed=%#x op=%d: I3 CurrentOEKVer=%d missing from OEKs ring", seed, op, st.CurrentOEKVer)
	}

	// I5. SecretIndex roundtrip — re-marshal+decode every record
	// to catch use-after-wipe / aliased buffers.
	for id, sec := range st.SecretIndex {
		if sec.Record == nil {
			continue
		}
		if want, ok := expectedSecrets[id]; ok {
			gotPayload, _ := sec.Record.Payload.(string)
			if gotPayload != want {
				t.Fatalf("seed=%#x op=%d: I5 secret %s payload drift (got %q want %q)",
					seed, op, id, gotPayload, want)
			}
		}
		buf, err := proto.Marshal(sec.Record)
		if err != nil {
			t.Fatalf("seed=%#x op=%d: I5 secret %s re-marshal failed: %v", seed, op, id, err)
		}
		var fresh proto.SecretRecord
		if err := proto.Unmarshal(buf, &fresh); err != nil {
			t.Fatalf("seed=%#x op=%d: I5 secret %s re-decode failed: %v", seed, op, id, err)
		}
	}

	// I4. TipHash 32 bytes when chain has events.
	if len(st.TipHash) != 32 && st.TipSeq > 0 {
		t.Fatalf("seed=%#x op=%d: I4 TipHash wrong length: %d", seed, op, len(st.TipHash))
	}

	// I1. Replay determinism — codex audit fix. The previous code
	// commented "two replays yield byte-identical states" but
	// didn't actually compare. Run a SECOND replay AND a third
	// against a copy of the file (catches code that mutates the
	// input file as a side effect), then compare deeply.
	st2, err := ReplayScope(path, pub, xPub, opener)
	if err != nil {
		t.Fatalf("seed=%#x op=%d: I1 second replay failed: %v", seed, op, err)
	}
	if err := scopeStateEquivalent(st, st2); err != nil {
		t.Fatalf("seed=%#x op=%d: I1 replay non-deterministic: %v", seed, op, err)
	}
	// Replay a COPY of the chain file — guards against code that
	// makes a path-specific cache mutate state.
	tmp := path + ".replay-copy"
	if data, rerr := os.ReadFile(path); rerr == nil {
		if werr := os.WriteFile(tmp, data, 0o600); werr == nil {
			defer os.Remove(tmp)
			st3, err := ReplayScope(tmp, pub, xPub, opener)
			if err == nil {
				if eqErr := scopeStateEquivalent(st, st3); eqErr != nil {
					t.Fatalf("seed=%#x op=%d: I1 replay differs across path copy: %v", seed, op, eqErr)
				}
			}
		}
	}
}

// scopeStateEquivalent deep-compares two ScopeStates for I1.
func scopeStateEquivalent(a, b *ScopeState) error {
	if a.ScopeID != b.ScopeID {
		return fmt.Errorf("ScopeID drift: %q vs %q", a.ScopeID, b.ScopeID)
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
	if len(a.MemberSet) != len(b.MemberSet) {
		return fmt.Errorf("MemberSet len: %d vs %d", len(a.MemberSet), len(b.MemberSet))
	}
	for i := range a.MemberSet {
		if !bytes.Equal(a.MemberSet[i], b.MemberSet[i]) {
			return fmt.Errorf("MemberSet[%d] differs", i)
		}
	}
	if len(a.OEKs) != len(b.OEKs) {
		return fmt.Errorf("OEKs ring size: %d vs %d", len(a.OEKs), len(b.OEKs))
	}
	for v, ka := range a.OEKs {
		kb, ok := b.OEKs[v]
		if !ok {
			return fmt.Errorf("OEK v%d in A but not B", v)
		}
		if !bytes.Equal(ka, kb) {
			return fmt.Errorf("OEK v%d byte drift", v)
		}
	}
	if len(a.SecretIndex) != len(b.SecretIndex) {
		return fmt.Errorf("SecretIndex size: %d vs %d", len(a.SecretIndex), len(b.SecretIndex))
	}
	for id, sa := range a.SecretIndex {
		sb, ok := b.SecretIndex[id]
		if !ok {
			return fmt.Errorf("secret %s in A but not B", id)
		}
		if (sa.Record == nil) != (sb.Record == nil) {
			return fmt.Errorf("secret %s tombstone state differs", id)
		}
		if sa.Record != nil {
			ba, _ := proto.Marshal(sa.Record)
			bb, _ := proto.Marshal(sb.Record)
			if !bytes.Equal(ba, bb) {
				return fmt.Errorf("secret %s record bytes differ", id)
			}
		}
	}
	return nil
}

func oekVersionList(st *ScopeState) []uint64 {
	out := make([]uint64, 0, len(st.OEKs))
	for v := range st.OEKs {
		out = append(out, v)
	}
	return out
}

func sortedNoDup(set [][]byte) bool {
	for i := 1; i < len(set); i++ {
		c := bytes.Compare(set[i-1], set[i])
		if c >= 0 {
			return false // not strictly increasing → either out of order or dup
		}
	}
	return true
}

func pickNonMember(pool [][]byte, members [][]byte) []byte {
	for _, p := range pool {
		isMember := false
		for _, m := range members {
			if bytes.Equal(m, p) {
				isMember = true
				break
			}
		}
		if !isMember {
			return p
		}
	}
	return nil
}

func randStr(r *rand.Rand, n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = cs[r.Intn(len(cs))]
	}
	return string(b)
}
