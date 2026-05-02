package chain

import (
	"fmt"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// CompactUser is currently DISABLED.
//
// Codex audit (🟡 chain/compact.go:15): the original implementation
// rewrote user.cbor to the latest event, but ReplayUser requires
// events[0].Seq == 0 (chain/user.go:37) — any compacted non-genesis
// user chain becomes unreplayable, locking the user out of their
// own vault. There is no caller of this function in v1, so we keep
// the symbol but make it a loud error to prevent future callers
// from re-introducing the bug. Compaction support for the user
// chain is reserved for v2 once a "compacted prefix" segment with
// a verifiable hash of replaced ops is specified (TODO.md).
func CompactUser(path string) (bool, error) {
	return false, fmt.Errorf("chain.CompactUser is disabled in v1: ReplayUser requires events[0].Seq==0; compacting %s would orphan the chain", path)
}

// CompactScope rewrites path to drop superseded secret.set events.
// Keeps every member.change (so member_set replay stays faithful) and
// every secret.set whose event_id appears in state.SecretIndex with a
// non-empty EventID (= the post-replay authoritative live set).
//
// Resulting chains are non-contiguous in seq/prev_hash (STORAGE.md §5.4);
// replay tolerates gaps as long as scope_id, signatures, and member-set
// authorisation hold for every kept event.
//
// Safety contract — refused with error rather than silently lose data:
//   - state.SecretIndex must reference every secret-set event_id we
//     intend to keep. We assert that every non-empty EventID in
//     state.SecretIndex is actually present in the chain file before
//     dropping anything.
//   - state must be the post-replay state of THIS chain file. The
//     caller is responsible (a stale snapshot would let us drop a
//     still-referenced event); we mitigate via the EventID-presence
//     check above.
//
// Observability: returns the event_ids of dropped secret.sets in chain
// order so the caller can log what was compacted (sync prints a count;
// doctor could surface unexpected drops).
//
// Returns:
//   - rewritten == true iff the file was actually rewritten (= the new
//     contents are smaller than the old).
//   - dropped: event_ids of every removed secret.set, in chain order.
//   - err: I/O error, contract violation, or marshal failure.
//
// Calling with state == nil compacts to "member.changes only" (rarely
// useful — callers should pass real state).
func CompactScope(path string, state *ScopeState) (rewritten bool, dropped []string, err error) {
	events, err := ReadScopeEvents(path)
	if err != nil || len(events) <= 1 {
		return false, nil, err
	}
	live := map[string]struct{}{}
	if state != nil {
		for _, cur := range state.SecretIndex {
			if cur.EventID != "" {
				live[cur.EventID] = struct{}{}
			}
		}
	}
	// Enforce safety contract: every live EventID must be present in
	// the chain file. If not, the snapshot is stale relative to the
	// file (e.g. caller racing another writer). Refuse rather than
	// drop a referenced event silently.
	if len(live) > 0 {
		fileIDs := map[string]struct{}{}
		for _, ev := range events {
			if ev.SignedPrefix.Kind != proto.KindSecretSet {
				continue
			}
			prefix, _ := ev.PrevHashInput()
			fileIDs[proto.EventID(prefix)] = struct{}{}
		}
		for id := range live {
			if _, ok := fileIDs[id]; !ok {
				return false, nil, fmt.Errorf("compact %s: live event_id %s not in chain file (stale snapshot?)", path, id)
			}
		}
	}
	keep := make([][]byte, 0, len(events))
	dropped = nil
	for _, ev := range events {
		switch ev.SignedPrefix.Kind {
		case proto.KindMemberChange:
			// Always retained — member_set integrity depends on it.
		case proto.KindSecretSet:
			prefix, _ := ev.PrevHashInput()
			id := proto.EventID(prefix)
			if _, isLive := live[id]; !isLive {
				dropped = append(dropped, id)
				continue
			}
		default:
			// Unknown kinds: drop and report. Replay would have rejected
			// them anyway, but treating them as "drop" keeps the file
			// usable.
			prefix, _ := ev.PrevHashInput()
			dropped = append(dropped, proto.EventID(prefix))
			continue
		}
		b, err := proto.Marshal(ev)
		if err != nil {
			return false, nil, err
		}
		keep = append(keep, b)
	}
	pre, err := fileSizeOf(path)
	if err != nil {
		return false, nil, err
	}
	total := 0
	for _, k := range keep {
		total += len(k)
	}
	if int64(total) >= pre {
		// Compaction wouldn't actually shrink — leave the file as-is.
		// Returning dropped=nil here matches "nothing changed".
		return false, nil, nil
	}
	if err := WriteAll(path, keep); err != nil {
		return false, nil, err
	}
	return true, dropped, nil
}

// fileSizeOf returns the size of path or 0 if missing.
func fileSizeOf(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return st.Size(), nil
}
