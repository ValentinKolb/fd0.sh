package chain

import (
	"os"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// CompactUser keeps only the latest auth.set in path. The local prev_hash
// chain becomes non-contiguous after compaction; verification falls back on
// per-event signatures and the vault tip binding (STORAGE.md §5.4).
//
// Returns true if the file was rewritten.
func CompactUser(path string) (bool, error) {
	events, err := ReadUserEvents(path)
	if err != nil || len(events) <= 1 {
		return false, err
	}
	cb, err := proto.Marshal(events[len(events)-1])
	if err != nil {
		return false, err
	}
	pre, err := fileSizeOf(path)
	if err != nil {
		return false, err
	}
	if int64(len(cb)) >= pre {
		return false, nil
	}
	return true, WriteAll(path, [][]byte{cb})
}

// CompactScope keeps every member.change (so member_set replay stays
// faithful) and every `secret.set` whose event_id is in keepEventIDs.
// Superseded `secret.set`s for the same id are dropped.
//
// Resulting chains are non-contiguous in seq/prev_hash (STORAGE.md §5.4);
// replay tolerates gaps as long as scope_id, signatures, and member-set
// authorisation hold for every kept event.
//
// keepEventIDs must contain the event_ids of the caller's current
// secret_index (post-replay, post-tombstone). Pass nil to keep nothing
// beyond member.change events (rarely useful).
func CompactScope(path string, keepEventIDs map[string]struct{}) (bool, error) {
	events, err := ReadScopeEvents(path)
	if err != nil || len(events) <= 1 {
		return false, err
	}
	keep := make([][]byte, 0, len(events))
	for _, ev := range events {
		switch ev.SignedPrefix.Kind {
		case proto.KindMemberChange:
			// always retained
		case proto.KindSecretSet:
			if keepEventIDs == nil {
				continue
			}
			prefix, _ := ev.PrevHashInput()
			if _, ok := keepEventIDs[proto.EventID(prefix)]; !ok {
				continue
			}
		default:
			continue
		}
		b, err := proto.Marshal(ev)
		if err != nil {
			return false, err
		}
		keep = append(keep, b)
	}
	pre, err := fileSizeOf(path)
	if err != nil {
		return false, err
	}
	total := 0
	for _, k := range keep {
		total += len(k)
	}
	if int64(total) >= pre {
		return false, nil
	}
	return true, WriteAll(path, keep)
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
