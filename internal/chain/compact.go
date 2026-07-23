package chain

import (
	"fmt"
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

// CompactScope is disabled in v1. Removing signed events creates a local
// sequence gap that is not authenticated by the vault tip and can hide a newer
// secret while retaining the real final event. Sync repairs files produced by
// older versions from the server's full, transparency-verified history.
func CompactScope(path string, state *ScopeState) (rewritten bool, dropped []string, err error) {
	return false, nil, fmt.Errorf("chain.CompactScope is disabled in v1: compacting %s would create unauthenticated history gaps", path)
}
