package simtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
	"testing"
)

// anchorIndexTest mirrors the production anchorIndex (sync_primary.go) so
// the test can compute which server a scope is anchored to.
func anchorIndexTest(scopeID string, n int) int {
	h := sha256.Sum256([]byte(scopeID))
	return int(binary.BigEndian.Uint64(h[:8]) % uint64(n))
}

// TestPrimaryModeMissingAnchorFailsLoud is the DETERMINISTIC sensitivity
// test for the missing-anchor hard error (review blind spot: the
// integration script's Part C only triggered by chance). A member that
// has a scope but whose [sync].servers no longer contains that scope's
// committed primary must FAIL LOUD on sync — never silently "succeed".
//
// We compute the scope's anchor from the server pubkeys + scope_id, then
// reconfigure the client to EXCLUDE exactly that server, and assert sync
// surfaces the error.
func TestPrimaryModeMissingAnchorFailsLoud(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns agents; skipped in -short")
	}
	h := New(t, 2)
	h.PrimaryMode = true
	alice := h.AddClient("alice")
	dave := h.AddClient("dave")
	h.ShareScope(alice, "shared", dave)
	dave.Sync() // dave now holds the scope + reads its committed anchor

	ids := dave.ScopeIDs()
	if len(ids) != 1 {
		t.Fatalf("expected exactly one scope, got %v", ids)
	}
	scopeID := ids[0]

	// Determine the anchor server for this scope (sorted pubkeys, indexed).
	pubs := [][]byte{
		[]byte(h.Servers[0].srv.Store().TranslogPub()),
		[]byte(h.Servers[1].srv.Store().TranslogPub()),
	}
	sort.Slice(pubs, func(i, j int) bool { return bytes.Compare(pubs[i], pubs[j]) < 0 })
	anchorPub := pubs[anchorIndexTest(scopeID, 2)]
	var otherURL string
	for _, s := range h.Servers {
		if !bytes.Equal([]byte(s.srv.Store().TranslogPub()), anchorPub) {
			otherURL = s.URL
		}
	}

	// Reconfigure dave to EXCLUDE the anchor server, then sync.
	dave.SetServers([]string{otherURL})
	out, ok := dave.Sync()
	if ok || !strings.Contains(out, "not in your [sync].servers") {
		t.Fatalf("missing-anchor must fail loud; got ok=%v out=%q", ok, out)
	}
}

// TestHarnessServersHaveDistinctKeys guards against the harness bug that
// once silently disabled primary-per-scope routing: two in-process servers
// sharing a translog key (same default key path) made them
// indistinguishable, so anchor selection (which keys on the pubkey)
// collapsed and tests passed for the wrong reason. Each server MUST have a
// distinct translog identity.
func TestHarnessServersHaveDistinctKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("New builds binaries; skipped in -short")
	}
	h := New(t, 3)
	seen := map[string]bool{}
	for _, s := range h.Servers {
		pub := string(s.srv.Store().TranslogPub())
		if pub == "" {
			t.Fatalf("server %s has no translog pubkey", s.Label)
		}
		if seen[pub] {
			t.Fatalf("two harness servers share a translog pubkey — primary routing would be untestable")
		}
		seen[pub] = true
	}
}
