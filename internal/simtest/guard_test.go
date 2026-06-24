package simtest

import (
	"strings"
	"testing"
)

// TestHarnessServersHaveDistinctKeys guards that two in-process servers
// have distinct translog identities. Clients use a single primary, but
// DR-backup replication (server-side) keys its archive by the SOURCE
// server's pubkey, so distinct identities matter — and a shared key would
// silently mask identity bugs.
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
			t.Fatalf("two harness servers share a translog pubkey")
		}
		seen[pub] = true
	}
}

// TestMultiServerConfigIsRejected is the A1 invariant guard: fd0 writes to
// a SINGLE primary. A client configured with more than one server must
// fail its sync loudly — never silently fall back to multi-push (the
// model that diverged in production). The message points the operator at
// the DR-backup path for redundancy.
func TestMultiServerConfigIsRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns agents; skipped in -short")
	}
	h := New(t, 2)
	c := h.AddClientWithServers("alice", h.ServerURLs()) // two servers configured
	out, ok := c.Sync()
	if ok {
		t.Fatalf("sync with 2 configured servers must fail under single-primary, got success:\n%s", out)
	}
	if !strings.Contains(out, "single primary") {
		t.Fatalf("expected a single-primary rejection message, got:\n%s", out)
	}
}
