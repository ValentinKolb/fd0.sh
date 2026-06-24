package simtest

import (
	"testing"
	"time"
)

// TestPostCommitLossIsIdempotent covers the "accepted but un-acked" failure
// (review blind spot: the fault model only did full partitions). The
// server COMMITS a pushed event but the response never reaches the client;
// the client must treat it as a failure, re-push on the next sync, and the
// server must dedup idempotently — no lost write, no duplicate, no
// corruption. This exercises the dup/idempotency path the v0.4.x reconcile
// work relies on, which had no fault-injection test.
func TestPostCommitLossIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns agents; skipped in -short")
	}
	h := New(t, 1)
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")
	h.ShareScope(alice, "shared", bob)

	if err := alice.Set("shared", "K", "v1"); err != nil {
		t.Fatal(err)
	}

	// The server processes the push (commits) but the ack is dropped.
	h.Servers[0].SetFault(FaultPostCommit)
	alice.Sync() // "fails" from alice's view — the server actually has it
	h.Servers[0].SetFault(FaultNone)

	// Recovery: alice re-pushes (server dedups), bob pulls. Converge.
	for i := 0; i < 3; i++ {
		alice.Sync()
		bob.Sync()
	}

	if v, ok := alice.Get("shared", "K"); !ok || v != "v1" {
		t.Fatalf("alice lost her own write after post-commit-loss: %q,%v", v, ok)
	}
	if v, ok := bob.Get("shared", "K"); !ok || v != "v1" {
		t.Fatalf("bob did not receive the committed-but-unacked value: %q,%v", v, ok)
	}
	for _, c := range []*Client{alice, bob} {
		if out, ok := c.Doctor(); !ok {
			t.Fatalf("%s doctor unhealthy after post-commit-loss:\n%s", c.Name, out)
		}
	}
}

// TestServer429DoesNotHangAndRecovers covers an HTTP error status (vs. a
// transport partition): when the server replies 429 to everything, the
// client must fail gracefully within a bounded time (the signedPOST /
// registration backoff is bounded), not hang or crash, and must recover
// once the server is healthy — without losing local writes.
func TestServer429DoesNotHangAndRecovers(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns agents; skipped in -short")
	}
	h := New(t, 1)
	alice := h.AddClient("alice")
	h.ShareScope(alice, "shared")
	if err := alice.Set("shared", "K", "v"); err != nil {
		t.Fatal(err)
	}

	h.Servers[0].SetFault(Fault429)
	start := time.Now()
	alice.Sync() // may fail; must return within the bounded backoff
	if d := time.Since(start); d > 2*time.Minute {
		t.Fatalf("429 sync hung for %v (backoff not bounded)", d)
	}
	// Local write is never lost regardless of server status.
	if v, ok := alice.Get("shared", "K"); !ok || v != "v" {
		t.Fatalf("local write lost during 429: %q,%v", v, ok)
	}

	h.Servers[0].SetFault(FaultNone)
	alice.Sync()
	if out, ok := alice.Doctor(); !ok {
		t.Fatalf("alice doctor unhealthy after 429 recovery:\n%s", out)
	}
}
