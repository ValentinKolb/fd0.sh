package simtest

import "testing"

// TestHarnessSmoke validates the harness itself end to end: build the
// binaries, stand up two in-process servers, init two clients, share a
// scope, write + sync + read across both clients. If this passes, the
// harness faithfully drives the real stack and the seeded simulation
// (sim_test.go) can rely on it.
func TestHarnessSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}
	h := New(t, 2)
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")

	h.ShareScope(alice, "shared", bob)

	if err := alice.Set("shared", "K", "v1"); err != nil {
		t.Fatal(err)
	}
	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice sync failed:\n%s", out)
	}
	if out, ok := bob.Sync(); !ok {
		t.Fatalf("bob sync failed:\n%s", out)
	}
	if got, ok := bob.Get("shared", "K"); !ok || got != "v1" {
		t.Fatalf("bob Get K = %q,%v; want v1,true", got, ok)
	}

	// Partition server 0, write again, sync (degraded), heal, converge.
	h.Servers[0].SetDown(true)
	if err := alice.Set("shared", "K", "v2"); err != nil {
		t.Fatal(err)
	}
	alice.Sync() // degraded: server0 down, server1 ok — still exits 0
	h.Servers[0].SetDown(false)
	alice.Sync()
	bob.Sync()
	if got, ok := bob.Get("shared", "K"); !ok || got != "v2" {
		t.Fatalf("after heal bob Get K = %q,%v; want v2,true", got, ok)
	}
}
