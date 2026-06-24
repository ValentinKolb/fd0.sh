package simtest

import "testing"

// TestPrimaryModeHeterogeneousConfig closes the review's C3/A1 gap: with
// primary mode, members that configure their [sync].servers in DIFFERENT
// orders must still agree on each scope's primary and converge — because
// the anchor is read from the committed _meta secret, not computed from
// each member's local config. Without the committed anchor (the RED #1
// fix), a local sorted-pubkey computation would still agree on order, but
// this guards that the committed path is what's used and is order-stable.
func TestPrimaryModeHeterogeneousConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns agents; skipped in -short")
	}
	h := New(t, 2)
	h.PrimaryMode = true
	urls := h.ServerURLs()
	rev := []string{urls[1], urls[0]} // reversed order

	alice := h.AddClientWithServers("alice", urls) // [S0, S1]
	bob := h.AddClientWithServers("bob", rev)      // [S1, S0]
	h.ShareScope(alice, "shared", bob)

	if err := alice.Set("shared", "AK", "av"); err != nil {
		t.Fatal(err)
	}
	if err := bob.Set("shared", "BK", "bv"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		alice.Sync()
		bob.Sync()
	}
	for _, c := range []*Client{alice, bob} {
		if v, ok := c.Get("shared", "AK"); !ok || v != "av" {
			t.Errorf("%s AK=%q,%v want av (heterogeneous-order divergence)", c.Name, v, ok)
		}
		if v, ok := c.Get("shared", "BK"); !ok || v != "bv" {
			t.Errorf("%s BK=%q,%v want bv (heterogeneous-order divergence)", c.Name, v, ok)
		}
	}
}

// TestPrimaryModeNoFaults isolates primary-per-scope ROUTING from
// partition handling: 2 servers, 2 clients, primary mode, NO faults.
// Each client writes a key, both sync, both must read both keys. If this
// fails, the routing itself is broken (independent of partitions).
func TestPrimaryModeNoFaults(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns agents; skipped in -short")
	}
	h := New(t, 2)
	h.PrimaryMode = true
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")
	h.ShareScope(alice, "shared", bob)

	if err := alice.Set("shared", "AK", "av"); err != nil {
		t.Fatal(err)
	}
	if err := bob.Set("shared", "BK", "bv"); err != nil {
		t.Fatal(err)
	}
	// Several rounds so both writers push to the scope's primary and both
	// readers pull from it.
	for i := 0; i < 4; i++ {
		alice.Sync()
		bob.Sync()
	}
	for _, c := range []*Client{alice, bob} {
		if v, ok := c.Get("shared", "AK"); !ok || v != "av" {
			t.Errorf("%s AK=%q,%v want av", c.Name, v, ok)
		}
		if v, ok := c.Get("shared", "BK"); !ok || v != "bv" {
			t.Errorf("%s BK=%q,%v want bv", c.Name, v, ok)
		}
	}
}
