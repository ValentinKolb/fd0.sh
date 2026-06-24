package simtest

import (
	"fmt"
	"testing"
)

// TestSinglePrimarySameKeyConverges covers concurrent writes to the SAME
// key by DIFFERENT members against one primary. Two members repeatedly
// write the same key without syncing in between, so their local chains
// differ on that key; after syncing to quiescence ALL members must agree
// on ONE value, and it must be one that was actually written (no
// split-brain, no phantom).
func TestSinglePrimarySameKeyConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns agents; skipped in -short")
	}
	h := New(t, 1)
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")
	h.ShareScope(alice, "shared", bob)

	written := map[string]bool{}
	for i := 0; i < 5; i++ {
		// Both write the SAME key before either syncs -> contention.
		av := fmt.Sprintf("a%d", i)
		bv := fmt.Sprintf("b%d", i)
		if err := alice.Set("shared", "K", av); err != nil {
			t.Fatal(err)
		}
		if err := bob.Set("shared", "K", bv); err != nil {
			t.Fatal(err)
		}
		written[av] = true
		written[bv] = true
		alice.Sync()
		bob.Sync()
	}
	for i := 0; i < 4; i++ {
		alice.Sync()
		bob.Sync()
	}

	av, aok := alice.Get("shared", "K")
	bv, bok := bob.Get("shared", "K")
	if !aok || !bok {
		t.Fatalf("contended key missing: alice ok=%v, bob ok=%v", aok, bok)
	}
	if av != bv {
		t.Fatalf("no agreement on contended key K: alice=%q bob=%q (split-brain)", av, bv)
	}
	if !written[av] {
		t.Fatalf("converged value %q for K was never written (phantom)", av)
	}
	for _, c := range []*Client{alice, bob} {
		if out, ok := c.Doctor(); !ok {
			t.Fatalf("%s doctor unhealthy:\n%s", c.Name, out)
		}
	}
}
