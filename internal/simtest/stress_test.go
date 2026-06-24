package simtest

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// TestSimPrimaryStress is a larger, MULTI-SCOPE stress run of primary mode:
// more clients, more servers, several shared scopes (so different scopes
// anchor to different servers), a long faulted schedule, and a hard
// convergence requirement. It exercises primary-per-scope routing across
// many scopes under sustained partition churn — closer to a real fleet
// than the single-scope TestSimPrimaryMode.
//
// Heavier than the other sims; still skipped under -short.
func TestSimPrimaryStress(t *testing.T) {
	if testing.Short() {
		t.Skip("stress: builds binaries + spawns agents; skipped in -short")
	}
	const (
		nClients = 5
		nServers = 3
		nScopes  = 4
		nOps     = 120
	)
	for _, seed := range []int64{7, 99} {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			runStress(t, seed, nClients, nServers, nScopes, nOps)
		})
	}
}

func runStress(t *testing.T, seed int64, nClients, nServers, nScopes, nOps int) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	h := New(t, nServers)
	h.PrimaryMode = true

	names := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace"}
	clients := make([]*Client, nClients)
	for i := range clients {
		clients[i] = h.AddClient(names[i])
	}
	owner := clients[0]
	scopes := make([]string, nScopes)
	for i := range scopes {
		scopes[i] = "scope" + strconv.Itoa(i)
		h.ShareScope(owner, scopes[i], clients[1:]...)
	}

	// Oracle: latest[scope][key] = last value written; written = value set.
	type sk struct{ scope, key string }
	latest := map[sk]string{}
	written := map[sk]map[string]bool{}
	keyOwner := map[sk]int{}
	wc := map[int]int{}

	set := func(ci int) {
		c := clients[ci]
		wc[ci]++
		sc := scopes[rng.Intn(nScopes)]
		key := fmt.Sprintf("K%d_%d", ci, rng.Intn(2))
		val := fmt.Sprintf("c%d-w%d", ci, wc[ci])
		if err := c.Set(sc, key, val); err != nil {
			t.Fatalf("seed %d: set: %v", seed, err)
		}
		k := sk{sc, key}
		latest[k] = val
		if written[k] == nil {
			written[k] = map[string]bool{}
		}
		written[k][val] = true
		keyOwner[k] = ci
	}

	// S4 mid-run monotonicity ("received-then-lost"): once a client has
	// READ a value for a (scope,key), it must never later read an OLDER
	// value or absence. seen[ci][k] = highest write-number ci has read.
	seen := make([]map[sk]int, nClients)
	for i := range seen {
		seen[i] = map[sk]int{}
	}
	observe := func(ci int) {
		c := clients[ci]
		for k := range latest {
			got, ok := c.Get(k.scope, k.key)
			if !ok {
				if seen[ci][k] > 0 {
					t.Fatalf("seed %d: S4 received-then-lost — %s lost %s/%s (had w%d, now absent)",
						seed, c.Name, k.scope, k.key, seen[ci][k])
				}
				continue
			}
			if !written[k][got] {
				t.Fatalf("seed %d: phantom read — %s %s/%s=%q never written", seed, c.Name, k.scope, k.key, got)
			}
			n := writeNum(got)
			if n < seen[ci][k] {
				t.Fatalf("seed %d: S4 received-then-lost — %s regressed %s/%s from w%d to %q",
					seed, c.Name, k.scope, k.key, seen[ci][k], got)
			}
			if n > seen[ci][k] {
				seen[ci][k] = n
			}
		}
	}

	down := 0
	for step := 0; step < nOps; step++ {
		switch rng.Intn(10) {
		case 0, 1, 2, 3:
			set(rng.Intn(nClients))
		case 4, 5, 6:
			ci := rng.Intn(nClients)
			clients[ci].Sync()
			observe(ci)
		case 7, 8:
			si := rng.Intn(nServers)
			s := h.Servers[si]
			if s.IsDown() {
				s.SetDown(false)
				down--
			} else if down < nServers-1 { // never all down
				s.SetDown(true)
				down++
			}
		case 9:
			ci := rng.Intn(nClients)
			set(ci)
			clients[ci].Sync()
			observe(ci)
		}
	}

	// Heal and drive to quiescence (more rounds — bigger fleet).
	for _, s := range h.Servers {
		s.SetDown(false)
	}
	for round := 0; round < 6; round++ {
		for _, c := range clients {
			c.Sync()
		}
	}

	// Safety + convergence: every client reads every key's latest value;
	// owners never lose their own writes; no phantom reads; doctor clean.
	gaps := 0
	var detail []string
	for k, want := range latest {
		for ci, c := range clients {
			got, ok := c.Get(k.scope, k.key)
			if keyOwner[k] == ci && (!ok || got != want) {
				t.Fatalf("seed %d: own-write loss — %s %s/%s=%q want %q", seed, c.Name, k.scope, k.key, got, want)
			}
			if ok && !written[k][got] {
				t.Fatalf("seed %d: phantom read — %s %s/%s=%q never written", seed, c.Name, k.scope, k.key, got)
			}
			if !ok || got != want {
				gaps++
				if len(detail) < 10 {
					detail = append(detail, fmt.Sprintf("%s %s/%s=%q(want %q)", c.Name, k.scope, k.key, got, want))
				}
			}
		}
	}
	for _, c := range clients {
		if out, ok := c.Doctor(); !ok {
			t.Fatalf("seed %d: %s doctor unhealthy:\n%s", seed, c.Name, out)
		}
	}
	if gaps > 0 {
		t.Fatalf("seed %d: %d (client,key) pairs not converged in primary mode; e.g. %s",
			seed, gaps, strings.Join(detail, ", "))
	}
}
