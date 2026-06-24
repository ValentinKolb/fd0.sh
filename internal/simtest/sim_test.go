package simtest

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// The simulation drives a randomized, seeded schedule of writes, syncs,
// and transient primary outages across N clients sharing one scope
// against a SINGLE primary server (model A1), then heals and asserts the
// data-safety invariants plus full convergence.
//
// Why single-primary: with exactly one ordering authority per scope,
// replica divergence is impossible by construction — the failure class
// that bit production (api/api2 forked under multi-push) cannot occur.
// The sim proves the REAL binaries converge and never lose a write under
// faults.
//
// Oracle: each key has a SINGLE fixed writer, so the latest value of a
// key is deterministic. Invariants checked:
//
//	S1 own-write durability · S2 no phantom/corrupt read ·
//	S3 doctor-clean vaults · S4 received-then-lost monotonicity
//	(continuous) · CONVERGENCE — every client reads every key's latest
//	value (REQUIRED: one authority must converge the fleet).
//
// A failing seed reproduces deterministically — re-run with that seed.

type simConfig struct {
	seed    int64
	clients int
	ops     int
	scope   string
}

func runSim(t *testing.T, cfg simConfig) {
	t.Helper()
	rng := rand.New(rand.NewSource(cfg.seed))
	h := New(t, 1) // single primary (A1)
	srv := h.Servers[0]

	clients := make([]*Client, cfg.clients)
	names := []string{"alice", "bob", "carol", "dave", "erin", "frank"}
	for i := range clients {
		clients[i] = h.AddClient(names[i])
	}
	owner := clients[0]
	h.ShareScope(owner, cfg.scope, clients[1:]...)

	// Each client owns a disjoint set of keys (single-writer-per-key).
	latest := map[string]string{}
	writtenVals := map[string]map[string]bool{}
	keyOwner := map[string]int{}
	writeCount := map[int]int{}

	set := func(ci int) {
		c := clients[ci]
		writeCount[ci]++
		key := fmt.Sprintf("K%d_%d", ci, rng.Intn(3)) // 3 keys per writer
		val := fmt.Sprintf("c%d-w%d", ci, writeCount[ci])
		if err := c.Set(cfg.scope, key, val); err != nil {
			t.Fatalf("seed %d: %v", cfg.seed, err)
		}
		latest[key] = val
		if writtenVals[key] == nil {
			writtenVals[key] = map[string]bool{}
		}
		writtenVals[key][val] = true
		keyOwner[key] = ci
	}

	// Monotonic-read oracle (S4): once a client has READ a value for a key,
	// it must never later read an OLDER value or absence for that key.
	seen := make([]map[string]int, cfg.clients)
	for i := range seen {
		seen[i] = map[string]int{}
	}
	observe := func(ci int) {
		c := clients[ci]
		for key := range latest {
			got, ok := c.Get(cfg.scope, key)
			if !ok {
				if seen[ci][key] > 0 {
					t.Fatalf("seed %d: SAFETY S4 (received-then-lost) — %s lost %s entirely (had w%d, now absent)\n"+
						"reproduce: go test ./internal/simtest -run 'TestSimSinglePrimary/seed=%d' -count=1 -v",
						cfg.seed, c.Name, key, seen[ci][key], cfg.seed)
				}
				continue
			}
			if !writtenVals[key][got] {
				t.Fatalf("seed %d: SAFETY S2 (phantom/corrupt read) — %s reads %s=%q, never written\n"+
					"reproduce: go test ./internal/simtest -run 'TestSimSinglePrimary/seed=%d' -count=1 -v",
					cfg.seed, c.Name, key, got, cfg.seed)
			}
			n := writeNum(got)
			if n < seen[ci][key] {
				t.Fatalf("seed %d: SAFETY S4 (received-then-lost) — %s regressed %s from w%d to %q\n"+
					"reproduce: go test ./internal/simtest -run 'TestSimSinglePrimary/seed=%d' -count=1 -v",
					cfg.seed, c.Name, key, seen[ci][key], got, cfg.seed)
			}
			if n > seen[ci][key] {
				seen[ci][key] = n
			}
		}
	}

	for step := 0; step < cfg.ops; step++ {
		switch rng.Intn(10) {
		case 0, 1, 2, 3: // write (40%)
			set(rng.Intn(cfg.clients))
		case 4, 5, 6: // sync a random client (30%)
			ci := rng.Intn(cfg.clients)
			clients[ci].Sync()
			observe(ci) // S2/S4 at every mid-run observation point
		case 7, 8: // transient primary outage (20%): sync fails while down,
			// local reads still work; healed before the final rounds.
			srv.SetDown(!srv.IsDown())
		case 9: // a writer writes then immediately syncs (10%)
			ci := rng.Intn(cfg.clients)
			set(ci)
			clients[ci].Sync()
			observe(ci)
		}
	}

	// ── Heal the primary and drive to quiescence ─────────────────────
	srv.SetDown(false)
	for round := 0; round < 4; round++ {
		for _, c := range clients {
			c.Sync()
		}
	}

	// ── SAFETY + CONVERGENCE (all REQUIRED under single-primary) ─────
	for ci := range clients {
		observe(ci) // final S2/S4 pass
	}
	for key, want := range latest {
		for ci, c := range clients {
			got, ok := c.Get(cfg.scope, key)
			// S1: the owning writer must read its own latest value.
			if keyOwner[key] == ci && (!ok || got != want) {
				t.Fatalf("seed %d: SAFETY S1 (own-write loss) — writer %s reads its own %s=%q (ok=%v), want %q\n"+
					"reproduce: go test ./internal/simtest -run 'TestSimSinglePrimary/seed=%d' -count=1 -v",
					cfg.seed, c.Name, key, got, ok, want, cfg.seed)
			}
			// CONVERGENCE: with one authority every reader must see latest.
			if !ok || got != want {
				t.Fatalf("seed %d: CONVERGENCE — single primary must converge, but %s reads %s=%q want %q\n"+
					"reproduce: go test ./internal/simtest -run 'TestSimSinglePrimary/seed=%d' -count=1 -v",
					cfg.seed, c.Name, key, got, want, cfg.seed)
			}
		}
	}
	for _, c := range clients {
		if out, ok := c.Doctor(); !ok {
			t.Fatalf("seed %d: SAFETY S3 (corruption) — %s doctor unhealthy:\n%s", cfg.seed, c.Name, out)
		}
	}
}

// writeNum parses the per-writer sequence number out of a value of the
// form "c<ci>-w<n>" (set() above). Returns -1 if the value is not in that
// shape, which observe() treats as a phantom-read failure.
func writeNum(val string) int {
	i := strings.LastIndex(val, "-w")
	if i < 0 {
		return -1
	}
	n, err := strconv.Atoi(val[i+2:])
	if err != nil {
		return -1
	}
	return n
}

// TestSimSinglePrimary runs the A1 simulation across several seeds. Each
// seed is an independent randomized history with transient primary
// outages; the fleet must always converge and never lose data.
func TestSimSinglePrimary(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation builds binaries + spawns agents; skipped in -short")
	}
	for _, seed := range []int64{1, 2, 3, 42, 1337} {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			runSim(t, simConfig{seed: seed, clients: 3, ops: 40, scope: "shared"})
		})
	}
}
