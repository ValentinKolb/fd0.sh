package simtest

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// The simulation drives a randomized, seeded schedule of writes, syncs,
// and network partitions across N clients sharing one scope, then heals
// the network and asserts the data-safety invariants that our real bugs
// violated.
//
// Oracle design: each key has a SINGLE fixed writer, so the latest value
// of a key is deterministic (no cross-writer last-writer-wins ambiguity).
// After healing the network and syncing to quiescence we check two tiers:
//
//   - SAFETY (must hold NOW): own-write durability, no phantom/corrupt
//     reads, and `doctor`-clean vaults. These encode "never lose data".
//   - CONVERGENCE (the #2a acceptance target): every client reads every
//     key's latest value. This is NOT guaranteed by today's multi-push /
//     no-gossip model — a writer that reconciles a lagging replica is
//     correctly refused (to avoid dropping foreign data), which also
//     blocks it from updating that replica. The simulation REPORTS this
//     gap today and will REQUIRE it once server-side replication lands.
//
// A failing seed reproduces deterministically — re-run with that seed.

type simConfig struct {
	seed               int64
	clients            int
	servers            int
	ops                int
	scope              string
	primaryMode        bool // [sync].mode = "primary"
	requireConvergence bool // fail (not just report) on a convergence gap
}

func runSim(t *testing.T, cfg simConfig) {
	t.Helper()
	rng := rand.New(rand.NewSource(cfg.seed))
	h := New(t, cfg.servers)
	h.PrimaryMode = cfg.primaryMode

	clients := make([]*Client, cfg.clients)
	names := []string{"alice", "bob", "carol", "dave", "erin", "frank"}
	for i := range clients {
		clients[i] = h.AddClient(names[i])
	}
	owner := clients[0]
	h.ShareScope(owner, cfg.scope, clients[1:]...)

	// Each client owns a disjoint set of keys (single-writer-per-key).
	// latest[key] is the oracle (last value written); writtenVals[key] is
	// every value ever written to it (to catch phantom/corrupt reads);
	// keyOwner[key] is the writing client index (own-write durability).
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

	// Monotonic-read oracle (S4): once a client has READ a given value
	// for a key, it must never later read an OLDER value or absence for
	// that key. This is the precise "received-then-lost" safety property
	// — exactly what the F1 foreign-event fix exists to guarantee — and
	// it requires MID-RUN observation (the prior oracle only looked at
	// the end). seen[ci][key] is the highest write-number ci has read.
	seen := make([]map[string]int, cfg.clients)
	for i := range seen {
		seen[i] = map[string]int{}
	}
	// observe reads every known key for client ci and enforces S2 (no
	// phantom value) + S4 (no regression). Called after each of ci's
	// syncs and again in the final check.
	observe := func(ci int) {
		c := clients[ci]
		for key := range latest {
			got, ok := c.Get(cfg.scope, key)
			if !ok {
				if seen[ci][key] > 0 {
					t.Fatalf("seed %d: SAFETY S4 (received-then-lost) — %s lost %s entirely "+
						"(had w%d, now absent)\nreproduce: go test ./internal/simtest -run 'TestSimSeeds/seed=%d' -count=1 -v",
						cfg.seed, c.Name, key, seen[ci][key], cfg.seed)
				}
				continue
			}
			if !writtenVals[key][got] {
				t.Fatalf("seed %d: SAFETY S2 (phantom/corrupt read) — %s reads %s=%q, never written\n"+
					"reproduce: go test ./internal/simtest -run 'TestSimSeeds/seed=%d' -count=1 -v",
					cfg.seed, c.Name, key, got, cfg.seed)
			}
			n := writeNum(got)
			if n < seen[ci][key] {
				t.Fatalf("seed %d: SAFETY S4 (received-then-lost) — %s regressed %s from w%d to %q\n"+
					"reproduce: go test ./internal/simtest -run 'TestSimSeeds/seed=%d' -count=1 -v",
					cfg.seed, c.Name, key, seen[ci][key], got, cfg.seed)
			}
			if n > seen[ci][key] {
				seen[ci][key] = n
			}
		}
	}

	// Track how many servers are currently partitioned; never down ALL.
	downCount := 0

	for step := 0; step < cfg.ops; step++ {
		switch rng.Intn(10) {
		case 0, 1, 2, 3: // write (40%)
			set(rng.Intn(cfg.clients))
		case 4, 5, 6: // sync a random client (30%)
			ci := rng.Intn(cfg.clients)
			clients[ci].Sync()
			observe(ci) // S2/S4 at every mid-run observation point
		case 7, 8: // toggle a partition (20%), keeping >=1 server up
			si := rng.Intn(cfg.servers)
			s := h.Servers[si]
			if s.IsDown() {
				s.SetDown(false)
				downCount--
			} else if downCount < cfg.servers-1 {
				s.SetDown(true)
				downCount++
			}
		case 9: // a writer writes then immediately syncs (10%)
			ci := rng.Intn(cfg.clients)
			set(ci)
			clients[ci].Sync()
			observe(ci)
		}
	}

	// ── Heal everything and drive to quiescence ──────────────────────
	for _, s := range h.Servers {
		s.SetDown(false)
	}
	// Each writer must push its own events to every (now-healed) server,
	// and each reader must pull. Multi-push means clients ARE the
	// propagation, so a few full rounds converge the fleet.
	for round := 0; round < 4; round++ {
		for _, c := range clients {
			c.Sync()
		}
	}

	// ── SAFETY invariants (MUST hold on the current architecture) ────
	// These encode the prime directive ("never lose data"). A violation
	// here is a real bug and fails the test.
	//
	// S1 — own-write durability: a writer always reads its own keys as
	//      its own latest value. The reconcile rebuild + transactional
	//      rollback must never drop a client's own authored write.
	// S2 — no phantom/corruption: any value read was actually written.
	// S3 — fail-safe: every client's vault passes `doctor` after an
	//      arbitrary faulted run.
	// S4 — received-then-lost: a client never regresses a key it has read
	//      (enforced continuously by observe, above + here).
	for ci := range clients {
		observe(ci) // final S2/S4 pass
	}
	convergenceGaps := 0
	var gapDetail []string
	for key, want := range latest {
		for ci, c := range clients {
			got, ok := c.Get(cfg.scope, key)
			// S1: the owning writer must read its own latest value.
			if keyOwner[key] == ci {
				if !ok || got != want {
					t.Fatalf("seed %d: SAFETY S1 (own-write loss) — writer %s reads its own %s=%q (ok=%v), want %q\n"+
						"reproduce: go test ./internal/simtest -run 'TestSimSeeds/seed=%d' -count=1 -v",
						cfg.seed, c.Name, key, got, ok, want, cfg.seed)
				}
			}
			// Convergence (not safety): a reader seeing a stale/absent
			// foreign value. Counted, not fatal — see below.
			if !ok || got != want {
				convergenceGaps++
				if len(gapDetail) < 8 {
					gapDetail = append(gapDetail, fmt.Sprintf("%s %s=%q(want %q)", c.Name, key, got, want))
				}
			}
		}
	}
	// S3: fail-safe — no corruption after the faulted run.
	for _, c := range clients {
		if out, ok := c.Doctor(); !ok {
			t.Fatalf("seed %d: SAFETY S3 (corruption) — %s doctor unhealthy:\n%s", cfg.seed, c.Name, out)
		}
	}

	// ── CONVERGENCE invariant (the #2a ACCEPTANCE TARGET) ────────────
	// Full cross-client convergence (every client reads every key's
	// latest value) is NOT guaranteed by the current multi-push /
	// no-gossip model: a writer that reconciles a lagging replica is
	// (correctly) refused to avoid dropping foreign data, which also
	// blocks it from updating that replica — so a reader can miss the
	// value. This is the gap server-side replication (#2a) closes.
	//
	// We therefore REPORT the gap rather than fail. Once #2a lands,
	// flip requireConvergence to true: it becomes the acceptance test
	// proving replication makes the fleet converge.
	if convergenceGaps > 0 {
		msg := fmt.Sprintf("seed %d: convergence gap — %d (client,key) pairs not converged; e.g. %v",
			cfg.seed, convergenceGaps, gapDetail)
		if cfg.requireConvergence {
			t.Fatalf("%s — primary-per-scope mode must converge fully\n"+
				"reproduce: go test ./internal/simtest -run 'TestSimPrimaryMode/seed=%d' -count=1 -v",
				msg, cfg.seed)
		}
		t.Logf("%s (expected on multi-push; safety invariants all held)", msg)
	}
}

// writeNum parses the per-writer sequence number out of a value of the
// form "c<ci>-w<n>" (set() above). Returns -1 if the value is not in
// that shape, which observe() treats as a phantom-read failure.
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

// TestSimSeeds runs the simulation across several seeds. Each seed is an
// independent randomized history; a failure names the seed for replay.
func TestSimSeeds(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation builds binaries + spawns agents; skipped in -short")
	}
	seeds := []int64{1, 2, 3, 42, 1337}
	for _, seed := range seeds {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			runSim(t, simConfig{
				seed:    seed,
				clients: 3,
				servers: 2,
				ops:     40,
				scope:   "shared",
			})
		})
	}
}

// TestSimPrimaryMode is the #2a acceptance test: with primary-per-scope
// routing enabled, the fleet must FULLY converge (every client reads every
// key's latest value) under the same faulted schedules that leave a
// convergence gap in multi-push mode. requireConvergence makes a gap fatal.
func TestSimPrimaryMode(t *testing.T) {
	if testing.Short() {
		t.Skip("simulation builds binaries + spawns agents; skipped in -short")
	}
	seeds := []int64{1, 2, 3, 42, 1337}
	for _, seed := range seeds {
		seed := seed
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			runSim(t, simConfig{
				seed:               seed,
				clients:            3,
				servers:            2,
				ops:                40,
				scope:              "shared",
				primaryMode:        true,
				requireConvergence: true,
			})
		})
	}
}
