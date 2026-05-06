# fd0 performance baseline

Snapshot of where fd0 performance sits on a developer machine, taken
2026-05-06 against the post-Wave-E codebase. Used as a regression
target — a future commit that pushes any of these numbers >25% in
the wrong direction wants explicit justification.

**Hardware**: Apple M1 Max, macOS, single-threaded.
**Reproduce**:

```sh
go test -bench=. -benchmem -benchtime=2s -run=^$ \
    ./internal/server/store ./internal/chain ./internal/vault
```

## Server-side translog (`internal/server/store`)

The hot path on every `/sync` push: SQLite-backed incremental Merkle
tree with per-leaf signature.

| Operation                  | Depth |     ns/op |   B/op | allocs |   ops/sec |
|----------------------------|------:|----------:|-------:|-------:|----------:|
| `AppendLeaf` cold          |     0 |   540 081 |  8 760 |    235 |     ~1850 |
| `AppendLeaf` warm          |  1 000 |   615 104 |  8 911 |    239 |     ~1625 |
| `AppendLeaf` warm          | 10 000 | 1 010 664 |  9 501 |    256 |      ~990 |
| `InclusionProofFor`        |  1 000 |   144 320 |  7 580 |    198 |     ~6930 |
| `InclusionProofFor`        | 10 000 |   793 590 |  7 610 |    200 |     ~1260 |
| `ConsistencyProofFor`      |  1 000 |   189 301 | 12 023 |    306 |     ~5285 |
| `ConsistencyProofFor`      | 10 000 |   857 845 | 13 635 |    351 |     ~1166 |

### Notes

- **AppendLeaf** scales sub-linearly with depth. Cold→1k is +14% (one
  cached SQLite plan amortised); 1k→10k is +64% (B-tree index walks
  start to cost real time on the leaves table).
- The 10k figure (~1ms / append) bounds throughput at ~1000 push/sec
  per chain on a single machine. Multi-chain throughput is higher
  because each chain has its own incremental-tree state and the
  store doesn't hold a global lock per append.
- **Inclusion proofs** at 10k take ~5.5× the 1k cost despite path
  length only growing 1.3×. That's SQL row-lookup overhead — at
  small N the index fits in cache, at 10k it spills. A future
  optimisation candidate IF push verification ever becomes a
  bottleneck.
- **Consistency proofs** track inclusion proofs closely (same
  underlying tree-frontier walk).

### Extrapolation to 1M leaves

I did not benchmark 1M directly because the pre-fill setup was
~10 minutes and we don't yet have a deployment that needs it.
Linear extrapolation from the AppendLeaf trend (1k → 10k = +64%)
suggests 1M would land around 2–3 ms/op — ~400 leaves/sec sustained.
That's enough headroom for ≤100k events/day per scope without
sweat; it's NOT enough for write-heavy multi-tenant workloads
without sharding the store.

## Client-side scope replay (`internal/chain`)

Run on every CLI command that touches a scope. Reads the chain file,
re-verifies every signature, applies every event to the running
state.

| Operation                |  Events |       ns/op |   B/op | allocs | per-event |
|--------------------------|--------:|------------:|-------:|-------:|----------:|
| `ReplayScope`            |     100 |   5 648 189 | 808 130 |  8 750 |    56 µs  |
| `ReplayScope`            |   1 000 |  55 514 122 |   8 MiB | 86 928 |    55 µs  |
| `ReplayScope`            |  10 000 | 555 139 028 |  80 MiB | 870 036 |    56 µs  |
| `AppendScope`            |       — |   5 959 800 |  4 881 |     28 |   ~6 ms   |

### Notes

- Replay is **perfectly linear**. ~56 µs per event regardless of
  chain depth — the per-event cost is dominated by ed25519
  signature verify (~30 µs) plus CBOR decode + AAD construction.
- Implication: at **10 000 events per scope, every CLI command
  takes ~555 ms** of replay before doing anything. STORAGE.md §5
  compaction is the answer; CompactScope thresholds should
  trigger well before this point in production.
- Allocation cost is steep — 870k allocs for a 10k-event replay
  (87 allocs/event). Most are CBOR decode buffers. Halving this
  would halve replay wall-time. Optimisation candidate IF replay
  ever shows up in user-perceived latency profiling.
- `AppendScope` is ~6 ms because of the per-event fsync. Going to
  unbuffered group-commit would help integration-test throughput
  but compromises the crash-consistency story for real users
  (current per-event fsync is correct).

## Vault unlock (`internal/vault`)

User-facing latency: every `fd0 unlock` and every CLI command
that opens the vault hits this path.

| Operation                  |        ns/op |    B/op | allocs |   wall   |
|----------------------------|-------------:|--------:|-------:|----------|
| `Open` (passphrase wrap)   |  146 579 485 | 67 MiB  |     76 |  ~147 ms |
| `DeriveKey` (Argon2id only)|  141 913 092 | 67 MiB  |     31 |  ~142 ms |
| `Save` (no KDF, just AEAD) |   12 553 659 |   6 KiB |     34 |   ~13 ms |

### Notes

- **`Open` is dominated by Argon2id**. The KDF alone takes 142 ms;
  the rest of `Open` (AEAD body decrypt + CBOR decode + magic /
  version checks) is ~5 ms — negligible by design.
- The 67 MiB allocation is **on-spec**: `crypto.DefaultArgon2 =
  Argon2Params{M: 64*1024 KiB, T: 3, P: 1}`. The benchmark sanity-
  checks that nobody accidentally weakens M.
- **`Save` is ~13 ms** (no KDF — only AEAD-reseal + fsync). This is
  the cost on every state mutation (every secret.set, every
  member.change after replay-and-vault-update).
- A 150 ms unlock is generous on modern hardware but absolutely
  visible to the user. If we ever want to go below this, options
  are: lower memory cost (security regression), agent-cache the
  payload key (already done — agent unlocks once, holds for the
  session), or move to interactive-TUI feedback ("KDF in progress").
  The current architecture (agent + once-per-session unlock) makes
  this latency acceptable.

## What this catches

- **Argon2 weakening**: any commit that drops M below 64 MiB will
  show `BenchmarkVaultDeriveKeyOnly` allocate <67 MiB and run
  faster. Codex audit guard.
- **Replay cost regression**: a future change that doubles
  per-event allocations would push 10k replay from 555 ms to ~1 s
  — a clear signal in CI bench drift.
- **AppendLeaf O(n²)**: if a future schema change adds an
  unbounded SELECT in the append path, the warm-10k figure would
  blow past linear; compare against the warm-1k baseline.
- **Index loss**: dropping the SQLite leaves index would push
  inclusion-proof at 10k from <1 ms to >>10 ms.

## Not covered (defer to v1.x bench-pass)

- **End-to-end sync wall-time** (multi-scope, multi-event): would
  need a stable test server harness and `hyperfine` against the
  actual `fd0` binary. Skipped for v1.0; the per-component numbers
  give upper bounds.
- **Multi-tenant translog throughput** (concurrent push from N
  clients): single-threaded numbers above bound the lower limit.
- **1M-leaf translog**: pre-fill takes ~10 minutes; not reproduced
  here. Linear extrapolation in the table above.
- **Memory under load** on the server side — the SQLite store
  doesn't pre-load the chain into memory, so steady-state RSS is
  bounded by SQLite's page cache (configurable; default 2 MiB).

## How to compare against this baseline

A future bench run:

```sh
go test -bench=. -benchmem -benchtime=2s -run=^$ \
    ./internal/server/store ./internal/chain ./internal/vault \
    > bench-current.txt
diff -u <(grep -E '^Benchmark' BENCH.md) \
       <(grep -E '^Benchmark' bench-current.txt)
```

Or use `benchstat` (`go install golang.org/x/perf/cmd/benchstat`)
to get statistically meaningful comparisons across multiple runs.
