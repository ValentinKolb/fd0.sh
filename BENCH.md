# fd0 performance baseline

Microbenchmarks for the three hottest internal paths: server-side
translog append + proof generation, client-side chain replay, and
vault unlock. Captured to fix a regression target — a future commit
that pushes any number more than 25% in the wrong direction needs
explicit justification.

Snapshot taken 2026-05-06 against commit `0de52b1` (the introduction
of `chain.AppendTx` uniform append-with-rollback) on a developer
machine.

**Hardware**: Apple M1 Max, macOS, single-threaded.
**Reproduce**:

```sh
go test -bench=. -benchmem -benchtime=2s -run=^$ \
    ./internal/server/store ./internal/chain ./internal/vault
```

## Server-side translog (`internal/server/store`)

The hot path on every `/sync` push: SQLite-backed incremental Merkle
tree with per-leaf signature.

| Operation                  |  Depth |     ns/op |  B/op | allocs |   ops/sec |
|----------------------------|-------:|----------:|------:|-------:|----------:|
| `AppendLeaf` cold          |      0 |   540 081 | 8 760 |    235 |     ~1850 |
| `AppendLeaf` warm          |  1 000 |   615 104 | 8 911 |    239 |     ~1625 |
| `AppendLeaf` warm          | 10 000 | 1 010 664 | 9 501 |    256 |      ~990 |
| `AppendLeaf` warm          |100 000 | 9 287 440 |10 547 |    284 |      ~108 |
| `InclusionProofFor`        |  1 000 |   144 320 | 7 580 |    198 |     ~6930 |
| `InclusionProofFor`        | 10 000 |   793 590 | 7 610 |    200 |     ~1260 |
| `InclusionProofFor`        |100 000 |10 303 929 | 9 619 |    245 |       ~97 |
| `ConsistencyProofFor`      |  1 000 |   189 301 |12 023 |    306 |     ~5285 |
| `ConsistencyProofFor`      | 10 000 |   857 845 |13 635 |    351 |     ~1166 |
| `ConsistencyProofFor`      |100 000 | 9 124 275 |16 100 |    417 |      ~110 |

### Notes

- **AppendLeaf** scales sub-linearly from 1k → 10k (+64%), then jumps 9× from 10k → 100k for a 10× scale increase. The inflection at ~10k is the leaves-table B-tree spilling the SQLite page cache; from there per-append cost is bounded by SQL row-lookup latency, not SHA-256 or signature cost.
- The 100k figure (~9 ms/append) caps single-chain throughput at ~110 push/sec on one machine. Multi-chain throughput is higher: each chain has its own incremental-tree state and the store does not hold a global lock per append.
- **Inclusion / consistency proofs** show the same inflection: inclusion ~13× slower from 10k → 100k, consistency ~10.6×. Path length only grows by ~3.3 Merkle levels (log₂(100k) − log₂(10k) ≈ 3.3); the rest is SQL row-lookup. Wave-H optimisation candidates if a deployment shows real load: pre-warm the page cache, cache the most-recent N proof results, or move the Merkle frontier in-memory (current schema stores every internal-node hash in SQLite for replay-after-crash).

### Extrapolation to 1M leaves

100k → 1M is another 10× scale. If the 9.2× ratio held, 1M would land around 85 ms/op ≈ ~12 leaves/sec sustained. The extrapolation is shaky: at 1M the working set is well past any reasonable page cache and the constant becomes "B-tree walks at log₂(1M) ≈ 20 levels of disk I/O per insert", which on SSD is closer to 50–100 ms.

Either way, more than 100k events per single chain is not a comfortable v1.0 deployment shape on this storage backend. Larger deployments need chain-level horizontal partitioning, a separate translog backend, or periodic checkpoint-and-prune of the leaves table once inclusion-proof requests for old events stop arriving. Tracked as Wave H performance work.

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

- Replay is perfectly linear: ~56 µs per event regardless of chain depth. The per-event cost is dominated by ed25519 signature verify (~30 µs) plus CBOR decode and AAD construction.
- At 10 000 events per scope, every CLI command spends ~555 ms in replay before doing anything. `STORAGE.md` §5 compaction is the answer; `CompactScope` thresholds should trigger well before this point in production.
- Allocation cost is steep: 870k allocs for a 10k-event replay (87 allocs/event). Most are CBOR decode buffers. Halving this would halve replay wall-time. Optimisation candidate if replay shows up in user-perceived latency profiling.
- `AppendScope` is ~6 ms because of the per-event fsync. Group-commit would help integration-test throughput but compromises the crash-consistency story for real users; per-event fsync is correct.

## Vault unlock (`internal/vault`)

User-facing latency: every `fd0 unlock` and every CLI command
that opens the vault hits this path.

| Operation                  |        ns/op |    B/op | allocs |   wall   |
|----------------------------|-------------:|--------:|-------:|----------|
| `Open` (passphrase wrap)   |  146 579 485 | 67 MiB  |     76 |  ~147 ms |
| `DeriveKey` (Argon2id only)|  141 913 092 | 67 MiB  |     31 |  ~142 ms |
| `Save` (no KDF, just AEAD) |   12 553 659 |   6 KiB |     34 |   ~13 ms |

### Notes

- `Open` is dominated by Argon2id: the KDF alone takes 142 ms; the rest (AEAD body decrypt, CBOR decode, magic / version checks) is ~5 ms.
- The 67 MiB allocation is on-spec: `crypto.DefaultArgon2 = Argon2Params{M: 64*1024 KiB, T: 3, P: 1}`. The benchmark sanity-checks that no commit accidentally weakens M.
- `Save` is ~13 ms (no KDF, only AEAD-reseal + fsync). It runs on every state mutation: every `secret.set` and every `member.change` after replay-and-vault-update.
- A 150 ms unlock is visible but acceptable. Options to go lower: weaken Argon2 memory cost (security regression), agent-cache the payload key (already done — agent unlocks once and holds for the session), or add interactive TUI feedback ("KDF in progress").

## What this catches

- **Argon2 weakening**: any commit that drops M below 64 MiB makes `BenchmarkVaultDeriveKeyOnly` allocate <67 MiB and run faster.
- **Replay cost regression**: a change that doubles per-event allocations pushes 10k replay from 555 ms to ~1 s.
- **AppendLeaf O(n²)**: a schema change that adds an unbounded SELECT in the append path makes the warm-10k figure blow past linear vs. warm-1k.
- **Index loss**: dropping the SQLite leaves index pushes 10k inclusion-proof from <1 ms to >>10 ms.

## Not covered (defer to v1.x bench-pass)

- **End-to-end sync wall-time** (multi-scope, multi-event): needs a stable test-server harness and `hyperfine` against the `fd0` binary. Skipped for v1.0; per-component numbers above give upper bounds.
- **Multi-tenant translog throughput** (concurrent push from N clients): the single-threaded numbers bound the per-chain lower limit.
- **1M-leaf translog**: pre-fill takes ~10 minutes; not reproduced here. The ratio-based estimate above is shaky — at 1M the working set is well past any reasonable page cache and cost becomes I/O-bound, not CPU-bound.
- **Server memory under load**: the SQLite store does not preload the chain, so steady-state RSS is bounded by the SQLite page cache (configurable; default 2 MiB).

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
