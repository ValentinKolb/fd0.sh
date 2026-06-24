# Server-side replication (primary-per-scope) — design

Status: **design, not implemented.** This document specifies the
server-side replication that replaces the current client-driven
multi-push model. It is phased so that the data-safe parts ship first and
the cryptographically subtle part (failover / anchor hand-off) is gated
behind external review. Companion: `PROTOCOL.md` §11 (Peer Replication),
`TRANSLOG.md`, `STORAGE.md`.

## 1. Problem

Today multi-server means the **client** pushes every event to every
configured server and reconciles against each independently. With more
than one server this has no single ordering authority per scope, so
replicas can hold divergent lineages. The reconcile path then either
drops data or (with the F1 fix) refuses and cannot converge.

This is not a hypothesis. The simulation harness (`internal/simtest`)
reproduces it deterministically: seed 42 of `TestSimSeeds` shows a value
written by one member that a second member can never read, because the
writer is correctly refused when reconciling a lagging replica (refusing
is the safe choice — it avoids dropping a third member's data). The
**safety invariants hold** (no data is lost), but **convergence does
not**. Convergence is the property server-side replication restores.

Goal: **exactly one ordering authority (the "primary") per scope.**
Clients return to the well-tested single-authority behaviour; replicas
exist for read availability and backup.

## 2. The hard constraint: the transparency log is keyed per server

A scope's STH (signed tree head) is signed by the **server's** translog
key (`store/translog_key.go`: one key per server instance), not by a
per-chain key. Clients TOFU-pin `(server URL → translog pubkey)` and
verify a scope's STH against the key of the server they pinned.

Consequence: a replica **cannot** re-serve a primary-owned scope under
its own identity — the STH the client expects (signed by the replica's
key) does not exist, and a replica re-signing the chain under its own key
would create a *second* anchoring key for the same chain. Two keys
anchoring one chain is **equivocation**: it breaks the transparency and
witness guarantees that are the product's reason to exist.

Therefore replication must preserve the invariant **"each scope chain is
anchored by exactly one server key, for its whole lifetime, globally
agreed."** Everything below follows from that.

### 2.1 Transport server vs. anchor server (must be modelled separately)

⚠️ Review finding (RED): today the client keys *everything* —
STH pinning, vault cursors, witness queries — by the **URL it contacted**
(`cli/translog.go`, `witness.go`: pin/verify against the contacted
server's pubkey). Replication breaks that conflation: the server a client
*talks to* (the transport server, possibly a replica) is not necessarily
the server whose key *anchors* the scope (the anchor server / primary).

The protocol must therefore distinguish, end to end:

- **Anchor server** — the (frozen, §3) translog identity that signs a
  scope's STHs. The client verifies a scope's STH against the **anchor
  key recorded for that scope**, regardless of which URL served the bytes.
  Witness cross-checks for the scope are likewise issued against the
  anchor identity.
- **Transport server** — whichever reachable URL (primary or replica)
  delivered the events. Used only for connectivity/failover, never for
  STH trust.

This separation must be reflected in: the pull/sync response (which
carries the anchor identity for each scope), the client's per-scope vault
state (store the anchor pubkey, not just a URL cursor), and the witness
query path. Until this is implemented, Phases 1–2 are NOT safe to ship —
a replica serving a primary-anchored STH would fail the client's
contacted-URL-keyed verification (or, worse, pass it against the wrong
key).

## 3. Primary assignment — the anchor is FROZEN at scope creation ✅ IMPLEMENTED

Client-side primary-per-scope routing is implemented in
`internal/cli/sync_primary.go` and wired into `RunSync` (each server
handles only the scopes it anchors). Opt-in via `[sync].mode = "primary"`;
the default stays multi-push so existing deployments are unaffected.

The anchor is **committed to the scope's shared `_meta` secret** by the
creator (`MetaKeyAnchor`, `RunScopeCreate`) and READ by every member —
member-agnostic, so members with different local `[sync].servers` sets
still agree (review RED #1). A member whose config lacks the committed
anchor server **fails loudly** rather than silently skipping the scope
(review RED #2). Scopes with no committed anchor fall back to multi-push.
Acceptance: `TestSimPrimaryMode` + `TestPrimaryModeHeterogeneousConfig` (§6).


⚠️ Review finding (RED): a purely live computation
`primary(scope_id) = servers[H(scope_id) mod N]` is **unsafe** — the
moment the operator adds or removes a server, `N` changes and the anchor
of every existing scope silently moves to a different key. Two keys
anchoring one chain over its lifetime is indistinguishable from
equivocation and breaks §2's one-anchor invariant.

So the anchor must be **bound to the scope, not recomputed**:

- `H(scope_id) mod N` is used **only once**, to pick the *initial*
  primary at scope-creation time.
- The chosen anchor — the **primary's translog pubkey** — is recorded
  durably and immutably **in the scope's genesis metadata** (server-side
  chain metadata, and mirrored in each client's per-scope vault state on
  first contact). It is content-bound, so it cannot be silently rewritten.
- All later reads/writes resolve the anchor from this recorded value, NOT
  from the live server set. Adding/removing servers therefore never moves
  an existing scope's anchor.
- Changing a scope's anchor is **only** possible via the explicit,
  witness-observable hand-off of Phase 3 (§5) — never as a side effect of
  a config change.

Server-set membership itself is versioned as a signed **epoch** (an
operator-signed, witness-anchored record of "the set of server pubkeys at
epoch e"). The initial-primary computation references a specific epoch, so
which key was legitimately chosen is auditable after the fact. New scopes
created under epoch e+1 may use the new set; existing scopes keep their
frozen anchor.

Spreading initial primaries across the set still spreads write load and
failure domain; no single server is "the" primary.

## 4. Server-to-server auth (reuses existing peer keys)

Servers already discover and TOFU-pin each other's translog pubkeys via
`/v1/server-info` + the `peers` table (`server/peers.go`,
`store/peers.go`). Replication adds one authenticated server→server
capability:

- The requesting server signs with its **translog key** using the
  existing `fd0-sig` scheme (the signed input already binds the target
  server's pubkey, preventing cross-server replay).
- The receiving server authorises the request iff the signer pubkey is a
  **pinned peer** (new check alongside the existing `IsUserRegistered`
  path in `auth.go`), gated to the replication endpoints only.

No new key material, no new trust root: a peer is trusted for *transport
access*, never for *data integrity* — events are member-signed and
content-addressed, and inclusion/consistency is witness-checkable, so a
malicious peer can never **forge** an event.

Withholding is weaker than that, though (review finding, downgraded from
the original "cannot withhold"): a replica can serve a **stale but
validly-signed** older STH and simply omit newer events. The transparency
log makes this *detectable*, not *impossible* — and only if a freshness
policy actually looks. So Phase 1 reads from a replica MUST apply a
freshness check: cross-check the replica-served STH size against the
anchor's latest known size (from the witness, or a direct primary probe
on a sampling interval) and reject/deprioritise a replica that lags beyond
a bound. Without that policy a replica can hide recent writes from a
reader indefinitely.

Peer authorisation is also revocable: removing a peer pubkey from the set
must immediately stop honouring its replication requests (the existing
peer table is sticky-TOFU for *discovery*; the replication-auth check
must consult the *current* authorised set, not the last-seen one).

## 5. Phased rollout (data-safety first)

Each phase is independently shippable and reversible. **No phase resets
or rewrites the primary's data.** Migration of the live fleet
(`api.fd0.sh` stays primary; `api2` is reset and re-seeded) is covered in
§7.

### Phase 0 — cold-standby backup (no client change, no trust change) ✅ IMPLEMENTED

Implemented in: `internal/server/store/backup.go` (read-only archive +
`IsPeerPub`), `internal/server/peer_replicate.go` (peer-auth +
`GET /v1/peer/chain`), `internal/server/replicate.go` (the pull loop),
wired via `Config.ReplicateFrom` / `FD0_REPLICATE_FROM`. Acceptance test:
`TestPhase0BackupReplication` (byte-identical mirror incl. signed STH,
live tables untouched, idempotent, unpinned-peer refused).



A replica pulls a **full, verbatim copy** of a primary's scope chains
(encrypted event blobs + the primary's signed STHs) on an interval, via
the peer-authenticated pull of §4, and stores them unchanged. It does
**not** serve them to clients. Purpose: disaster recovery — if the
primary's disk dies, the standby holds every (encrypted) event.

- Config: `FD0_REPLICATE_FROM=<primary-url>` (a server-level opt-in).
- Zero client involvement, zero trust-model change, zero equivocation:
  the standby never anchors anything; it just keeps bytes safe.
- This alone delivers the single most-requested property ("a server can
  die without losing data") at near-zero risk.
- **Storage (review finding):** `translog_sths` today has no
  signer/anchor namespace and the append/STH-sign APIs assume the *local*
  server key. Replicated chains must be stored in an explicit
  **anchor-namespaced** form — each stored chain tagged with the
  anchoring pubkey, and the local append/sign path **guarded** so the
  standby can never re-sign or extend a chain it merely mirrors. A
  replicated chain is read-only, foreign-anchored data; conflating it with
  a locally-anchored chain is the one way Phase 0 could create a second
  anchor. This guard is a prerequisite of Phase 0, not a later concern.

### Phase 1 — read replicas (client verifies against the primary key)

A replica serves *reads* of a primary-owned scope by returning the
primary's chain **and the primary's STH unchanged**. The client, knowing
`primary(scope_id)`, verifies that STH against the primary's pinned key.

- Wire: additive — the pull response already carries the STH; the client
  change is *which pinned key it verifies against*, selected by the
  deterministic primary function.
- Gives read availability/failover with the anchor invariant intact (one
  key per chain).

### Phase 2 — write forwarding

A client write to any server is forwarded by that server to the scope's
primary, which orders and anchors it; the result (primary STH +
inclusion proof) is returned through the replica to the client.

- Lets clients write to any server while the primary remains the sole
  ordering authority.

### Phase 3 — failover + anchor hand-off (**requires external review**)

This is the one cryptographically subtle part and is **deliberately not
specified for implementation here**. When a primary is unavailable,
promoting a replica changes which key anchors the scope — a controlled
*anchor hand-off*. Done naively it is indistinguishable from
equivocation. A correct design must:

- Make the hand-off an explicit, witness-observable transition (e.g. a
  signed "hand-off" record from the old primary, or a quorum attestation)
  so clients and witnesses can tell a legitimate promotion from a
  malicious fork.
- Define what happens to writes accepted by the old primary but not yet
  replicated at promotion time (the only window where data could be at
  risk — must be closed, not hand-waved).
- Specify how clients learn the new anchor key and how witnesses track
  the chain across the key change.

Until this is designed and **reviewed by a cryptographer**, failover is
**manual**: an operator promotes a standby in a documented ceremony — the
standby adopts the old primary's translog identity from backup (the same
operation as restoring the primary), which sidesteps anchor hand-off
entirely. **Fencing is mandatory (review finding):** because the standby
takes over the old primary's *identity*, the old primary MUST be
positively fenced first — stopped, or its translog key removed, or set
read-only — so two live servers cannot sign different continuations under
the same key (that would be exactly the equivocation we forbid). The
ceremony must also document expected client/witness behaviour across the
takeover (clients continue verifying against the same anchor key; the
witness sees one continuous chain). Phases 0–2 deliver backup + read-HA +
write-anywhere; only *automatic* failover waits on Phase 3.

## 6. Acceptance test

The simulation harness is the acceptance test. `internal/simtest`
asserts the safety invariants on every seed — including S4, the
continuous **received-then-lost** check that verifies no client ever
regresses a value it has read (the exact F1 property) at every mid-run
observation point.

- `TestSimSeeds` runs in multi-push mode and REPORTS the convergence gap
  (e.g. seed 42 leaves 12 (client,key) pairs unconverged) while all
  safety invariants hold — the motivation for primary-per-scope routing.
- `TestSimPrimaryMode` runs the SAME faulted schedules with
  `[sync].mode = "primary"` and `requireConvergence = true`: every client
  must read every key's latest value after quiescence, under arbitrary
  partitions. **It passes on all seeds, including seed 42** — the
  convergence acceptance criterion for primary-per-scope routing is met.

*Active-active reads from a replica* and *automatic failover* (serving a
primary-anchored scope's STH through a different server, §2.1 / Phase 3)
are **explicitly out of scope** — they are availability optimisations,
not correctness, and they are the parts that would touch the
trust/verification path. The accepted model is:

- **Reads**: a scope is read from its primary. If the primary is down,
  that scope is temporarily unavailable (the data is safe — on the
  primary and in the DR backup — just not served until the primary is
  back or restored).
- **Failover**: **manual** operator restore (promote a DR-backup replica
  by adopting the old primary's identity, with fencing — §5 Phase 3). No
  automatic anchor hand-off.

What primary routing + DR backup already deliver — single-authority
convergence (no divergence / data loss) and no-data-loss-on-server-death
— is the correctness goal of #2a and is complete.

## 7. Live migration (no data reset on the existing primary)

- **`api.fd0.sh` becomes the primary and is never reset.** Its chains are
  already the authoritative lineage; the new server binary reads the
  existing DB format unchanged (no storage-format change). A binary
  upgrade is not a data reset.
- **`api2` is reset and re-seeded** from the primary (Phase 0 pull). It
  ends byte-identical to the primary's lineage.
- **Pre-reset safety check (mandatory, and it must be EXECUTABLE — review
  finding):** "api2 holds nothing the primary lacks" has to be a concrete
  comparison, not a vibe. For every chain on `api2` (`SELECT chain_id` →
  per chain, the full event set and the tip): assert `api2`'s event-id set
  for that chain is a **subset** of the primary's, and the tips are
  compatible (api2's tip seq ≤ primary's, with matching prev-hash linkage
  at api2's tip). The reset is allowed only if, for every chain, this
  holds. Abort on any of: a chain present on api2 but not the primary; an
  event-id on api2 absent from the primary; or a **same-seq-but-different
  event** (a genuine fork). On abort, get the missing events onto the
  primary first (have the authoring members sync to the primary), then
  re-run the check. This is the same foreign-event class the F1 fix
  protects; skipping or hand-waving the check is the one way this
  migration could lose data. Ship this as a one-shot `fd0-server
  replicate-precheck --primary <url>` subcommand so it is auditable, not a
  manual SQL session.
- **Clients** keep all secrets (anchored at the primary) and need only a
  one-time per-server cursor reset for `api2` after it re-seeds.

## 8. Non-goals (v1)

- Quorum/Raft consensus. Primary-per-scope is single-authority by design;
  if write-HA with no failover window becomes a hard requirement, a
  quorum model can be introduced *under the same client interface* later.
- Client-side multi-lineage merge (the rejected "option b"): it would
  push security-critical membership/OEK consensus onto every client.
