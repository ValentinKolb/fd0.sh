# Replication & redundancy — design (single-primary, model A1)

How fd0 gets redundancy without ever letting two servers disagree about a
scope's history. The short version: **one write/read authority per scope
(the primary), plus an optional server-side disaster-recovery backup.**
Multi-write replication is deliberately not supported.

## 1. The problem multi-write can't solve

Each fd0 server keeps an append-only, hash-chained, per-server-signed log
per scope (a transparency log; the witness cosigns its STHs). If a client
writes the same scope to two independent servers ("multi-push"), the two
logs are separate linear histories. The moment one write lands on server
A but not server B — B briefly down, a partial sync, a crash — the chains
fork at that sequence and, because the log is append-only and each server
has cosigned its own STHs, **they can never re-converge on their own.**

There is no safe automatic fix:

- You cannot rewrite a forked, cosigned chain — resetting one server makes
  *that* server equivocate against its own past STHs (the exact thing the
  transparency log exists to detect).
- Merging at the secret level (last-writer-wins) means **discarding a
  conflicting write** — silent data loss, which violates fd0's prime
  directive (never lose data).

This is not hypothetical: it happened in production (api.fd0.sh and
api2.fd0.sh forked under multi-push). The conclusion is structural:
**a scope must have exactly one ordering authority.**

## 2. The model: one primary per client (A1)

- A client is configured with **exactly one** server (`[sync].server`).
  Every write and every read for every scope goes to that one primary.
- A configuration listing more than one server is a **hard error**, not a
  silent multi-push — the CLI tells the operator to use a DR backup
  instead (`internal/cli/sync_multi.go`).
- With one authority, divergence is **impossible by construction**: there
  is never a second history to disagree with, so no conflict can arise and
  no write is ever discarded.

Redundancy does not come from a second write target. It comes from a
server-side **disaster-recovery backup** (§3).

### Availability trade-off (stated explicitly)

A scope's availability equals its primary's uptime. There is **no live
read-failover** to another server — reading from a possibly-stale replica
is exactly the inconsistency we are eliminating. If the primary is down,
writes/reads to it fail until it returns; local reads of already-synced
secrets keep working (the vault is local). High availability via consensus
or automatic failover is a non-goal (§5).

## 3. Disaster-recovery backup (server-side, implemented)

A second server configured with `FD0_REPLICATE_FROM=<primary-url>` pulls
the primary's chains into a **write-once local archive** (`backup_events`
/ `backup_sths`), verifying each STH under the primary's key before
storing it. It:

- never serves the backed-up chains and never re-signs them (so it can
  never become a second authority — the one-authority invariant holds);
- is authorised as a TOFU-pinned peer (the primary lists it in
  `FD0_PEERS`); removing it from `FD0_PEERS` revokes the pull on reboot;
- exists purely so that if the primary's disk is lost, no event is lost.

Promotion of a backup to a new primary is an **operator ceremony**
(restore the archive into a fresh server identity, re-pin clients), not an
automatic failover. See `internal/server/replicate.go`,
`internal/server/peer_replicate.go`, `internal/server/store/backup.go`.

## 4. What this removed

The earlier "primary-per-scope" design (a committed `_meta` anchor routing
each scope to one of several write servers) was superseded by A1:
single-primary is simpler, needs no anchor agreement between members, and
covers the real topologies. Removed from the client: `[sync].mode`,
multi-push, per-scope anchor selection, replica read-failover. Kept: the
server-side DR-backup machinery above.

## 5. Non-goals

- **Multi-write / active-active.** Structurally unsafe (§1).
- **Automatic failover.** Promotion is a deliberate operator action.
- **Live read replicas.** Reads go to the primary only.
- **Consensus (Raft/Paxos).** Would give multi-node HA with one agreed
  log, but is a major addition and out of scope for v1.

## 6. Acceptance test

`internal/simtest` drives the **real** fd0 binaries: N clients sharing a
scope against ONE primary, a seeded schedule of writes/syncs/transient
primary outages, then asserts data-safety (own-write durability, no
phantom, received-then-lost monotonicity, doctor-clean) **and full
convergence** — required, because one authority must converge the fleet.
`TestMultiServerConfigIsRejected` guards that a multi-server config fails
loudly. The production failure mode (two servers forking) is now
impossible by construction, hence untestable.
