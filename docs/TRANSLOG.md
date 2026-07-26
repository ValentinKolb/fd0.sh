# fd0 Transparency Log (v1)

Companion to `PROTOCOL.md`, `STORAGE.md`, `API.md`, `THREATS.md`. The transparency log lifts the existing "tamper detection on the server-held chain" guarantee from "any client that pulls from `cursor=0` can detect modification" to "any pair of clients (or a third-party witness) can detect equivocation between divergent server views". It addresses `THREATS.md` T35 "Server equivocation".

The wire format and cryptographic constructions follow `PROTOCOL.md` conventions: deterministic CBOR (RFC 8949 §4.2.1), domain-separated signatures, byte concatenation `||`. The Merkle tree construction follows RFC 6962 with SHA-256.

## Contents

1. [Properties](#1-properties)
2. [Domain separators](#2-domain-separators)
3. [Tree construction](#3-tree-construction)
4. [Server keypair](#4-server-keypair)
5. [API endpoints](#5-api-endpoints)
6. [Client verification](#6-client-verification)
7. [Storage](#7-storage)
8. [Witness binary](#8-witness-binary)
9. [Full-history clients and legacy repair](#9-full-history-clients-and-legacy-repair)
10. [Deferred to v1.x and beyond](#10-deferred-to-v1x-and-beyond)
11. [Peer hints](#11-peer-hints-v004)
12. [Threat-model implications](#12-threat-model-implications)

---

## 1. Properties

Properties enforced by the protocol against a malicious server, given correct clients that verify proofs and persist STHs.

- **Append-only commitment.** The server publishes a Merkle tree per chain. Each event's leaf is fixed at insertion time and cannot be removed or rewritten without breaking a consistency proof against any earlier signed tree head (STH).
- **Equivocation detection (offline).** A server that presents two divergent histories of the same chain to two different clients produces two STHs at the same `tree_size` with different `root_hash`. Detected by any party that holds both STHs (the affected clients via cross-device gossip, a witness via STH archive).
- **Inclusion verifiability.** Every event a client appends to its local chain is delivered with an inclusion proof against an STH the client persists. A server-side rewrite of historical events is detected on the next pull (consistency proof fails).
- **Full-history repair.** v1 clients retain a contiguous local chain. Files produced by older compacting clients are repaired from a pinned server's full history only after STH and inclusion-proof verification.
- **Witness publishability.** A passive `fd0-witness` observer (§8) can fetch and archive STHs from any number of servers without needing membership in any scope. Witnesses see only `(chain_id, tree_size, root_hash, timestamp, signature)`; never plaintext events, never cleartext membership.

The transparency log adds one trust input (the server's signing pubkey) and one ceremony (first-contact pinning, analogous to identity-card safety-number verification — see `PROTOCOL.md` §2.3, `THREATS.md` §3).

---

## 2. Domain separators

| Domain                          | Use                                          |
| ------------------------------- | -------------------------------------------- |
| `fd0-translog-leaf-v1`          | Leaf hash input (§3.1)                       |
| `fd0-translog-node-v1`          | Inner-node hash input (§3.1)                 |
| `fd0-translog-empty-v1`         | Empty-tree sentinel root (§3.1)              |
| `fd0-translog-sth-v1`           | STH signature input (§3.3)                   |
| `fd0-translog-server-info-v1`   | Server-info signature input (§4.1)           |

Reuse of any of these domains for any other purpose is a protocol violation.

---

## 3. Tree construction

### 3.1 Leaves and inner nodes

One Merkle tree per chain. The chain identifier is `STORAGE.md` §2's `chain_id` (`"user:<shortId>"` or `"scope:<scope_id>"`). Leaves are added in the order events are appended, which equals the event's `seq` (zero-indexed = `seq=0` is the leaf at index 0).

```
leaf_input(ev)             = SHA-256(ev.PrevHashInput())               ; 32-byte canonical event hash
leaf_hash(ev)              = SHA-256("fd0-translog-leaf-v1" || leaf_input(ev))
node_hash(left, right)     = SHA-256("fd0-translog-node-v1" || left || right)
empty_root                 = SHA-256("fd0-translog-empty-v1")          ; size=0 sentinel
```

The leaf input is the **32-byte SHA-256 over the canonical event body** — explicitly `proto.HashPrefix(ev.PrevHashInput())` for both event types:

- **ScopeEvent**: `PrevHashInput() = cbor(SignedPrefix)` per `PROTOCOL.md` §4.1.
- **UserEvent**: `PrevHashInput() = cbor(UserEvent without signature)` per `PROTOCOL.md` §3.

This is the same 32-byte hash that anchors `prev_hash` linking. It is NOT the textual `event_id` (`"e_" + base32(SHA-256(prefix)[:16])`) — that form truncates to 128 bits and is unsuitable for cryptographic anchoring.

Using `PrevHashInput()` uniformly for scope and user events keeps a single leaf-encoding rule across both chain kinds.

The tree shape follows RFC 6962 §2: a binary Merkle tree where, for `n > 1` leaves, the left subtree is the largest power of two strictly less than `n` and the right subtree holds the remainder. This shape supports incremental updates in `O(log n)` and inclusion / consistency proofs of length `O(log n)`.

### 3.2 Tree head

```cddl
TreeHead = {
    chain_id   : tstr,
    tree_size  : uint .size 8,   ; uint64; number of leaves; 0 ≤ tree_size ≤ 2^63 - 1
    root_hash  : bstr .size 32,  ; empty_root if tree_size == 0
    timestamp  : uint .size 8,   ; uint64 unix seconds (server clock)
}
```

`tree_size` is bounded by `2^63 - 1` (RFC 6962 §3 restriction). Per-chain growth at one event per second would saturate this in ~292 billion years; not a practical concern.

`timestamp` is informational — clients MUST NOT reject an STH solely because its timestamp is in the past; a stale STH is only rejected by `tree_size` regression (§6.3).

### 3.3 Signed tree head

```cddl
STH = {
    head      : TreeHead,
    signature : bstr,            ; Ed25519(server_priv, "fd0-translog-sth-v1" || cbor(head))
}
```

The signature uses the server's transparency-log keypair (§4). Verifiers reconstruct `cbor(head)` deterministically and check the signature.

---

## 4. Server keypair

The server holds one Ed25519 keypair used exclusively for signing STHs and the server-info record. This key is distinct from any per-event signing identity and does not authenticate the server's TLS endpoint.

### 4.1 Lifecycle

- Operator supplies a path via `--server-priv-file=<path>` flag or `FD0_SERVER_PRIV_FILE` env var. A missing flag and missing env var defaults to `<server data dir>/server-translog.key`. The server data dir is the directory containing the SQLite database.
- The server cross-checks against `translog_server_key.pub` cached in the database (§7.2). The startup matrix:

  | keyfile present | DB cached pub present | action                                                                       |
  | --------------- | --------------------- | ---------------------------------------------------------------------------- |
  | yes             | no                    | Load keyfile, derive pubkey, persist to DB. Continue.                        |
  | yes             | yes, matches keyfile  | Load keyfile, continue.                                                      |
  | yes             | yes, does NOT match   | **FATAL** — keyfile / DB pubkey mismatch; refuse to start. Likely accidental key swap. |
  | no              | yes                   | **FATAL** — DB expects a key the operator has lost. Refuse to start. Operator MUST restore the keyfile or perform a key-rotation ceremony (§4.3). |
  | no              | no                    | Generate a fresh keypair, persist to keyfile + DB, log at WARN level. First-boot path. |

  The "fresh keypair" fallback exists so a single-operator first-boot has zero ceremony. It logs:

  ```
  fd0-server: WARN — generated new transparency-log key at <path>.
              BACK THIS UP NOW. Loss requires a key-rotation ceremony (`TRANSLOG.md` §4.3)
              and forces every client to re-pin on next contact, dropping equivocation
              evidence for STHs signed under the old key.
  ```

- The keyfile MUST contain exactly 64 bytes (raw Ed25519 private key, the standard `seed || pub` Go layout). Anything else is a startup-FATAL.
- Keyfile writes are atomic: write to `<path>.tmp` with mode `0600`, `fsync` the file, `rename` to `<path>`, `fsync` the parent directory. A crash between steps leaves either the old keyfile (no DB persistence yet, regenerate next boot) or a complete new keyfile (DB persistence on next boot reconciles).
- DB persistence (`INSERT INTO translog_server_key`) is committed BEFORE the server accepts any HTTP traffic. A crash between keyfile-write and DB-commit on first boot is recovered by retrying generation with the existing keyfile (matrix row 1).

### 4.2 Server-info endpoint

```
GET /v1/server-info
→ 200 application/cbor

ServerInfo = {
    server_pub : bstr .size 32,    ; Ed25519 pubkey (translog signing)
    issued_at  : uint,             ; unix seconds
    ? label    : tstr,             ; self-declared, [a-z0-9-]{0,32}
    ? peers    : [* PeerInfo],     ; resolved replicas (§11)
    domain     : "fd0-translog-server-info-v1",
    signature  : bstr,             ; Ed25519(server_priv,
                                   ;         "fd0-translog-server-info-v1" ||
                                   ;         cbor({server_pub, issued_at, ?label, ?peers}))
}

PeerInfo = {
    url    : tstr,                 ; canonical replica URL
    pub    : bstr .size 32,        ; replica's translog signing pubkey
    ? label : tstr                 ; replica's self-declared label
}
```

Self-signed — the only thing this proves is that the holder of `server_priv` issued the record. The first-contact pinning ceremony (§6.1) is what binds the key to the operator the user trusts.

`label` and `peers` are optional. Both fields use CBOR `omitempty` — a solo server with `FD0_LABEL` unset produces signed bytes without either field (the witness binary reuses the same record type, sets neither, and its signatures remain stable). When either field is populated, the signature input includes it, so verifiers must use the current `ServerInfo` shape.

`peers` is the operator's signed claim about which DR backups exist. Current clients treat it as informational; they still read and write one configured primary. Server-side DR replication uses the primary's `FD0_PEERS` list to authorize a standby pulling with `FD0_REPLICATE_FROM`. Trust is HINTS-not-TRUST per §11: any component that talks to a peer must run the first-contact pinning ceremony against that peer's own `/v1/server-info`.

### 4.3 Key rotation (operational ceremony)

If the server's translog signing key is lost or compromised, equivocation evidence under the old key is no longer enforceable. Recovery requires every client to re-pin:

1. Operator generates a new keypair, places it at the configured keyfile path.
2. Operator clears `translog_server_key` from the DB and restarts the server.
3. The server loads the new keyfile, persists the new pubkey to DB, signs a fresh STH for every chain at its current `tree_size` under the new key.
4. Clients pinning the old key see `pinned-key-mismatch` on next sync (§6.4) and surface a manual ceremony.
5. Existing STHs signed under the old key remain valid evidence for any equivocation that occurred before rotation; they are not retroactively useful for the new key.

Out-of-band: the operator MUST publish the new fingerprint via the same channel used at first contact.

---

## 5. API endpoints

`/v1/server-info`, `/v1/sth/{chain_id}`, `/v1/proof/inclusion`, and `/v1/proof/consistency` are **unauthenticated** — they expose only commitments to a public log. Withholding inclusion proofs from arbitrary observers would defeat the witness model, which requires that any party (including ones with no membership in any scope) can fetch and archive STHs.

Information leak: an unauthenticated `/v1/sth/{chain_id}` reveals (a) that the chain exists, (b) its current `tree_size`. `chain_id` is randomly-derived from a content hash for scopes (`s_<base32(...)>`) and from a server-assigned `shortId` for users; an attacker without prior knowledge cannot enumerate by guessing. This is the same metadata an authenticated `/sync` already exposes to any member.

`/sync` and the `/users` endpoints continue to require signed-request authentication per `API.md` §1.

**Wire-additivity rule (cross-cutting).** All CBOR map decoders in fd0 — server, client, witness — MUST silently ignore unknown keys. Optional fields can be added to existing map schemas without bumping the protocol version. Strict-mode union matching is forbidden.

### 5.1 Current STH

```
GET /v1/sth/{chain_id}
→ 200 application/cbor — STH (§3.3)
→ 404 if chain_id unknown to the server
```

### 5.2 Inclusion proof

```
GET /v1/proof/inclusion?chain_id={cid}&leaf_index={idx}&tree_size={n}
→ 200 application/cbor

InclusionProof = {
    leaf_index : uint,
    tree_size  : uint,
    audit_path : [* bstr .size 32],   ; sibling hashes, leaf-to-root order
}

→ 400 if leaf_index ≥ tree_size or tree_size > current size
→ 404 if chain_id unknown
```

`audit_path` is the RFC 6962 §2.1.1 path. Verifier recomputes the leaf hash from the event_id, walks the path with `node_hash`, and compares against the STH `root_hash`.

### 5.3 Consistency proof

```
GET /v1/proof/consistency?chain_id={cid}&from_size={a}&to_size={b}
→ 200 application/cbor

ConsistencyProof = {
    from_size : uint,
    to_size   : uint,
    nodes     : [* bstr .size 32],   ; RFC 6962 §2.1.2
}

→ 400 if from_size > to_size or to_size > current size
→ 404 if chain_id unknown
```

`from_size = 0` is allowed and returns an empty `nodes` slice (any tree is consistent with the empty tree). The verifier MUST still check that the new STH covers `to_size` leaves and that the recomputed root matches.

### 5.4 Sync integration

`/sync` is extended additively. Request schema (`API.md` §2.4):

```cddl
PullEntry = {
    cursor          : Cursor,                      ; existing
    ? last_sth_size : uint,                        ; NEW — caller's last persisted tree_size
}
```

Response schema additions per pulled scope:

```cddl
PullResult = {
    tip               : Tip,                       ; existing
    oek_version_max   : uint,                      ; existing
    events            : [* ScopeEvent],            ; existing
    ? denied          : bool,                      ; existing

    sth               : STH,                       ; MANDATORY when not denied
    inclusion_proofs  : [* InclusionProof],        ; MANDATORY; one per element of `events`,
                                                   ; each computed against `sth.tree_size`
    ? consistency_proof : ConsistencyProof,        ; present iff request supplied last_sth_size
                                                   ; and last_sth_size > 0
}
```

Push response per accepted (or de-duplicated) event:

```cddl
PushResult = {
    accepted           : bool,                     ; existing
    ? reason           : tstr,                     ; existing
    ? scope_id         : tstr,                     ; existing
    ? seq              : uint,                     ; existing
    ? event_id         : tstr,                     ; existing
    ? sth              : STH,                      ; MANDATORY iff accepted or reason=="dup",
                                                   ; reflects post-append tree
    ? inclusion_proof  : InclusionProof,           ; same condition; proves the event sits at
                                                   ; leaf_index=seq in sth.tree_size
    ? consistency_proof: ConsistencyProof,         ; same condition; from the client's
                                                   ; declared last_sth_size on the request
                                                   ; envelope (§5.5) to sth.tree_size
}
```

Pulled events are appended to the local chain only after their inclusion proofs verify against the response's STH AND that STH is consistent with the client's persisted STH.

### 5.5 Last-STH declaration on push

Push requests carry the client's per-chain `last_sth_size` so the server can return a synchronous consistency proof per accepted event. Request envelope additions:

```cddl
PushItem = {
    scope               : tstr,                    ; existing ("" for user chain)
    event               : ScopeEvent / UserEvent,  ; existing
    ? last_sth_size     : uint,                    ; client's persisted LastSTH.tree_size
                                                   ; for THIS chain (0 if none)
}
```

If `last_sth_size` is omitted the server omits `consistency_proof` from `PushResult`; the client MUST then refuse to advance `LastSTH` and instead refresh it via the next `/sync` pull (which carries the proof).

### 5.6 User-chain endpoints

The user chain (`API.md` §2.1–2.3) carries the same translog semantics. Response-schema additions:

- `POST /users` (genesis register): response gains `sth` and `inclusion_proof` for the genesis leaf at `seq=0`.
- `GET /users/<shortId>/events`: response gains `sth`, `inclusion_proofs` (one per returned event), and an optional `consistency_proof` if the request provided `last_sth_size` as a query parameter.
- `POST /users/<shortId>/events` (append): response gains `sth`, `inclusion_proof`, and `consistency_proof` per the same rules as `/sync` push.

---

## 6. Client verification

### 6.1 First contact (pinning)

On first sync against a server URL the client does not yet know:

1. Fetch `/v1/server-info`.
2. Verify the self-signature.
3. Display the server pubkey to the user as a fingerprint (e.g., a six-word safety-number-style string per `PROTOCOL.md` §2.3.2; same construction).
4. The user confirms out of band (operator's published fingerprint, secure channel, etc.).
5. Persist `(server_url, server_pub)` in the vault as `PinnedServer` (§7).

A subsequent change of `server_pub` for the same URL is rejected with `pinned-key-mismatch` and surfaces a manual ceremony — analogous to TOFU re-pinning of identity cards.

### 6.2 Sync verification

For each pulled scope with a non-empty `events[]`:

1. Verify the response's `sth.signature` against the pinned `server_pub`. Reject the entire response on failure.
2. If the request supplied `last_sth_size > 0`:
   a. The response MUST include `consistency_proof`. Missing → reject.
   b. Verify the consistency proof per RFC 6962 §2.1.2 from the locally persisted `LastSTH.root_hash` (at `last_sth_size`) to `sth.root_hash` (at `sth.tree_size`). Reject on failure.
3. For each event in `events[i]` (where `i` is its position in the response slice, mapping to leaf index `events[i].SignedPrefix.Seq`):
   a. The response MUST include `inclusion_proofs[i]` with `leaf_index == events[i].SignedPrefix.Seq` and `tree_size == sth.tree_size`. Mismatched index/size → reject.
   b. Recompute `leaf_hash(event_id_bytes(events[i]))`.
   c. Walk the audit path, compare against `sth.root_hash`. Reject on mismatch.
4. Append events to the local chain (existing path).
5. Persist the new STH as `LastSTH` for this chain. Replace any earlier persisted STH unconditionally — the verified consistency proof is the proof of monotonic tree growth.

For `denied=true` responses: the server omits the STH; client drops the scope as before. (Denied means the server claims we are not a member; we have no verified STH to anchor.)

For pull responses with `events == []`: the response MAY still include an STH and consistency proof (cheap to compute, useful to keep `LastSTH` fresh). Client verifies and persists if present.

### 6.3 Push verification

For each accepted/dup'd push result the client MUST execute, in order:

1. Verify the response's `sth.signature` against the pinned `server_pub`.
2. Verify the response's `inclusion_proof` against the pushed event's leaf hash at `leaf_index = seq` and `tree_size = sth.tree_size`.
3. **If the client supplied `last_sth_size > 0` on the push request**: the response MUST include `consistency_proof`. Verify it from `LastSTH` (at `last_sth_size`) to the response's STH (at `sth.tree_size`). Refuse on missing or invalid proof — do NOT advance `LastSTH`.
4. **Only then** persist the new STH as `LastSTH`. The atomicity matters: if step 3 is skipped or weak, the client loses its old anchor without proving the server hasn't equivocated.

For the rare case `last_sth_size == 0` on push (genuine first-ever event for a fresh chain): there is nothing to be consistent with; persist the new STH directly.

### 6.4 Error semantics

| Error                       | Reaction                                                             |
| --------------------------- | -------------------------------------------------------------------- |
| `bad-sth-signature`         | Refuse response; log; do not append events. The user MUST investigate. |
| `consistency-proof-failed`  | Refuse response. Strong signal of server equivocation or rewrite. Surface prominently. |
| `inclusion-proof-failed`    | Refuse response (same as above). |
| `sth-tree-size-regression`  | Server returned a smaller `tree_size` than `LastSTH`. Refuse. The server MUST never publish a smaller tree. |
| `pinned-key-mismatch`       | Refuse all interaction with this URL until the user re-pins. |
| `missing-sth-on-events`     | Server returned events without an STH. Reject — STH is mandatory in v1. |
| `missing-consistency-proof` | Client supplied `last_sth_size > 0` and the response omitted the consistency proof. Reject. |
| `keyfile-db-mismatch`       | Server: keyfile pubkey ≠ DB cached pubkey. Refuse to start. |

The first three are evidence of misbehavior. `fd0 doctor` surfaces them by reading the chain-event log and presenting them as red banners.

---

## 7. Storage

### 7.1 Vault schema additions

`STORAGE.md` §3 `VaultBody`:

```cddl
VaultBody = {
    ; ... existing fields ...
    ? pinned_servers : [* PinnedServer],                ; NEW
}

PinnedServer = {
    server_url   : tstr,
    server_pub   : bstr .size 32,
    pinned_at    : uint,
}
```

Per-scope `STORAGE.md` §3.2 `ScopeVaultData`:

```cddl
ScopeVaultData = {
    ; ... existing fields ...
    ? last_sth : STH,                                  ; NEW; CBOR-omitempty for legacy compat
}
```

User chain analogously gets a `last_sth_user` field on `VaultBody` (the user chain has no per-scope wrapper).

### 7.2 Server-side

`STORAGE.md` §2 SQLite schema gains:

```sql
CREATE TABLE translog_nodes (
    chain_id    TEXT    NOT NULL,
    level       INTEGER NOT NULL,           -- 0 = leaf
    index_at_level INTEGER NOT NULL,        -- 0-based
    hash        BLOB    NOT NULL,           -- 32 bytes
    PRIMARY KEY (chain_id, level, index_at_level)
);
CREATE INDEX translog_nodes_chain ON translog_nodes(chain_id, level);

CREATE TABLE translog_sths (
    chain_id    TEXT    NOT NULL,
    tree_size   INTEGER NOT NULL,
    root_hash   BLOB    NOT NULL,
    timestamp   INTEGER NOT NULL,
    signature   BLOB    NOT NULL,
    PRIMARY KEY (chain_id, tree_size)
);

CREATE TABLE translog_server_key (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    pub          BLOB NOT NULL,
    pub_pinned_at INTEGER NOT NULL
);
```

`translog_nodes` stores the explicit subtree hashes per RFC 6962 incremental update. Computed once at insert; never modified.

`translog_sths` caches every signed STH so witnesses can fetch historical STHs (`/v1/sth/{cid}?at_size={n}` — optional v1 extension; mandatory only for current STH in v1.0).

`translog_server_key` stores the operator-supplied or generated pubkey for self-check on boot (refuses to start if the file doesn't match the cached pubkey, preventing accidental key-swap).

---

## 8. Witness binary

`fd0-witness` is a separate binary. It polls server STH endpoints, archives them, signs cosigns, and exposes a read API for clients.

### 8.1 Operation

Configured with one or more `(server_url, server_pub_pin, [chain_id…])` tuples.
The `server_pub_pin` for a fresh production witness MUST be obtained through a
channel independent of the server connection being monitored. A persisted pin
from an earlier run remains authoritative. Fetching the self-signed key from
`/v1/server-info` on first contact is available only through the explicit
`pin_on_first_use` development option and does not establish independent
witness trust. The witness polls `GET /v1/sth/{chain_id}` per tuple at a
configurable interval (default `1h`).

For each new STH the witness MUST, in order:

1. Verify `sth.signature` against the pinned server pubkey. Drop on failure (logs at WARN).
2. Check `tree_size` is monotonically non-decreasing for `(server_url, chain_id)`. A regression is logged at ERROR and archived as evidence.
3. Verify consistency from the most recent persisted STH to the new STH via `GET /v1/proof/consistency`. Failure (including a refused proof endpoint) is logged at ERROR; both STHs are archived.

Step 3 catches "different-size forks" where the server presents history A at size N and incompatible history B at size N+k. Same-size forks are caught in §8.2 by the storage UNIQUE constraint.

### 8.2 Storage

SQLite. One row per `(server_url, chain_id, tree_size, root_hash)`:

```sql
CREATE TABLE witness_sths (
    server_url        TEXT    NOT NULL,
    chain_id          TEXT    NOT NULL,
    tree_size         INTEGER NOT NULL,
    root_hash         BLOB    NOT NULL CHECK (length(root_hash) = 32),
    timestamp         INTEGER NOT NULL,
    signature         BLOB    NOT NULL CHECK (length(signature) = 64),
    fetched_at        INTEGER NOT NULL,
    witness_signature BLOB CHECK (witness_signature IS NULL OR length(witness_signature) = 64),
    PRIMARY KEY (server_url, chain_id, tree_size, root_hash)
);
```

`root_hash` in the primary key is intentional: two STHs at the same `tree_size` with different roots coexist as evidence. Same-size equivocation is detected by counting distinct `root_hash` per `(server, chain, tree_size)` after insert. Different-size forks are detected via §8.1 step 3 and durably recorded in `witness_consistency_failures`.

On startup, the witness inspects `PRAGMA table_info(witness_sths)`. Archives
created before cosigning are migrated in place by adding the nullable
`witness_signature` column. Existing STH evidence remains readable but is not
treated as cosigned; new rows can carry and serve verified cosigns immediately.
The migration is idempotent.

When same-size equivocation is detected the witness logs:

```
fd0-witness: EQUIVOCATION DETECTED
  server: https://...
  chain : scope:s_xxx
  size  : 42
  root_a: <hex>  fetched_at <ts>  signature <hex>
  root_b: <hex>  fetched_at <ts>  signature <hex>
Both signatures verify under the pinned server pubkey.
```

Both signed STHs are evidence: each is a server commitment to a different root at the same size.

### 8.3 Cosign and cross-check

Four read endpoints make the witness archive externally queryable.
Summary:

| Endpoint                         | Returns                       | Use |
|----------------------------------|-------------------------------|-----|
| `/v1/server-info`        | `witness_pub`                 | first-contact pinning |
| `/v1/sth/<srv>/<chain>`  | `WitnessedSTH` or 404 / 409  | per-sync cosign check |
| `/v1/highest/<srv>/<chain>` | `{observed, tree_size}`     | first-fetch rollback probe (T41) |
| `/v1/equivocation/<srv>/<chain>` | `{equivocated}`        | historical-equivocation probe (T35) |

Detail follows.

The witness signs a cosign per archived STH using domain `fd0-witness-cosign-v1`:

```
WitnessedSTH = {
    sth         : STH,
    server_url  : tstr,            ; canonical server URL
    witness_pub : bstr .size 32,
    witness_sig : bstr .size 64,   ; Ed25519(witness_priv,
                                   ;   "fd0-witness-cosign-v1" || cbor({sth, server_url}))
}
```

Cosigns are withheld whenever the consistency check in §8.1 step 3 fails — the witness will not become a signing oracle for forks.

Witness HTTP API (all responses are `application/cbor`):

```
GET /v1/server-info
→ 200 — { witness_pub, witness_pub_hex }      ; not signed; pin out of band

GET /v1/sth/{server_b64}/{chain_id}[?tree_size=N]
→ 200 — WitnessedSTH (latest cosigned, or at the requested tree_size)
→ 404 if not observed, or no cosigned STH is available at the requested size
→ 409 if multiple distinct roots are archived at the requested tree_size (equivocation evidence)

GET /v1/highest/{server_b64}/{chain_id}
→ 200 — { observed: bool, tree_size: uint }   ; highest tree_size ever archived for (server, chain)

GET /v1/equivocation/{server_b64}/{chain_id}
→ 200 — { equivocated: bool }                 ; true iff any tree_size has multiple distinct roots
```

Clients configure pinned witnesses in `[[witness]]` config and a quorum threshold via `[witness_policy] min_cosigns`. On every sync the client requires `min_cosigns` matching cosigns at the server-supplied STH; queries `/highest` to detect first-fetch rollback (T41); queries `/equivocation` to detect historical equivocation across the chain (T35). A 409 from `/sth` or a positive `/equivocation` is a hard refusal.

---

## 9. Full-history clients and legacy repair

- The server never compacts. Its tree grows monotonically for each chain.
- Current clients retain every signed local event and require contiguous `seq` and `prev_hash` links during replay.
- A non-contiguous file is never exposed to a read command. During sync, the client performs a full pull from `cursor=0`, verifies the pinned server's STH and inclusion proofs, preserves local-only writes, and atomically replaces the file.
- The verified final STH becomes the new `LastSTH` anchor only after replay succeeds. Any failure restores the original local chain and vault state.

A fresh device performing a full pull (`cursor=0`) effectively gets `last_sth_size=0` (no persisted STH). It receives every event with an inclusion proof, plus a consistency proof from `from_size=0` to `to_size=tree_size` (trivially satisfied — any tree is consistent with empty). The first STH the device persists becomes the anchor for all subsequent syncs.

---

## 10. Deferred to v1.x and beyond

- **Server STH archive endpoint.** `translog_sths` is populated server-side; exposing `GET /v1/sth/{cid}?at_size={n}` would let witnesses backfill historical STHs. v1.0 serves only the current STH.
- **Signature batching.** Each `/sync` round signs one STH per affected chain. With N pulled scopes the server signs N STHs. A combined STH over all N `(chain_id, root_hash)` pairs is a v2 optimisation.

---

## 11. Peer hints (v0.0.4+)

A server with sibling replicas declares them in `/v1/server-info` via the optional `peers` field. The intent is **discovery, not trust**: the publishing server provides a SIGNED HINT that a peer exists with a particular pubkey; the client decides whether to use the hint.

### 11.1 Server side

```
FD0_LABEL=swu-ulm                                # self-declared identifier
FD0_PEERS=https://api2.fd0.sh                    # comma-separated peer URLs
```

The server runs a background resolver that hits each peer's `/v1/server-info` on boot and every `PeerResolveInterval` (default 1h). On first success it TOFU-pins the peer's signing pubkey in the local `peers` table; on subsequent successes it refreshes the peer's self-declared label and the `last_verified` timestamp. A pubkey mismatch on a later resolve is REFUSED — the operator must delete the row by hand (`DELETE FROM peers WHERE url = ?`) to allow a key rotation, so transient impersonation can't silently overwrite the pin.

The `peers` array in `/v1/server-info` is built from this table, sorted by URL, and signed alongside the rest of the record. A peer that fails resolution is RETAINED with its last-known pubkey and label — a transient outage at one peer must not silently drop it from the published list.

Peer `label` is filtered through the same `[a-z0-9-]{0,32}` charset the server applies to its own `FD0_LABEL`. A peer that publishes an invalid label is stored without a label; the pubkey + URL still pin. This keeps downstream UI safe from ANSI escapes / control characters smuggled through a hostile peer.

### 11.2 Client side

The client treats `peers` as informational metadata, not a sync target. There is no multi-server client sync: a client reads and writes exactly one primary (`[sync].server` in `~/.fd0/config.toml`). The peer list instead authorises server-to-server DR-backup replication — a standby with `FD0_REPLICATE_FROM=<primary>` is allowed to pull the primary's chains only because the primary lists it in `FD0_PEERS`. Auto-pinning a server-provided peer claim would let one malicious operator silently inject Sybil replicas under their control.

Future revisions MAY add `fd0 peer add <url>` to import a hint with confirmation, and `fd0 peer audit` to compare each pinned server's peer list against the others (intersection-trust). Both layer on top of the wire format defined here without protocol changes.

### 11.3 Security properties

- A server cannot fabricate a peer that doesn't exist with a real pubkey: the peer field is signed by the server, but the consuming client never trusts it without ALSO pinning the peer itself via the first-contact ceremony (§6.1). So the worst a malicious server can do is publish phantom peers — annoying for monitoring, useless as an attack vector.
- A server CAN refuse to publish a real peer it dislikes. This is observable: a client configured for both servers can fetch each one's `/v1/server-info` and notice that A doesn't list B while B lists A.
- Peer pubkey rotation is a manual operator step on every server that lists the rotating peer. This is intentional: silent re-TOFU would defeat the pin.

---

## 12. Threat-model implications

The transparency log changes how `THREATS.md` reasons about server
equivocation:

- **T35 server equivocation between clients** — promoted from
  acknowledged limit to detected-by-construction. Divergent
  histories produce divergent STHs at the same `tree_size`;
  any party comparing STHs out of band (cross-device, witness
  archive, client-witness cross-check) catches them.
- **T46 server-key compromise** — terminates equivocation
  detection for STHs signed under the compromised key. Operators
  rotate via the ceremony in §4.3; every client re-pins.
- **T41 first-fetch checkpoint rollback** — requires at least one
  witness to have observed the chain before the rollback. A
  truly-first-contact client with no witness has only the
  cross-device tip-comparison user-ceremony fallback.

See `THREATS.md` for the full catalog entries.
