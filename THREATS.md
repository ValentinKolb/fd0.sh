# fd0 Threat Model (v1)

Companion to `PROTOCOL.md`. The reference attacker is the hosted server operator with full read/write access to the server's database and code. Network attackers are strictly weaker.

---

## 1. Engineering guarantees

Properties enforced by the protocol against a malicious server, given correct clients.

- **Confidentiality of secrets.** Scope event bodies are AEAD-encrypted under per-scope OEKs that never appear server-side in plaintext.
- **Confidentiality of `super_priv`.** Each auth method's `encrypted_super_priv` is AEAD-encrypted under a key derived from a credential the server does not hold.
- **Unforgeable events.** Every event is Ed25519-signed by an identity the server does not hold.
- **Unforgeable membership changes.** `member.change` is the only event kind that mutates membership; its `op`, `member`, and `key_deliveries` are validated against pre- and post-mutation state.
- **Forward secrecy on member churn.** Every `member.change` rotates the OEK. Events authored after a `member.change op="remove"` are unreadable by the removed member.
- **Checkpoint joins.** A new member receives only the current scope projection encrypted under the new OEK. Pre-admission events remain unreadable.
- **Tamper detection on the server-held chain.** Both event chains are hash-linked end-to-end on the server. Modification or reordering is detectable by any client that pulls from `cursor=0`.
- **Single-file rollback detection.** The vault binds the latest accepted seq+hash for the user chain and for every subscribed scope (`PROTOCOL.md` §6). A rollback that touches only the chain file or only the vault is detected on the next open and the client refuses to operate.
- **Per-key snapshot isolation.** Every `auth.set` and every `secret.set` is a complete signed snapshot of one key. A read is a single decrypt; manipulating prior events cannot change the latest value.
- **Replay protection.** Per-request `(pk, nonce, ts)` window; content-addressed event IDs plus `UNIQUE` constraint prevent stored-event replay.
- **No cross-context ciphertext reuse.** Each AEAD site has a distinct AAD domain prefix.
- **No cross-protocol signature reuse.** Each signature has a domain separator.
- **HTTP request integrity.** Signed input covers method, path, canonical query, body hash, timestamp, and nonce.
- **Login is read-only.** Logging in does not modify the user identity chain.
- **Self-healing replay.** On every open, `replay_chain` (`STORAGE.md` §4) verifies each event in full before installing any new OEK in the vault.
- **Idempotent leave-scope recovery.** A `member.change op="remove"` of self spans two filesystem operations (chain unlink + vault re-seal); the next open's recovery pass reconciles partial state.
- **Pruning of revoked vault wraps.** `WrappedKey.method_id` ties each unlock entry to a specific active `AuthMethod`. Wraps for inactive methods are pruned on every sync.

---

## 2. Acknowledged limits

- **Server equivocation.** A malicious server can present different consistent prefixes — or different parallel branches — of an event log to different clients. The hash chain catches modifications, not divergent views. v1 ships without a transparency log; the protocol is designed to accommodate one additively in v2 (witness-cosigned tree heads over chain tips, inclusion-proof endpoints, client gossip).
- **All members are admins.** v1 has no role separation. Any member of a scope can add or remove any other member.
- **Insider key-delivery.** The server validates the recipient set on `KeyDelivery` but cannot validate that each sealed box contains the actual OEK. A malicious authorized author can deliver an unusable OEK to one recipient. Remediable by another current member posting a fresh `member.change op="remove"` of the bad author.
- **Insider projection-poisoning.** Any current member can post a `member.change` with a manipulated projection. Existing members verify against their local `secret_index` and reject mismatches. A new member has no prior local state and trusts the inviter.
- **First-fetch checkpoint rollback (user chain).** A fresh device fetching `?latest=true` cannot tell whether the server is serving the actual latest `auth.set` or an older one (e.g., one still containing a revoked credential). Cross-device tip comparison out of band is the user-ceremony mitigation.
- **First-fetch projection trust (scope).** A fresh device receiving a `member.change op="add"` for itself trusts the inviter for the projection contents.
- **Server can hide self-removal.** A malicious server can withhold a `member.change op="remove"` of self from the affected client. Future events under the new OEK are unreadable, but the local subscription remains stale until manually pruned.
- **Server can withhold scope discovery.** Membership discovery rides on `/sync` with `discover_memberships=true`. A malicious server can return a stale or filtered list.
- **Coordinated local rollback.** An attacker with filesystem control can restore vault and chain files in lockstep (matching `auth_tip` and `chain_tip`). The single-file binding does not catch this. Mitigation is operational (filesystem permissions, full-disk encryption).
- **Local audit is not authoritative after compaction.** Compacted chain files drop superseded events; the local `prev_hash` chain has gaps. Audit-grade verification requires fetching from the server with `cursor=0`.
- **Identity rotation requires recovery export or re-onboarding.** If `super_priv` is compromised, the user re-onboards with a new identity. If `super_priv` is lost, the user restores from a recovery export (`PROTOCOL.md` §6.3) or re-onboards.
- **No forward secrecy for already-fetched data.** A removed member retains every OEK they had access to and can decrypt any event ciphertext they still hold. OEK rotation only protects events authored after removal.
- **No per-event forward secrecy.** All events under one OEK era share the same key. Compromise of an OEK exposes the entire era's data.
- **No post-compromise security.** Identity compromise is terminal; the protocol does not include a ratcheting mechanism that heals after key exposure.
- **Local-machine compromise.** Same-UID malware can read process memory. `mlock`, no-core-dumps, and zeroization mitigate but do not eliminate.
- **No protection against a coerced user.**
- **Server availability is not a security property.**
- **Metadata side channels.** The server learns scope membership, online times, event sizes, and the membership graph.
- **Server-side storage growth is unbounded.** The server retains events forever. Operationally bounded; not cryptographically bounded.

---

## 3. User-ceremony properties

Properties that depend on user behavior.

- **Safety-number first-trust verification.** When importing a card, the user compares the displayed safety number with the source via an authentic out-of-band channel.
- **Strong-passphrase choice.** In passphrase mode the security of `super_priv` reduces to the user's passphrase. The CLI displays a strength estimate; it does not enforce a minimum.
- **Recovery-passphrase strength.** `RecoveryFile` security depends on the user's recovery passphrase.
- **Custody of `shortId`.** Knowing a `shortId` enables fetching the encrypted user chain. In passphrase mode this enables offline brute force.
- **Card-channel integrity.** A card delivered via a channel an attacker controls can be substituted. Safety numbers detect this if compared.
- **Cross-device chain-tip comparison.** Detects server-side equivocation if compared out of band.
- **Inviter trust on join.** When `/sync` discovery surfaces a new scope, the CLI prompts before exposing secrets. The user verifies the invite out of band.
- **Storage of recovery exports.** The user is responsible for the safety and availability of `RecoveryFile`.

---

## 4. Out of scope

- OS-level defense in depth.
- Hardware-token compromise scenarios beyond "key extraction is hard".
- Side channels in the underlying primitives.
- Supply-chain attacks against fd0 binaries.
