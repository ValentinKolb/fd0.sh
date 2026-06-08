# fd0 protocol — high-level

This reference exists so an agent using the fd0 CLI can reason about what is and is not protected, and what the constraints actually are. For exhaustive cryptographic detail, read `docs/PROTOCOL.md`, `docs/STORAGE.md`, `docs/TRANSLOG.md`, and `docs/THREATS.md` in the source repository.

## One-sentence summary

The server stores ciphertext and signed events; every secret is sealed client-side under a per-scope key, scope membership is a cryptographic operation (not policy), and every server tree-head is countersigned by an independent witness so a server cannot show different histories to different clients without leaving a publishable proof.

## What the server sees

| Layer | Visible | Not visible |
|---|---|---|
| Wire | TLS-terminated request timing, source IP, request size | Plaintext request body — encrypted at the protocol layer |
| Storage | Ciphertext + signed event headers, chain tips, STH archive | Secret values, secret names, scope memberships, passphrases, OEKs, super_priv |
| Operational | Stop the service, change DNS, sign a new STH | Decrypt anything in the storage column, even with root |

The server's operator can withhold service (denial), trigger replay-by-restore, or fork the log. None of these let the operator read plaintext. All of them are detected by clients or witnesses.

## Identities

Every user holds an ed25519 `super_keypair`. The private half (`super_priv`) lives:

1. **On disk** wrapped under the unlock passphrase (or YubiKey-PIV X25519 key), in `~/.fd0/vault.enc`.
2. **In memory** mlocked inside `fd0-agent` after `fd0 unlock` runs. The agent zeroes it on `fd0 lock`, on the configured idle timeout, or on max-lifetime.
3. **Optionally on a paper QR** or other off-host medium, via `fd0 recovery export`. The export is itself encrypted under a separate recovery passphrase.

`super_priv` is the root of identity. Loss without a recovery export means the user cannot decrypt anything they wrote.

## Scopes and the OEK

A **scope** is a named container of secrets (`work`, `personal`, etc.). Every scope has a current **Object Encryption Key** (OEK) — a symmetric key that encrypts every secret in that scope.

For each scope member, the OEK is wrapped (via X25519 sealed-box) to that member's super_pub. Adding a member is a `member.change op=add` event that wraps the current OEK to their key. Removing a member is a `member.change op=remove` event that generates a NEW OEK and re-wraps it to every remaining member but not the removed one.

The cryptographic consequence: after `remove-member`, any secret written under the new OEK cannot be decrypted by the removed member, even if they intercept the ciphertext from the wire. This is what "cryptographic membership" means.

Caveat the agent must explain to users: removal does NOT retroactively un-leak secrets the removed member already read. Treat anything they had access to before removal as compromised and rotate the underlying credentials (the actual GitHub token, the actual database password) out-of-band.

## Events and chains

Every state-changing operation is an event. Events are append-only and chained: each event's `prev_hash` covers the previous event in its chain. There are two chain kinds per user:

- **User chain** — `user:<shortId>`. Contains `auth.set` events (adding or rotating unlock methods).
- **Scope chain** — `scope:<scope_id>`, one per scope. Contains `scope.create`, `member.change`, `secret.set`, `secret.remove`, and `oek.rotate` events.

Events are CBOR-encoded, signed by their author's super_priv, and content-addressed by `event_id = SHA256(canonical_cbor)`. The server's `events.event_id UNIQUE` constraint provides idempotent dedup: pushing the same event twice is a no-op.

This is why the multi-server client can push every event to every configured server — duplicates are handled at the storage layer for free.

## Transparency log

Every server maintains an RFC 6962 Merkle tree per chain. Every accepted event becomes a leaf. The server signs a Signed Tree Head (STH) per request that touched the tree. An STH covers `(chain_id, tree_size, root_hash, timestamp)`.

Clients receive an STH on every sync and verify:

1. The STH's signature against the pinned server pubkey.
2. The inclusion proof for every event the response claims to have stored.
3. The consistency proof from the previously-anchored STH to the new one (a server cannot rewrite history without breaking the proof chain).

Independent **witnesses** poll each server's STH and cosign honest tree-heads. Two clients comparing notes — or a third-party observer — detect equivocation: if the server signs two STHs at the same `tree_size` with different roots, both are valid evidence of misbehavior.

This is why clients enforce a "pin matches" rule on every sync. A pin-mismatch is either operator-side key rotation (requires manual ceremony) or attack — both deserve refusal until manually resolved.

## Multi-server replicas

A client can target multiple servers via `[sync].servers = [...]`. The default hosted-fd0.sh client targets `api.fd0.sh` + `api2.fd0.sh`.

Multi-server semantics:

- **Push** — every event is pushed to every configured server in the same sync round. Server-side idempotent dedup absorbs duplicates.
- **Read** — first server that answers wins; subsequent servers are tried on transport failure.
- **Per-server state** — push floor and last verified STH are tracked PER server in the vault (`ScopeVaultData.PerServer[url]`). Each server's translog is independent and verified against its own pin.
- **Server peering** — each server advertises its peer URLs + signed pubkeys in `/v1/server-info`. This is HINT, not authority — clients pin each server they actually use via the TOFU ceremony, independently.

There is currently no server-to-server gossip. Cross-replica event propagation relies entirely on multi-pushing clients. A client that pushes only to one server leaves that data unreachable from the others until any multi-pushing client syncs.

## What this means for an agent using fd0

When you're using fd0 on behalf of the user:

- A failed `fd0 sync` does NOT mean the secret was lost — locally-stored events survive in `~/.fd0/chains/`. Retry sync; do not re-prompt the user for the value.
- A `pinned-key-mismatch` error is a SECURITY EVENT, not a transient. Stop, surface it, and require the user to verify the new fingerprint out of band before re-pinning. The fd0 prompt walks through this.
- A `witness cross-check failed` error is also a security event. The server's STH is not what the witness saw. Stop and refer the user to the operator.
- After `fd0 scope remove-member`, recommend rotating the underlying credentials externally. The cryptographic revocation only applies to FUTURE writes.
- Removing a credential with `fd0 rm` writes a tombstone. The bytes do not vanish until the next compaction; tell the user to rotate the underlying credential if it was a real leak.

## Why these guarantees matter

fd0's design treats the server as a hostile-by-default storage broker. The threat model assumes the operator might:

- Be coerced by a legal authority
- Be compromised by an attacker
- Be the attacker

For each, the worst they can do is deny service, fork the log (detectable), or roll the state back (also detectable via STH monotonicity). They cannot read or modify a single byte of plaintext.

This is what an agent must keep in mind when answering "is it safe to put X in fd0?" The answer for any credential that fits in a few KB is yes — even if the operator goes rogue, the secret is mathematically protected.
