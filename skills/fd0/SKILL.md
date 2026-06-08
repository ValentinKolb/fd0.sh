---
name: fd0
description: Use this skill whenever the user — or an agent acting on the user's behalf — needs to store, fetch, share, or organize secrets with the fd0 CLI (`fd0 init`, `fd0 set`, `fd0 get`, `fd0 sync`, `fd0 scope ...`, `fd0 card ...`). Trigger on any of these phrasings even when the user does not name fd0 explicitly:  "store a deploy key", "save this API token", "fetch my DB password", "share a credential with bob", "add bob to the work scope", "rotate access", "set up my passphrase", "vault locked", "lock failed", "sync errored". Also trigger when an agent in the middle of another task needs to inject a credential into a script or deploy step — `fd0 get NAME` is the canonical retrieval path. Do NOT trigger for hosting or operating the fd0-server; that is a separate concern documented in this project's docs/HOSTING.md.
---

# fd0 — Zero-knowledge secrets CLI

fd0 stores credentials client-side under a passphrase (or YubiKey), syncs ciphertext-only to a server, and shares scope-by-scope with teammates via cryptographic membership. The server cannot decrypt anything. Every change is a signed event, every server tree-head is countersigned by an independent witness.

Use this skill when the user wants to **manage their own secrets** with fd0. For the protocol model and trust guarantees, read `references/protocol.md`. For installing fd0 itself, read `references/install.md`.

## Decision tree

Map the user's intent to the right command before typing anything:

| User intent | Command |
|---|---|
| First-time setup on a fresh device | `fd0 init` then `fd0 unlock` |
| Store a credential | `fd0 set NAME VALUE [--scope LABEL]` |
| Retrieve a credential to stdout | `fd0 get NAME [--scope LABEL]` |
| Retrieve to clipboard, auto-clear | `fd0 copy NAME [--clear-after=30s]` |
| List secrets | `fd0 ls` |
| Forget a credential | `fd0 rm NAME` (tombstone, vanishes on compaction) |
| Organize related secrets | `fd0 scope create --label LABEL` |
| Share a scope with a person | They run `fd0 card export`, you `fd0 card import URL --label THEIR_NAME --yes`, then `fd0 scope add-member THEIR_NAME --scope LABEL` |
| Revoke access | `fd0 scope remove-member LABEL --scope LABEL` (rotates the per-scope key — they lose access on next sync) |
| Pull / push to server | `fd0 sync` |
| Confirm vault state | `fd0 doctor` (read-only check) |
| End the session | `fd0 lock` |

Every command except `fd0 sync` is local. `sync` is the only one that touches the network.

## Mental model

Three layers, in order of trust:

1. **Identity** — `super_priv` is the root ed25519 key. It lives mlocked inside `fd0-agent` once `fd0 unlock` runs and is wiped from memory on `fd0 lock` or `agent idle-timeout`. Loss of `super_priv` is permanent unless the user exported recovery (see Recovery below).
2. **Scopes** — Named containers (`work`, `personal`, etc). Each scope has an Object Encryption Key (OEK) that encrypts every secret in that scope. Members of a scope hold the OEK wrapped to their own card.
3. **Secrets** — Encrypted under the scope's current OEK. The server only sees ciphertext + signed metadata.

Adding a member wraps the OEK to their card. Removing a member rotates the OEK so future secrets in that scope are unreadable by them. This is **cryptographic** revocation, not policy. They cannot read what comes after `remove-member`, full stop.

## First-time setup

```
fd0 init            # generate identity, set passphrase (TWO entries — confirmation)
fd0 unlock          # decrypts the vault, spawns the agent, holds super_priv mlocked
fd0 sync            # registers identity with the configured server(s)
```

Defaults: client targets `https://api.fd0.sh` + `https://api2.fd0.sh` (the hosted instance, both replicas, multi-pushed). To self-host, the user edits `~/.fd0/config.toml` before `fd0 sync`:

```toml
[sync]
servers = ["https://your-server.example"]
```

The first sync to each server triggers a TOFU pin: fd0 prints a 12-group fingerprint, the user verifies it out of band, and types `y`. Subsequent syncs short-circuit. **Never bypass this** unattended with `FD0_AUTO_PIN=1` unless the user has explicitly accepted the risk for a scripted context.

## Storing and fetching

```
fd0 scope create --label work
fd0 set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxx" --scope work
fd0 set DB_PASSWORD - --scope work          # `-` (positional, not a flag) reads VALUE from stdin
                                            # — hides the secret from shell history and from `ps`
fd0 get DEPLOY_KEY --scope work             # plaintext to stdout
fd0 copy DEPLOY_KEY --clear-after=30s       # clipboard, auto-cleared
fd0 ls                                       # names across all scopes
fd0 sync                                     # push the new event(s)
```

Without `--scope`, fd0 looks up the secret across all scopes. If the name exists in exactly one scope it succeeds; if it is ambiguous it errors.

When fetching for a non-interactive context (e.g. CI script substitution, automation), prefer `fd0 get NAME --raw` — `--raw` strips trailing newlines that would otherwise pollute environment-variable assignments.

## Sharing a scope

The card-exchange flow has three steps. The two humans must verify safety numbers out of band — fd0 prints them to stderr.

**Alice creates a scope and writes some secrets** (her side):
```
fd0 scope create --label deploy
fd0 set GITHUB_TOKEN "ghp_..." --scope deploy
fd0 sync
```

**Both sides exchange cards** (each side runs `card export`, sends the URL to the other side, the other side imports):
```
alice$ fd0 card export                       # prints fd0://card/...  (safety number to stderr)
bob$   fd0 card export                       # same

# Each verifies the OTHER side's safety number out of band (Signal, in person, video call).
# Then pins:
alice$ fd0 card import "fd0://card/..." --label bob   --yes
bob$   fd0 card import "fd0://card/..." --label alice --yes
```

**Alice adds bob to the scope**:
```
alice$ fd0 scope add-member bob --scope deploy
alice$ fd0 sync
```

**Bob discovers the scope on his next sync** — he can now read every secret Alice has stored in `deploy`, including any she sets later, until she removes him.

## Revoking access

```
alice$ fd0 scope remove-member bob --scope deploy
alice$ fd0 sync
```

This generates a new OEK for the `deploy` scope, wrapped to every remaining member but NOT to bob. Any secret Alice writes AFTER this point is unreadable by bob even if he intercepts the ciphertext. Bob's local client drops the scope on his next sync.

Bob still has whatever he downloaded BEFORE the rotation. Treat anything he saw as compromised and rotate the underlying credentials (the actual GitHub token, the actual database password) out-of-band.

## Recovery

`super_priv` is the root of the user's identity. Lose it and they cannot decrypt anything they wrote, even with the passphrase. fd0 ships a recovery export that is encrypted under a separate recovery passphrase:

```
fd0 recovery export ~/fd0-recovery.cbor       # encrypted; ask twice for a new passphrase
# Store ~/fd0-recovery.cbor offline: paper QR, encrypted USB, password manager.
```

To restore on a fresh device:

```
fd0 recovery import ~/fd0-recovery.cbor
fd0 unlock
fd0 sync                                       # auto-discovers every scope the identity is in
```

When the user is about to do anything destructive — `fd0 auth rm`, `fd0 init` over an existing home, switching devices — recommend `fd0 recovery export` first if they have not done it.

## Diagnostics

When something looks off, run **`fd0 doctor`** first. It is read-only and reports:

- Replay of the user chain and every scope chain
- `auth_tip` and per-scope `chain_tip` against the on-disk events
- Auth methods vs vault wraps (no orphans either way)
- Witness cross-check policy if configured

A `doctor` failure points at a specific check; treat its message as the entry point to the problem rather than guessing.

## Security rules

These are not negotiable. The skill is useless and dangerous without them.

1. **Never** echo, log, store-in-variable, or paste-to-clipboard a passphrase. Pipe through stdin (`printf '%s\n' "$pass" | fd0 ...`) only in trusted scripts that the user explicitly authored. Important: fd0 has **no `--stdin` flag** — it reads from stdin automatically when stdin is not a TTY. Do not invent `fd0 unlock --stdin` or similar; the pipe alone is the contract.
2. **Never** set `FD0_AUTO_PIN=1` without the user's explicit consent. The TOFU prompt exists so a MITM cannot silently pin its own key.
3. **Never** dump `~/.fd0/vault.enc` or `~/.fd0/chains/` to a remote location for "debugging" — they contain ciphertext but their existence + size + chain tip is metadata.
4. When `fd0 copy` runs, mention the auto-clear time (`--clear-after`) so the user does not assume the clipboard is permanent.
5. Confirm before `fd0 rm`, `fd0 scope leave`, `fd0 auth rm`, and `fd0 recovery import` — each one is destructive or irreversible without a backup.
6. When the user has not run `fd0 recovery export`, prompt them to do it before any operation that could lose `super_priv` (re-init, device migration, `auth rm` of the last method).

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `not unlocked` / `agent not running` | No active agent | `fd0 unlock` |
| `another fd0 instance holds the lock` | Stale agent or concurrent op | Wait, or `fd0 lock` then retry; if persistent, `ps aux \| grep fd0-agent` and kill the stale PID |
| `429 Too Many Requests` on register | Per-IP rate limit | Retry after the `retry-after` seconds; do not loop |
| `pinned-key-mismatch` on sync | Server's translog key rotated, or MITM | STOP. Verify the new fingerprint out-of-band BEFORE re-pinning. `~/.fd0/config.toml` does not need editing — fd0 walks through the ceremony |
| `witness cross-check failed` | Witness disagrees with server | STOP. Possible equivocation. Open an issue with the server operator |
| `no server configured` | No `[sync].servers` set, no `FD0_SERVER` env, defaults disabled somehow | Add `[sync].servers = [...]` or pass `--server URL` |
| Sync says `pushed=0 dup=0` repeatedly | No local events to push | Normal — sync still pulls. Use `fd0 doctor` to confirm local state is sane |

## When to read the reference files

- **`references/protocol.md`** — Before answering questions about what the server can/cannot see, why removing a member actually revokes access, how the transparency log works, or what "ciphertext-only contract" means. Also before discussing trust assumptions for self-hosting vs hosted.
- **`references/install.md`** — When the user wants to install or update fd0 itself, or wants to install this skill in a different setup. Includes `bunx skills add` and manual paths.

## When NOT to use this skill

- The user is operating the **fd0 server** (`fd0-server`, `fd0-witness`) — refer them to `docs/HOSTING.md` instead.
- The user is asking about the **fd0 source code** or wire protocol internals — refer to `docs/PROTOCOL.md`, `docs/STORAGE.md`, `docs/TRANSLOG.md`.
- The user wants a different secrets manager (Bitwarden, 1Password, Vault) — do not pitch fd0; just help with what they asked.
