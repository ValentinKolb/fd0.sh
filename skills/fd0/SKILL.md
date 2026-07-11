---
name: fd0
description: >-
  Use this skill whenever the user — or an agent acting on the user's behalf — needs to store, fetch, share, or organize secrets with the fd0 CLI (`fd0 init`, `fd0 set`, `fd0 get`, `fd0 sync`, `fd0 scope ...`, `fd0 card ...`), use fd0 as a password manager (`fd0 pass ...`), manage SSH keys and hosts (`fd0 key ...`, `fd0 ssh ...`), or manage Talos Linux / Kubernetes credentials (`fd0 talos ...`, `fd0 kube ...`). Trigger on any of these phrasings even when the user does not name fd0 explicitly — "store a deploy key", "save this API token", "fetch my DB password", "share a credential with bob", "add bob to the work scope", "rotate access", "set up my passphrase", "vault locked", "lock failed", "sync errored", "open my password manager", "store a login", "copy my GitHub password", "add a TOTP code", "attach a recovery key file", "generate an ssh key", "share ssh access with the team", "connect to the prod box", "store the talosconfig", "share the kubeconfig", "bootstrap a talos cluster". Also trigger when an agent in the middle of another task needs to inject a credential into a script or deploy step — `fd0 get NAME` or `fd0 pass field get ITEM FIELD --raw` is the canonical retrieval path. Do NOT trigger for hosting or operating the fd0-server; that is a separate concern documented in this project's docs/HOSTING.md.
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
| Open the password-manager UI | `fd0 pass` (or `fd0 pass QUERY`) |
| Create a login item | `fd0 pass add NAME --url URL [--scope LABEL]` |
| Add username/password fields | `fd0 pass field set NAME username VALUE`; `fd0 pass field set NAME password --secret --generate` |
| Copy a password-manager field | `fd0 pass copy NAME [FIELD] [--clear-after=30s]` |
| Generate a password without storing | `fd0 pass generate [--length 32]` |
| Show a pass item safely | `fd0 pass show NAME` (masked by default; `--reveal` only when explicitly needed) |
| Store a passkey field | `fd0 pass field set NAME passkey VALUE --type passkey` |
| Add or print TOTP | `fd0 pass totp add NAME 'otpauth://...'`; `fd0 pass totp code NAME` |
| Attach a small key/recovery file | `fd0 pass file add NAME PATH [FIELD]` (32 KiB max per file) |
| Export an attached file | `fd0 pass file export NAME FIELD --out PATH` |
| Organize related secrets | `fd0 scope create --label LABEL` |
| Share a scope with a person | They run `fd0 card export`, you `fd0 card import URL --label THEIR_NAME --yes`, then `fd0 scope add-member THEIR_NAME --scope LABEL` |
| Revoke access | `fd0 scope remove-member LABEL --scope LABEL` (rotates the per-scope key — they lose access on next sync) |
| Pull / push to server | `fd0 sync` |
| Confirm vault state | `fd0 doctor` (read-only check) |
| Check installed client flavor | `fd0 version` (`standard` or `yubikey`) |
| Install fd0 Desktop with its managed CLI and agent | `curl -fsSL https://fd0.sh/install \| sh -s -- --desktop` |
| Install YubiKey-capable client | `curl -fsSL https://fd0.sh/install \| sh -s -- --yubikey` |
| Switch an existing install to YubiKey flavor | `fd0 update --flavor=yubikey` then `fd0 agent restart` |
| Set this device's default unlock method | `fd0 auth default yubikey` or `fd0 auth default passphrase` |
| End the session | `fd0 lock` |
| Generate an SSH key (ed25519, in-vault) | `fd0 key add NAME [--scope LABEL]` — prints the authorized_keys line |
| Import an existing SSH key | `fd0 key add NAME --import PATH` (encrypted RSA/ECDSA are refused — decrypt first) |
| Show a public key for authorized_keys | `fd0 key show NAME --pub` |
| Add an SSH host | `fd0 ssh add ALIAS [user@]host[:port] [--key NAME \| --with-key] [--jump ALIAS] [--tag T]` |
| Connect to a host | `fd0 ssh ALIAS` (or bare `fd0 ssh` for the fuzzy picker) |
| One-time SSH setup | `fd0 ssh enable` + `export SSH_AUTH_SOCK="$(fd0 ssh sock)"` in your shell rc |
| Store a Talos context | `fd0 talos add NAME --from-config ~/.talos/config` (or per-field `--ca-file/--crt-file/--key-file`) |
| Bootstrap a new Talos cluster (day-0) | `fd0 talos new NAME --endpoint https://IP:6443 [--vault-scope LABEL]` (needs `talosctl`) |
| Render + merge talosconfig | `fd0 talos sync --merge` |
| Onboard a teammate to a Talos cluster | `fd0 talos role-add --from CTX --name NAME --role os:operator` (needs `talosctl`) |
| Store / export the DR secrets.yaml | `fd0 talos secrets import\|export NAME --in\|--out FILE` |
| Store a kubeconfig | `fd0 kube add NAME --from-config ~/.kube/config` (or per-field `--server/--ca-file/...`) |
| Fetch a fresh kubeconfig from Talos | `fd0 talos kubeconfig CTX` (needs `talosctl`) |
| Render + merge kubeconfig | `fd0 kube sync --merge` |

Every command except `fd0 sync` is local. `sync` is the only one that touches the network. The `pass`/`key`/`ssh`/`talos`/`kube` families all store their material as ordinary scope-shared secrets, so sharing a password item, SSH key, host alias, or talosconfig with a teammate is the same `scope add-member` flow.

`add`, `new`, and `move` across feature families refuse to overwrite an existing name by default — pass `--force` to overwrite knowingly.

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
fd0 sync            # registers identity with the configured server
```

Defaults: client targets the single primary `https://api.fd0.sh` (the hosted instance; `api2.fd0.sh` is a server-side DR backup, not a second client target). Every write and read for every scope goes to that one primary. To self-host, the user edits `~/.fd0/config.toml` before `fd0 sync`:

```toml
[sync]
server = "https://your-server.example"
```

The first sync triggers a TOFU pin: fd0 prints a 12-group fingerprint, the user verifies it out of band, and types `y`. Subsequent syncs short-circuit. **Never bypass this** unattended with `FD0_AUTO_PIN=1` unless the user has explicitly accepted the risk for a scripted context.

## Default unlock method

Use `fd0 auth default METHOD` when a device should prefer one unlock method without a shell alias:

```
fd0 auth ls
fd0 auth default yubikey      # or passphrase, or a method_id from auth ls
fd0 auth default              # show the current device default
fd0 auth default --clear      # return to fd0's built-in selection
```

The setting is local to the current device in `~/.fd0/config.toml` under `[auth].default_method`. It is not synced, does not add or remove auth methods, and does not change vault wraps. `fd0 unlock --method=...` still overrides the local default for that invocation.

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

## Password manager

`fd0 pass` is the structured password-manager surface. It stores each item as a typed, scope-shared secret (`fd0.pass.item`) with:

- item title and URL matchers
- fields of type `text`, `secret`, `totp`, `passkey`, `file`, or `section`
- recursive sections by slash path, up to four levels deep
- per-item metadata for future GUI/autofill use
- small encrypted file attachments, capped at 32 KiB per file and 60 KiB per item

Bare `fd0 pass` opens the interactive terminal browser. `fd0 pass QUERY` opens the same browser with an initial search. In the browser, secrets are masked by default; use the visible shortcuts for copy/reveal. `q` and `esc` quit/back out.

Common interactive flow:

```
fd0 pass                          # browse all pass items
fd0 pass github                   # browse with initial query
fd0 pass --scope work             # browse one scope
```

Common scriptable flow:

```
fd0 pass add github --url https://github.com --scope work
fd0 pass field set github username valentin@example.com --scope work
fd0 pass field set github password --secret --generate --length 32 --scope work
fd0 pass field set github passkey '{"credential_id":"..."}' --type passkey --scope work
fd0 pass totp add github 'otpauth://totp/GitHub:valentin@example.com?secret=...' --scope work
fd0 pass section add github Recovery --scope work
fd0 pass field set github Recovery/code-1 "1234-5678" --secret --scope work
fd0 pass file add github ~/.ssh/recovery-key.pem SSH/recovery-key.pem --scope work
fd0 sync
```

Read and copy:

```
fd0 pass list --scope work
fd0 pass find github
fd0 pass find --url https://github.com/login
fd0 pass show github                  # masked by default
fd0 pass show github --reveal         # only when the user explicitly asks
fd0 pass copy github                  # copies preferred secret field: password/pass
fd0 pass copy github username
fd0 pass totp code github
fd0 pass field get github username --raw
fd0 pass file export github SSH/recovery-key.pem --out ./recovery-key.pem
```

Use `fd0 pass field set NAME PATH - --secret` for values that should not appear in shell history. A pass item is shared by sharing its scope; there is no separate per-item ACL. For browser/autofill-style lookup, use `fd0 pass find --url URL --json` and then retrieve the needed field explicitly.

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
- fd0/fd0-agent release flavor and YubiKey/PIV capability
- Witness cross-check policy if configured

A `doctor` failure points at a specific check; treat its message as the entry point to the problem rather than guessing.

## YubiKey unlock

YubiKey/PIV unlock is supported by the official `yubikey` client flavor. Do **not** tell normal users to build from the repo unless they are explicitly doing development work.

Check the installed flavor first:

```
fd0 version          # fd0 X.Y.Z standard OR fd0 X.Y.Z yubikey
fd0 doctor           # reports fd0/fd0-agent capability and mismatches
```

Install or switch to the YubiKey flavor:

```
curl -fsSL https://fd0.sh/install | sh -s -- --yubikey
# or, for an existing install:
fd0 update --flavor=yubikey
fd0 agent restart
```

Both `fd0` and `fd0-agent` must be the `yubikey` flavor. If `fd0 doctor` reports a mismatch after update, restart the agent before retrying enrollment or unlock.

After enrolling a YubiKey, suggest `fd0 auth default yubikey` only if the user wants plain `fd0 unlock` on that device to use the YubiKey. Keep passphrase unlock enrolled as recovery unless the user has a tested recovery export and explicitly accepts the risk.

## Security rules

These are not negotiable. The skill is useless and dangerous without them.

1. **Never** echo, log, store-in-variable, or paste-to-clipboard a passphrase. Pipe through stdin (`printf '%s\n' "$pass" | fd0 ...`) only in trusted scripts that the user explicitly authored. Important: fd0 has **no `--stdin` flag** — it reads from stdin automatically when stdin is not a TTY. Do not invent `fd0 unlock --stdin` or similar; the pipe alone is the contract.
2. **Never** set `FD0_AUTO_PIN=1` without the user's explicit consent. The TOFU prompt exists so a MITM cannot silently pin its own key.
3. **Never** dump `~/.fd0/vault.enc` or `~/.fd0/chains/` to a remote location for "debugging" — they contain ciphertext but their existence + size + chain tip is metadata.
4. When `fd0 copy` runs, mention the auto-clear time (`--clear-after`) so the user does not assume the clipboard is permanent.
5. Prefer `fd0 pass copy` over `fd0 pass show --reveal` for passwords/TOTP/secrets. Use `--reveal`, `pass field get`, or `pass file export` only when plaintext output is explicitly needed and keep it out of logs.
6. Confirm before `fd0 rm`, `fd0 pass rm`, `fd0 pass field rm`, `fd0 scope leave`, `fd0 auth rm`, and `fd0 recovery import` — each one is destructive or irreversible without a backup.
7. When the user has not run `fd0 recovery export`, prompt them to do it before any operation that could lose `super_priv` (re-init, device migration, `auth rm` of the last method).

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `not unlocked` / `agent not running` | No active agent | `fd0 unlock` |
| `another fd0 instance holds the lock` | The agent's background auto-sync (or another fd0) holds the flock; the client already waits ~5s before failing | Usually transient — just retry. If it persists, make sure no other fd0 is running: `ps aux \| grep fd0-agent`, kill a stale PID, then retry |
| `fd0 SSH agent socket unavailable` / `Connection refused` from `ssh-add -L` | fd0-agent is running but its SSH-agent listener is stale or was started with the wrong socket path | Run `fd0 agent restart`. |
| `standard flavor (YubiKey/PIV disabled)` while enrolling YubiKey | Installed client is the standard release flavor | Run `fd0 update --flavor=yubikey`, then `fd0 agent restart` |
| YubiKey unlock says running agent lacks support | `fd0` was updated but old `fd0-agent` is still running | Run `fd0 agent restart`; then check `fd0 doctor` |
| `fd0 is managed by fd0 Desktop` during `fd0 update` | The command belongs to the signed Desktop bundle | Open fd0 Desktop, then use **Support > Check now** so app, CLI, and agent update together |
| `429 Too Many Requests` on register | Per-IP rate limit | Retry after the `retry-after` seconds; do not loop |
| `pinned-key-mismatch` on sync | Server's translog key rotated, or MITM | STOP. Verify the new fingerprint out-of-band BEFORE re-pinning. `~/.fd0/config.toml` does not need editing — fd0 walks through the ceremony |
| `witness cross-check failed` | Witness disagrees with server | STOP. Possible equivocation. Open an issue with the server operator |
| `no server configured` | No `[sync].server` set, no `FD0_SERVER` env, defaults disabled somehow | Add `[sync].server = "URL"` or pass `--server URL` |
| Sync says `pushed=0 dup=0` repeatedly | No local events to push | Normal — sync still pulls. Use `fd0 doctor` to confirm local state is sane |

## When to read the reference files

- **`references/protocol.md`** — Before answering questions about what the server can/cannot see, why removing a member actually revokes access, how the transparency log works, or what "ciphertext-only contract" means. Also before discussing trust assumptions for self-hosting vs hosted.
- **`references/install.md`** — When the user wants to install or update fd0 itself, or wants to install this skill in a different setup. Includes `bunx skills add` and manual paths.

## When NOT to use this skill

- The user is operating the **fd0 server** (`fd0-server`, `fd0-witness`) — refer them to `docs/HOSTING.md` instead.
- The user is asking about the **fd0 source code** or wire protocol internals — refer to `docs/PROTOCOL.md`, `docs/STORAGE.md`, `docs/TRANSLOG.md`.
- The user wants a different secrets manager (Bitwarden, 1Password, Vault) — do not pitch fd0; just help with what they asked.
