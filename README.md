# fd0

**Zero-knowledge encrypted secret store for individuals and teams.** Written in Go.

[Install](#install) · [Quickstart](#quickstart) · [Multi-member scopes](#multi-member-scopes) · [Configuration](#configuration) · [Recovery](#recovery) · [Build from source](#build-from-source) · [Security](#security) · [License](#license)

Four components:

- **`fd0`** — CLI client with inline TUI: passphrase/yubikey unlock, scope and secret commands, fuzzy search.
- **`fd0-agent`** — Unix-socket daemon. Holds `super_priv` mlocked, performs Ed25519 / X25519 / sealed-box on demand, runs periodic sync.
- **`fd0-server`** — HTTP API + SQLite. Stores ciphertext and signed metadata only; never sees plaintext.
- **`fd0-witness`** — Optional passive observer. Polls server STHs, cosigns honest ones, archives divergent ones. Detects server equivocation.

The server cannot read secrets. Membership changes rotate the per-scope key. Full spec: [docs/PROTOCOL.md](./docs/PROTOCOL.md), [docs/API.md](./docs/API.md), [docs/STORAGE.md](./docs/STORAGE.md), [docs/TRANSLOG.md](./docs/TRANSLOG.md), [docs/THREATS.md](./docs/THREATS.md). Release notes: [CHANGELOG.md](./CHANGELOG.md).

## Layout

This repo holds three things:

- **Go code** at the root (`cmd/`, `internal/`, `tools/`, `tests/`). Single module — `go install ./cmd/…` from the root builds everything.
- **Specs and reference docs** under [`docs/`](./docs/) — protocol, API, storage, transparency log, threat model, benchmarks.
- **Homepage** under [`website/`](./website/) — Bun + Hono + Tailwind, one static page rendered server-side.

The three are intentionally one repo: cross-cutting changes (a protocol revision that updates the spec, the implementation, and the homepage's wire-format example) land as one PR with one CHANGELOG entry.

## Install

Two scripts. Both detect an existing install, ask before upgrading, and verify the release manifest with cosign (auto-skip if cosign isn't installed; `--no-verify` to silence).

**Client** — workstation, laptop, any device that holds keys. Installs `fd0` and `fd0-agent` into `~/.local/bin` and seeds `~/.fd0/config.toml`. Pass `--system` for `/usr/local/bin`.

```bash
curl -fsSL https://raw.githubusercontent.com/ValentinKolb/fd0.sh/main/scripts/install.sh | sh
```

**Server** — host that stores ciphertext + transparency log. Installs `fd0-server` and `fd0-witness` into `/usr/local/bin`, creates the `fd0` system user, drops a hardened systemd unit at `/etc/systemd/system/fd0.service`, seeds `/etc/default/fd0-server`. Does **not** start the service — review the config first, then `sudo systemctl enable --now fd0`. Refuses to upgrade while the service is active (stop it first).

```bash
curl -fsSL https://raw.githubusercontent.com/ValentinKolb/fd0.sh/main/scripts/install-server.sh | sudo sh
```

Or run the server in Docker:

```bash
docker run -d --name fd0-server -p 4048:4048 -v fd0-data:/data \
  ghcr.io/valentinkolb/fd0-server:latest
```

## Quickstart

```bash
fd0 init                                 # generate identity, set passphrase
fd0 unlock                               # start agent, decrypt vault
fd0 scope create --label work
fd0 set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxx"
fd0 ls                                   # list secrets with scope label
fd0 get DEPLOY_KEY                       # plaintext to stdout
fd0 copy DEPLOY_KEY                      # to clipboard, auto-clears after 30s
fd0 get                                  # interactive fuzzy search
fd0 sync                                 # exchange with the configured server
fd0 lock                                 # zeroize agent, end session
```

## Multi-member scopes

```bash
# alice
fd0 card export                          # prints fd0://card/...
                                         # signed by alice; safety number on stderr

# bob receives alice's card via an authentic channel and pins it:
fd0 card import "fd0://card/..." --label alice

# alice invites bob:
fd0 card import "fd0://card/..." --label bob   # bob's card → alice's vault
fd0 scope add-member bob --scope work
fd0 sync

# bob's next sync auto-discovers the scope and decrypts via the agent's
# sealed-box (Ed25519-derived X25519 by default; YubiKey-PIV X25519 if enrolled):
fd0 sync
fd0 ls                                   # sees alice's secrets

# alice removes bob → OEK rotates, bob loses access on his next sync
fd0 scope remove-member bob --scope work
fd0 sync
```

## Configuration

`~/.fd0/config.toml`:

```toml
[sync]
server    = "http://127.0.0.1:4048"      # or via FD0_SERVER env
interval  = "1h"                          # periodic background sync; "" disables
on_unlock = true                          # sync immediately after unlock

[client]
lock_wait = "10s"                         # block up to 10s on ~/.fd0/.lock contention; "" = fail fast

[agent]
idle_timeout = "5m"                       # zeroize super_priv after N idle (default 5m)
max_lifetime = "8h"                       # hard cap, lock after N regardless of activity (default 8h)

[clipboard]
clear_after_seconds = 30                  # default for `fd0 copy`; 0 disables auto-clear
```

`fd0 copy NAME --clear-after=30s` overrides `[clipboard].clear_after_seconds` per call. `--clear-after=0` disables auto-clear for that call.

Environment overrides: `FD0_HOME`, `FD0_SERVER`, `FD0_LOCK_WAIT`, `FD0_AGENT_IDLE`, `FD0_AGENT_MAX_LIFETIME`.

## Server

```bash
fd0-server --bind=:4048 --db=./fd0.db
```

Flags also available as `FD0_BIND`, `FD0_DB`, `FD0_MAX_BODY`, `FD0_VERBOSE`.

## Recovery

`super_priv` is the root of identity. Back it up to roll out a new device or to recover from a lost one:

```bash
fd0 recovery export ~/fd0-recovery.cbor   # encrypted under a recovery passphrase
                                          # store offline (paper QR, password manager)

# on a fresh device:
fd0 recovery import ~/fd0-recovery.cbor
fd0 unlock
fd0 sync                                  # discovers all scopes you were a member of
```

## Diagnostics

```bash
fd0 doctor
```

Read-only health check. Sections, in order:

- **agent** — running and unlocked.
- **user chain** — replays clean, vault `auth_tip` matches chain tip.
- **scopes** — per scope: chain replays, vault `chain_tip` matches,
  current OEK is in the vault, our `super_pub` is in the member set,
  secret count.
- **auth method consistency** — for every active auth method on the
  user chain there is a matching wrap in `vault.enc`; for every
  wrap there is an active method. For YubiKey wraps, additional
  structural checks on `public_params` (32-byte X25519 pub,
  sealed K_unlock ≥ 80 bytes).
- **files** — no chain files exist for scopes not listed in the
  vault.

Exits non-zero on any error-class finding. Warnings (e.g. file
ahead of vault) do not fail the run.

## Build from source

```bash
git clone https://github.com/ValentinKolb/fd0.sh
cd fd0.sh
go install ./cmd/...
```

### YubiKey-PIV (firmware ≥ 5.7, X25519)

Build with `-tags=yubikey` to enable on-card unlock. Both binaries need the tag because the agent's resolver factory and the CLI's enrollment flow are tag-conditional.

```bash
# Build with YubiKey support
go install -tags=yubikey ./cmd/fd0 ./cmd/fd0-agent

# Add a YubiKey method to an existing identity
fd0 auth add --yubikey                  # touch=always (production default)
fd0 auth add --yubikey --touch=never    # touch-only-on-unlock; faster for daily use
fd0 auth add --yubikey --force          # overwrite an existing slot 9d key
                                        # (DESTRUCTIVE: any vault still bound
                                        #  to the old slot pub is locked out)

# Unlock — auto-picks the first method by id when multiple types exist
fd0 unlock                              # picks deterministically; logs the choice
fd0 unlock --method=yubikey             # explicit
fd0 unlock --method=passphrase          # explicit
```

A connected YubiKey on a system with multiple PCSC readers can be selected via `FD0_YUBIKEY_CARD=<substring>` (case-insensitive match against the reader name). Without the env var fd0 refuses to act when more than one YubiKey-shaped reader is present.

The pure-Go build (no `-tags=yubikey`) refuses YubiKey unlock with a clean error pointing at the rebuild requirement. Existing passphrase methods continue to work without the tag.

## Status

v1.0. Wire protocol, on-disk formats, and HTTP API are frozen. Future
versions preserve compatibility with v1 events at rest (see
[docs/PROTOCOL.md](./docs/PROTOCOL.md) §8 conformance).

The YubiKey-PIV path has been exercised end-to-end on real hardware
across four adversarial review rounds; the multi-user shell suite
runs 91 assertions including a 200-cycle stress phase that asserts
zero FD growth on the agent. The threat model catalogs 54 threats
with code-↔-doc annotations enforced by `tools/threat-coverage`.

## Security

Report vulnerabilities privately to **mail@valentin-kolb.com** with
the subject prefix `fd0-security:`. Include the affected version,
the construction or code path you believe is wrong, and any
reproducer.

For non-security bug reports, file a GitHub issue.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
