# fd0

Zero-knowledge encrypted secret store for individuals and teams. Written in Go.

Three components:

- **`fd0`** — CLI client with inline TUI: passphrase/yubikey unlock, scope and secret commands, fuzzy search.
- **`fd0-agent`** — Unix-socket daemon. Holds `super_priv` mlocked, performs Ed25519 / X25519 / sealed-box on demand, runs periodic sync.
- **`fd0-server`** — HTTP API + SQLite. Stores ciphertext and signed metadata only; never sees plaintext.

The server cannot read secrets. Membership changes rotate the per-scope key. Full spec: [PROTOCOL.md](./PROTOCOL.md), [API.md](./API.md), [STORAGE.md](./STORAGE.md), [THREATS.md](./THREATS.md).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ValentinKolb/fd0.sh/main/scripts/install.sh | sh
```

Installs `fd0`, `fd0-agent`, `fd0-server` into `~/.local/bin` and seeds `~/.fd0/config.toml`. Use `--system` for `/usr/local/bin`.

Server-only via Docker:

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
# sealed-box (Ed25519-derived X25519 in v1; YubiKey-PIV is scaffold-only):
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

Verifies: vault opens, agent unlocked, every chain replays, vault tip-binding consistent, current OEK present per scope, vault wraps and active auth methods match, no orphan files.

## Build from source

```bash
git clone https://github.com/ValentinKolb/fd0.sh
cd fd0.sh
go install ./cmd/...
```

YubiKey support is scaffolded but unfinished. The build tag exists and CI verifies it compiles, but on-card unlock is pending hardware-day integration (slot pub-key retrieval, sealed-box completion). The pure-Go (passphrase-only) build is the supported path.

```bash
go install -tags=yubikey ./cmd/fd0-agent   # scaffold; not functional yet
```

## Status

Pre-1.0. Wire protocol is stabilising; on-disk formats are versioned. Breaking changes between minor versions are possible until v1.0.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
