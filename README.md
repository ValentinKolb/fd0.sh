# fd0

Zero-knowledge secrets manager. Run the server yourself, or point your client at the hosted instance at [fd0.sh](https://fd0.sh) — either way the server stores ciphertext and signed events only.

[Quickstart](#quickstart) · [How it works](#how-it-works) · [Self-host](#self-host) · [Configuration](#configuration) · [Build from source](#build-from-source) · [Specs](#specs) · [License](#license)

```
The server cannot decrypt.        Every secret is sealed client-side.
Membership is cryptographic.       Add or remove members atomically.
The server cannot equivocate.      Every STH is cosigned by a witness.
```

## Status

v1.0. Wire protocol, on-disk formats, and HTTP API are frozen — future versions stay compatible with v1 events at rest ([PROTOCOL.md §8](./docs/PROTOCOL.md)). 54 catalogued threats with code-to-doc annotations enforced by `tools/threat-coverage`. Multi-user shell suite: 91 assertions plus a 200-cycle stress phase. YubiKey-PIV reviewed end-to-end across four adversarial rounds. Release notes: [CHANGELOG.md](./CHANGELOG.md).

## Quickstart

Install the client (workstation, laptop, anything that holds keys):

```bash
curl -fsSL https://fd0.sh/install | sh
```

Supported platforms: Linux and macOS on amd64 and arm64. Drops `fd0` and `fd0-agent` into `~/.local/bin` (or `/usr/local/bin` with `--system`), verifies the release manifest with cosign when available, and prints a PATH hint when `~/.local/bin` is not on `$PATH`. Windows is not yet built — the binaries cross-compile but the agent's AF_UNIX socket is not validated.

Point it at a server — either your own, or [fd0.sh](https://fd0.sh):

```bash
fd0 init                                 # generate identity, set passphrase
fd0 unlock                               # start agent, decrypt vault
fd0 scope create --label work
fd0 set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxx"
fd0 sync                                 # exchange with the configured server
fd0 get DEPLOY_KEY                       # plaintext to stdout
fd0 copy DEPLOY_KEY                      # to clipboard, auto-clears after 30s
fd0 get                                  # interactive fuzzy search
fd0 lock                                 # zeroize agent, end session
```

### Share a scope with another member

```bash
# alice
fd0 card export                          # prints fd0://card/...
                                         # safety number to stderr — verify
                                         # out-of-band with bob

# bob receives alice's card via an authentic channel and pins it:
fd0 card import "fd0://card/..." --label alice

# alice invites bob:
fd0 card import "fd0://card/..." --label bob
fd0 scope add-member bob --scope work
fd0 sync

# bob's next sync auto-discovers the scope and decrypts via the agent's
# sealed-box (Ed25519-derived X25519, or YubiKey-PIV X25519 if enrolled):
fd0 sync
fd0 ls

# alice removes bob → OEK rotates, bob loses access on his next sync
fd0 scope remove-member bob --scope work
fd0 sync
```

### SSH keys + hosts

Keys are generated inside the agent and served over the standard
ssh-agent protocol; hosts render to `~/.ssh/fd0.conf`. Both are
scope-shared, so onboarding a teammate is the same `scope add-member`
flow as sharing a password.

```bash
fd0 key add laptop                       # ed25519, never on disk in plaintext
fd0 ssh add prod-db app@db.internal \
    --jump bastion --key laptop --scope work
fd0 ssh enable                           # one-time: Include line + shell rc hint
export SSH_AUTH_SOCK="$(fd0 ssh sock)"
ssh prod-db                              # or: fd0 ssh   (fuzzy picker)
```

### Talos Linux + Kubernetes

`fd0 talos` manages Talos client contexts and the DR-grade
`secrets.yaml`; `fd0 kube` manages kubeconfigs for any cluster. The
everyday paths — store, list, render, enable automatic refresh, and merge
into `~/.talos/config` / `~/.kube/config` — are pure Go and need no extra
tools (`kubectl` is never required). Only the Talos cluster-admin paths
that need PKI crypto or a live API connection (`talos new`,
`talos role-add`, `talos kubeconfig`) shell out to `talosctl`.

```bash
fd0 talos add --from-config ~/.talos/config --scope work
fd0 talos enable --merge                 # keep ~/.talos/config current after fd0 sync

fd0 talos new prod --endpoint https://10.0.1.10:6443 \
    --scope work --vault-scope work-dr   # day-0: generates cluster PKI
fd0 talos kubeconfig prod                # fetch + store the admin kubeconfig

fd0 kube add --from-config ~/.kube/config --scope work
fd0 kube enable --merge                  # keep ~/.kube/config current after fd0 sync
```

`add` / `new` / `move` across `key`, `ssh`, `talos`, `kube` refuse to
overwrite an existing name — pass `--force` to overwrite knowingly.

## How it works

Four components, one repo:

```
fd0          CLI client. Inline TUI: passphrase / YubiKey unlock,
             scope and secret commands, fuzzy search.

fd0-agent    Unix-socket daemon. Holds super_priv mlocked, performs
             Ed25519 / X25519 / sealed-box on demand. Periodic sync.

fd0-server   HTTP API + SQLite. Ciphertext + signed metadata. Never
             sees plaintext. Maintains a per-chain RFC 6962 transparency
             log; returns an STH on every sync.

fd0-witness  Independent verifier. Polls fd0-server STHs, cosigns
             honest ones, archives divergent ones. Two clients
             comparing notes — or a third-party observer — detect
             server-side equivocation.
```

The server never sees plaintext. Adding a member wraps the per-scope key to their card; removing one rotates it — cryptographic, not policy-enforced. Every signed tree head is countersigned by the witness, so a server that tries to show different histories to different clients leaves a publishable proof.

Full specs: [PROTOCOL.md](./docs/PROTOCOL.md), [API.md](./docs/API.md), [STORAGE.md](./docs/STORAGE.md), [TRANSLOG.md](./docs/TRANSLOG.md), [THREATS.md](./docs/THREATS.md).

## Self-host

Three Docker images on `ghcr.io/valentinkolb`, multi-arch (amd64 + arm64):

```
fd0-server    ~18 MB, scratch base, port 4048
fd0-witness   ~18 MB, scratch base, port 4049
fd0-website   Bun runtime, port 5173
```

Minimal per-service composes live in [`deploy/`](./deploy/) — drop them into whatever infra you already run:

```bash
cd deploy/server
METRICS_TOKEN=$(openssl rand -hex 32) docker compose up -d
```

Put your own TLS terminator in front. The full production recipe — a DR backup, ACME, witnesses, backups, key rotation — is in [`docs/HOSTING.md`](./docs/HOSTING.md), which is also how `fd0.sh` itself runs.

Endpoints exposed by `fd0-server`:

```
GET  /health      JSON liveness
GET  /version     JSON build info
GET  /metrics     Prometheus (token-guarded via FD0_METRICS_TOKEN)
POST /v1/users    register
POST /v1/sync     push + pull events
GET  /v1/server-info, /v1/chains, /v1/sth/{chain}, /v1/proof/{kind}
```

## Configuration

Client — `~/.fd0/config.toml`:

```toml
[sync]
server    = "https://api.fd0.sh"          # the single primary (one authority per scope)
interval  = "1h"                          # periodic background sync; "" disables
on_unlock = true                          # sync immediately after unlock

[client]
lock_wait = "5s"                          # wait up to 5s on ~/.fd0/.lock contention (default)

[agent]
idle_timeout = "5m"                       # zeroize super_priv after N idle
max_lifetime = "8h"                       # hard cap, lock after N regardless of activity

[clipboard]
clear_after_seconds = 30                  # default for `fd0 copy`; 0 disables auto-clear

[kube]
enabled    = true                         # refresh ~/.kube/config.fd0 after fd0 sync
auto_merge = true                         # also fold into ~/.kube/config

[talos]
enabled    = true                         # refresh ~/.talos/config.fd0 after fd0 sync
auto_merge = true                         # also fold into ~/.talos/config
```

`server` is the single primary the client writes and reads — fd0 has one ordering authority per scope, so replicas can never diverge. Listing more than one server (`servers = [...]`) is a hard error: a second write target could fork, and reconciling that means discarding a write. For redundancy run a server-side disaster-recovery backup (`FD0_REPLICATE_FROM`) instead — see [docs/REPLICATION.md](docs/REPLICATION.md). When `server` is unset it falls back to `FD0_SERVER`, then the built-in default (`api.fd0.sh`, hosted at fd0.sh). Self-hosters override by setting `server`.

`fd0 copy NAME --clear-after=30s` overrides per-call. Env overrides: `FD0_HOME`, `FD0_SERVER`, `FD0_LOCK_WAIT`, `FD0_AGENT_IDLE`, `FD0_AGENT_MAX_LIFETIME`.

Server — flags or env:

```bash
fd0-server --bind=:4048 --db=./fd0.db
```

`FD0_BIND`, `FD0_DB`, `FD0_MAX_BODY`, `FD0_METRICS_TOKEN`, `FD0_VERBOSE`, `FD0_LABEL`, `FD0_PEERS`, plus rate-limit knobs (`FD0_RATELIMIT_*`). `fd0-server --help` for the full list. The server-to-server peer (DR-backup) auth and the peer-hint wire format are documented in `docs/TRANSLOG.md` §11.

## Diagnostics

```bash
fd0 doctor
```

Read-only health check. Replays the user chain and every scope chain, verifies vault `auth_tip` and per-scope `chain_tip` against the chain tips, checks that every active auth method has a matching vault wrap and vice versa (with structural checks on YubiKey wraps), and flags orphan chain files. Exits non-zero on errors; warnings (file ahead of vault) do not fail the run.

## Recovery

`super_priv` is the root of identity. Back it up to roll out a new device or recover from a lost one:

```bash
fd0 recovery export ~/fd0-recovery.cbor   # encrypted under a recovery passphrase
                                          # store offline (paper QR, password manager)

# on a fresh device:
fd0 recovery import ~/fd0-recovery.cbor
fd0 unlock
fd0 sync                                  # auto-discovers every scope you're a member of
```

## AI agents

`skills/fd0/` is an agent skill covering the CLI: when to use which command, the card-exchange + scope-membership flow, the security rules (no `--stdin` flag, never echo passphrases, refuse to blindly re-pin on key mismatch), and a high-level protocol reference so the agent can reason about what the server can and cannot see.

```bash
bunx skills add ValentinKolb/fd0.sh
```

After install the agent recognises requests like "save my deploy key" or "share the prod password with bob" as fd0 territory and walks through the correct command sequence.

## Build from source

```bash
git clone https://github.com/ValentinKolb/fd0.sh
cd fd0.sh
go install ./cmd/...
```

### YubiKey-PIV (firmware ≥ 5.7, X25519)

Build with `-tags=yubikey` to enable on-card unlock. Both `fd0` and `fd0-agent` need the tag — the agent's resolver factory and the CLI's enrollment flow are tag-conditional.

```bash
go install -tags=yubikey ./cmd/fd0 ./cmd/fd0-agent

fd0 auth add --yubikey                    # touch=always (production default)
fd0 auth add --yubikey --touch=never      # faster for daily use
fd0 auth add --yubikey --force            # overwrite slot 9d
                                          # (DESTRUCTIVE: vaults bound to the
                                          # old slot pub are locked out)

fd0 unlock                                # picks deterministically; logs the choice
fd0 unlock --method=yubikey               # explicit
fd0 unlock --method=passphrase            # explicit
```

`FD0_YUBIKEY_CARD=<substring>` disambiguates when multiple PCSC readers are present (case-insensitive match against the reader name). Without it, `fd0` refuses to act on a multi-reader host. The pure-Go build refuses YubiKey unlock with a pointer at the rebuild requirement; passphrase methods keep working.

## Repository layout

```
cmd/        Binaries: fd0, fd0-agent, fd0-server, fd0-witness.
            Test helpers: fd0-test-mitm, fd0-test-bad-witness.
internal/   Implementation. Single Go module rooted at the repo top.
docs/       Specs and reference (protocol, API, storage, transparency
            log, threat model, benchmarks).
deploy/     Reference Traefik + compose stack.
tests/      Integration shell suite.
tools/      Lint / threat-coverage helpers (e.g. semgrep rules).
website/    fd0.sh source — Bun + Hono + Solid SSR (`@valentinkolb/ssr`).
skills/     Agent skill — install via `bunx skills add ValentinKolb/fd0.sh`.
```

One module. `go install ./cmd/...` from the root builds everything. Cross-cutting changes (a protocol revision that updates spec, implementation, and homepage example) land as one PR with one CHANGELOG entry.

## Specs

| File | Contents |
|---|---|
| [PROTOCOL.md](./docs/PROTOCOL.md) | Event types, signing rules, conformance |
| [API.md](./docs/API.md) | HTTP routes, wire format, status codes |
| [STORAGE.md](./docs/STORAGE.md) | On-disk layout, vault format, chain files |
| [TRANSLOG.md](./docs/TRANSLOG.md) | RFC 6962 mapping, witness protocol |
| [THREATS.md](./docs/THREATS.md) | 54 catalogued threats and mitigations |
| [BENCH.md](./docs/BENCH.md) | Benchmark methodology and results |

## Security

Report vulnerabilities privately to **mail@valentin-kolb.com** with subject prefix `fd0-security:`. Include the affected version, the construction or code path you believe is wrong, and any reproducer. Non-security bug reports: GitHub Issues.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
