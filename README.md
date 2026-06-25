# fd0

fd0 is a client-side encrypted secrets manager with scoped sharing, an
ssh-agent compatible local agent, Talos/Kubernetes config storage, and a
transparency log for server-held event chains.

User documentation lives at [fd0.sh/docs](https://fd0.sh/docs). This repository
contains the implementation, deployment assets, protocol specs, threat model,
and engineering references.

## Repository status

- Wire format, HTTP API, and on-disk v1 event formats are compatibility targets.
- The client writes and reads one configured primary server. Redundancy is
  server-side disaster recovery, not multi-primary writes.
- The server stores ciphertext and signed events. It does not receive plaintext
  secrets.
- Threat coverage is maintained through `docs/THREATS.md` and `// THREAT: Tnn`
  code annotations checked by `go run ./tools/threat-coverage`.

## Components

| Component | Purpose |
| --- | --- |
| `fd0` | CLI for vault, scopes, secrets, cards, SSH, Talos, Kube, sync, and recovery. |
| `fd0-agent` | Local Unix-socket daemon. Holds unlocked identity material in memory and serves signing/decrypt/ssh-agent requests. |
| `fd0-server` | HTTP API and SQLite store for signed encrypted event chains. |
| `fd0-witness` | Passive transparency-log observer. Archives signed tree heads and detects equivocation. |
| `fd0-website` | The hosted documentation and product site at `fd0.sh`. |

## Build

```sh
go install ./...
```

YubiKey PIV unlock is behind the `yubikey` build tag:

```sh
go install -tags=yubikey ./cmd/fd0 ./cmd/fd0-agent
```

Build the website separately:

```sh
cd website
bun install
bun run build
```

## Test and lint

```sh
make test             # go test ./...
make integration      # tests/integration_*.sh
make lint             # go vet, golangci-lint if installed, semgrep if installed, threat coverage
make all              # build, test, integration, lint
```

Useful targeted checks:

```sh
go run ./tools/threat-coverage
go test ./internal/wirecompat -run TestWireCompatV1Verify
cd website && bun run build
```

## Repository layout

| Path | Contents |
| --- | --- |
| `cmd/` | Binaries: client, agent, server, witness, and test helpers. |
| `internal/` | Go implementation. Single module rooted at the repo top. |
| `docs/` | Protocol, API, storage, translog, hosting, replication, threat, and benchmark references. |
| `deploy/` | Docker Compose examples for `fd0-server` and `fd0-witness`; TLS/proxy details live in `docs/HOSTING.md`. |
| `tests/` | Multi-user integration shell suite. |
| `tools/` | Threat coverage and Semgrep guardrails. |
| `website/` | fd0.sh site and user-facing documentation. |
| `skills/` | Agent skill for safe fd0 CLI use. |

## Technical references

| File | Scope |
| --- | --- |
| [docs/PROTOCOL.md](./docs/PROTOCOL.md) | Cryptographic protocol, event formats, identities, scopes, vault, recovery. |
| [docs/API.md](./docs/API.md) | HTTP API, authentication header, `/v1/sync`, status codes. |
| [docs/STORAGE.md](./docs/STORAGE.md) | Server SQLite schema, client files, replay, compaction, backup rules. |
| [docs/TRANSLOG.md](./docs/TRANSLOG.md) | RFC 6962-style transparency log, STHs, witnesses, peer hints. |
| [docs/THREATS.md](./docs/THREATS.md) | Canonical threat catalogue and code annotation coverage. |
| [docs/HOSTING.md](./docs/HOSTING.md) | Production hosting runbook. |
| [docs/REPLICATION.md](./docs/REPLICATION.md) | Disaster-recovery replication model. |
| [docs/BENCH.md](./docs/BENCH.md) | Performance baseline and benchmark method. |

## Release model

Component tags use separate namespaces:

- `client-vX.Y.Z` for `fd0` and `fd0-agent`
- `server-vX.Y.Z` for `fd0-server`
- `witness-vX.Y.Z` for `fd0-witness`
- `website-vX.Y.Z` for `fd0-website`
- `fd0-vX.Y.Z` for coordinated wire-protocol bumps

See [CHANGELOG.md](./CHANGELOG.md) for release history.

## Security

Report vulnerabilities privately to **mail@valentin-kolb.com** with subject
prefix `fd0-security:`. Include the affected version, the construction or code
path, and a reproducer when possible.

Use GitHub Issues for non-security bugs.

## License

Apache-2.0. See [LICENSE](./LICENSE).
