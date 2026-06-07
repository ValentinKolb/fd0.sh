# Deploy

Minimal docker-compose building blocks for the two fd0 services. No reverse proxy, no TLS, no opinions about your infrastructure — bring your own.

```
deploy/
├── server/compose.yml       Just fd0-server
└── witness/compose.yml      Just fd0-witness, points at any fd0-server
```

For the full TLS-terminated production recipe (Caddy + Let's Encrypt + Podman quadlet) see [`docs/HOSTING.md`](../docs/HOSTING.md) — that's how `fd0.sh` itself runs.

## fd0-server

Stores ciphertext and signed event headers. Serves the v1 API on port 4048.

```sh
cd deploy/server
METRICS_TOKEN=$(openssl rand -hex 32) docker compose up -d
curl http://localhost:4048/health
```

Put your TLS terminator in front, then point your fd0 client at it:

```toml
# ~/.fd0/config.toml
[sync]
server = "https://your-domain.example"
```

## fd0-witness

Polls one fd0-server's transparency log, countersigns honest STHs, archives divergent ones. Detects equivocation.

```sh
cd deploy/witness
SERVER_URL=https://api.fd0.sh \
METRICS_TOKEN=$(openssl rand -hex 32) \
docker compose up -d
curl http://localhost:4049/health
```

The witness auto-discovers chains from the server's `/v1/chains` endpoint and TOFU-pins the server's pubkey on first contact. To run an independent witness against a server you don't operate, set `FD0_WITNESS_SERVER_PUB` to the hex pubkey obtained out-of-band — see the comments in `witness/compose.yml`.

## Configuration

Both composes are env-driven. Required vars are declared with `:?` so `docker compose up` refuses to start without them. Optional vars are commented in the compose files showing their defaults — uncomment to override.

| Service | Required | Useful optionals |
|---|---|---|
| server | `METRICS_TOKEN` | `FD0_BIND`, `FD0_DB`, `FD0_RATELIMIT_*` |
| witness | `SERVER_URL`, `METRICS_TOKEN` | `FD0_WITNESS_SERVER_PUB`, `FD0_WITNESS_POLL_INTERVAL`, `FD0_WITNESS_CHAINS` |

Full env-var reference per binary: `fd0-server --help`, `fd0-witness --help`.

## Backups

The two named volumes (`fd0-server-data`, `fd0-witness-data`) hold everything irreplaceable:

- `fd0-server-data` — SQLite event store + ed25519 transparency-log signing key
- `fd0-witness-data` — SQLite archive + ed25519 cosign key

Lose either and clients will need to re-pin. Snapshot the volumes (or use `sqlite3 .backup` against the DB files inside) on whatever schedule fits your durability target. The `fd0.sh` production setup uses both hourly VM snapshots and a daily `sqlite3 .backup` cron — see [`docs/HOSTING.md`](../docs/HOSTING.md) for the recipe.

## Multiple instances

To watch a second server, drop a second copy of `witness/compose.yml` in its own directory, set a different `SERVER_URL`, give the volumes different names. Each witness runs as an independent process with its own DB and metrics endpoint.

To run a second server (different domain, different operator), drop a second copy of `server/compose.yml` with its own volume. Two fd0-servers can coexist on one host as long as their `ports:` don't collide.
