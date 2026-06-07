# fd0 — demo deployment

Single-file reference stack: Traefik + fd0-server + fd0-witness + fd0-website behind TLS. Drop `compose.yml` into Portainer, Coolify, or `docker compose` directly. Three env knobs, images hardcoded to `ghcr.io/valentinkolb/fd0-*:latest`.

```
fd0.sh          → fd0-website   (landing + /witness dashboard)
api.fd0.sh      → fd0-server    (data API — what clients sync against)
witness.fd0.sh  → fd0-witness   (public verifier — polls fd0-server)
```

This is a starting point. Resource limits, log drivers, backups, monitoring, multi-node — adapt for your environment.

## Prerequisites

- Docker Engine ≥ 24 with the Compose plugin
- A box reachable on TCP/80 and TCP/443
- DNS — A records for `${DOMAIN}`, `api.${DOMAIN}`, `witness.${DOMAIN}` pointed at the box

## Settings

Three env vars control the stack. Set them as stack env vars in Portainer / Coolify, or edit the defaults in `compose.yml`:

| Variable | Default | Purpose |
|---|---|---|
| `DOMAIN` | `fd0.sh` | Apex; subdomains `api.` and `witness.` derive from it |
| `ACME_EMAIL` | `admin@fd0.sh` | Let's Encrypt expiry notifications |
| `METRICS_TOKEN` | placeholder | Shared bearer token for `/metrics` on all three services |

Generate the token:

```sh
openssl rand -hex 32
```

If you fork the project, edit the image references at the top of each service block.

## Deploy

```sh
docker compose -f compose.yml up -d
docker compose logs -f
```

Traefik provisions a Let's Encrypt cert per host via TLS-ALPN-01 on first request. First request takes ~30 s while the cert issues.

## Witness configuration

Pure env. No config file, no inline compose blocks. The witness reads:

| Env | Default in compose | Purpose |
|---|---|---|
| `FD0_WITNESS_SERVER_URL` | `https://api.${DOMAIN}` | The fd0-server this witness watches |
| `FD0_WITNESS_PIN_ON_FIRST_USE` | `true` | TOFU pin — fetch pubkey from `/v1/server-info` on first poll |
| `FD0_WITNESS_AUTO_DISCOVER` | `true` | Pull chain list from `/v1/chains` every round |
| `FD0_WITNESS_POLL_INTERVAL` | `30s` | Time between rounds |
| `FD0_WITNESS_SERVER_PUB` | (unset) | Explicit hex pubkey — alternative to TOFU |
| `FD0_WITNESS_CHAINS` | (unset) | Comma-separated allow-list — alternative to auto-discover |

### Multi-server

One witness watches one server. To watch a second server, copy the `fd0-witness` service block, change the `FD0_WITNESS_SERVER_URL`, give it its own volume and Traefik Host(), and run both. Independent processes, independent DBs, independent metrics — smaller failure domain than a multi-target mega-witness.

### Trust model

Out of the box the witness self-bootstraps via TOFU: first poll fetches `/v1/server-info`, validates the server's self-signature, persists the pubkey. SSH-`known_hosts` semantics — later changes fail with `ErrPinMismatch`.

**Caveat.** `/v1/server-info` is self-signed: the server signs the pubkey announcement with the key it presents. The signature proves the server has the corresponding private key, not that the pubkey is the "real" one. A MITM at first contact pins the attacker's key. For self-host (this stack), the bootstrap window is under your control. For an **independent** witness watching a server you don't control, set `FD0_WITNESS_SERVER_PUB` to the pubkey obtained out-of-band (operator's website, signed announcement, etc).

Published cosigns are the audit artefact — anyone cross-checking witness output against the server's real pubkey catches a TOFU mispin.

Inspect the pinned key after first run:

```sh
docker compose exec fd0-witness sh -c \
  'sqlite3 /data/witness.db "SELECT hex(server_pub) FROM pinned_servers"'
```

## Metrics

All three services read the same `METRICS_TOKEN`. One Prometheus job covers the stack:

```yaml
scrape_configs:
  - job_name: fd0
    scheme: https
    bearer_token: <your METRICS_TOKEN>
    static_configs:
      - targets:
          - api.fd0.sh        # fd0-server
          - witness.fd0.sh    # fd0-witness
          - fd0.sh            # fd0-website
```

Missing or wrong token → 404 (the endpoint denies its own existence). Per-service domain metrics:

| | RED HTTP | Go runtime | Domain |
|---|---|---|---|
| fd0-server | yes | yes | registrations, events pushed/pulled, users, chains, db size |
| fd0-witness | yes | yes | polls, cosigns, equivocations, consistency failures, tree_size |
| fd0-website | yes | – | – |

## Operational notes

**Backups.** Volumes that hold state:

- `fd0-server-data` — SQLite DB + translog signing key. Lose it and clients can't sync; the translog key in particular is unrecoverable.
- `fd0-witness-data` — witness archive + cosign key. Lose it and prior cosigns are gone; clients pinned to a now-rotated key need a re-pin event.
- `traefik-letsencrypt` — ACME state. Replaceable; Let's Encrypt re-issues on next request (subject to rate limits).

Snapshot strategy is yours — `docker run --rm -v <vol>:/src ...` + tar is the lazy starting point.

**Upgrades.** The image references are hardcoded to `:latest`. To pull a newer build:

```sh
docker compose pull
docker compose up -d
```

To pin a specific tag, edit the `image:` lines in `compose.yml` (e.g. `ghcr.io/valentinkolb/fd0-server:v1.0.1`). The server runs SQLite migrations on boot. Witness storage is forward-compatible across patch and minor versions.

**Rate limiting.** The server's per-identity + per-IP rate limit is on by default. Tune via `FD0_RATELIMIT_WRITES_PER_MIN`, `FD0_RATELIMIT_BYTES_PER_MIN`, `FD0_RATELIMIT_REGISTER_PER_HOUR`. `fd0-server --help` has the full list — add them to the `fd0-server.environment` block in `compose.yml`.

**Health.** Every service exposes `GET /health` returning `{"status":"ok",…}`. The compose file uses these for HEALTHCHECK probes; `docker compose ps` shows `unhealthy` if a probe fails three times in a row.
