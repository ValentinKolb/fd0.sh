# fd0 — demo deployment

Single-file reference stack: Traefik + fd0-server + fd0-witness + fd0-website behind TLS. Drop `compose.yml` into Portainer, Coolify, or `docker compose` directly — no external `.env`, no `witness.toml`. Defaults baked in, every knob overridable as a stack env var.

```
fd0.sh          → fd0-website   (landing + /witness dashboard)
api.fd0.sh      → fd0-server    (data API — what clients sync against)
witness.fd0.sh  → fd0-witness   (public verifier — polls fd0-server)
```

This is a starting point. Resource limits, log drivers, backups, monitoring, multi-node — adapt for your environment.

## Prerequisites

- Docker Engine ≥ 24 with the Compose plugin (`configs.content` needs Compose ≥ v2.20)
- A box reachable on TCP/80 and TCP/443
- DNS for your domain — A records for `${DOMAIN}`, `api.${DOMAIN}`, `witness.${DOMAIN}` pointed at the box

## Settings

Five values control the stack. All have defaults in `compose.yml`. Override either by editing the file or by setting them as stack env vars (Portainer Stack → Environment variables, `docker compose --env-file …`, host env):

| Variable | Default | Purpose |
|---|---|---|
| `DOMAIN` | `fd0.sh` | Apex; subdomains `api.` and `witness.` derive from it |
| `ACME_EMAIL` | `admin@fd0.sh` | Let's Encrypt expiry notifications |
| `GHCR_OWNER` | `valentinkolb` | Image namespace at `ghcr.io/<owner>/fd0-*` |
| `FD0_VERSION` | `latest` | Image tag — pin (`v1.0.0`) in production |
| `METRICS_TOKEN` | placeholder | Shared bearer token for `/metrics` on all three services |

Generate the token:

```sh
openssl rand -hex 32
```

## Deploy

```sh
docker compose -f compose.yml up -d
docker compose logs -f
```

Traefik provisions a Let's Encrypt cert per host via TLS-ALPN-01 on first request. First request takes ~30 s while the cert issues.

## Configure the witness

The witness needs a server pubkey and a list of chains to poll. Neither exists until the stack is up and at least one user has registered, so:

1. Bring the stack up. `chains = []` is fine — the witness logs warnings and continues.
2. Register a user against `https://api.${DOMAIN}` (`fd0 init && fd0 unlock && fd0 sync`).
3. Discover the server pubkey + chain IDs:

   ```sh
   # Server cosign pubkey
   fd0 doctor | grep server_pub

   # Chain IDs
   docker compose exec fd0-server \
     sqlite3 /data/fd0.db 'SELECT chain_id FROM chains'
   ```

4. Edit the inline `configs.witness-config.content` block in `compose.yml`:

   ```toml
   [[target]]
   server_url    = "https://api.fd0.sh"
   server_pub    = "<32-byte hex from step 3>"
   poll_interval = "30s"
   chains = [
       "user:abc12345",
       "scope:s_xxxxxxxxxxxxxxxxxxxxxxxx",
   ]
   ```

5. `docker compose up -d fd0-witness` — the witness picks up the new config and starts polling.

The witness ignores unknown chains gracefully, so adding new ones later doesn't need a full stack restart.

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

**Upgrades.** Pin `FD0_VERSION` to a specific tag rather than `latest`:

```sh
FD0_VERSION=v1.0.1 docker compose pull
FD0_VERSION=v1.0.1 docker compose up -d
```

The server runs SQLite migrations on boot. Witness storage is forward-compatible across patch and minor versions.

**Rate limiting.** The server's per-identity + per-IP rate limit is on by default. Tune via `FD0_RATELIMIT_WRITES_PER_MIN`, `FD0_RATELIMIT_BYTES_PER_MIN`, `FD0_RATELIMIT_REGISTER_PER_HOUR`. `fd0-server --help` has the full list — add them to the `fd0-server.environment` block in `compose.yml`.

**Health.** Every service exposes `GET /health` returning `{"status":"ok",…}`. The compose file uses these for HEALTHCHECK probes; `docker compose ps` shows `unhealthy` if a probe fails three times in a row.
