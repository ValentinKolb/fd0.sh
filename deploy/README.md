# fd0 — demo deployment

Reference compose stack for running fd0 behind Traefik with TLS. Three
containers, three subdomains, one shared metrics token.

```
fd0.sh          → fd0-website   (landing + /witness dashboard)
api.fd0.sh      → fd0-server    (data API — what clients sync against)
witness.fd0.sh  → fd0-witness   (public verifier — polls fd0-server)
```

This is a starting point. Adapt for your environment — resource limits,
log drivers, backup, monitoring, multi-node, etc. are out of scope here.

## Prerequisites

- Docker Engine ≥ 24 with the Compose plugin
- A box reachable on TCP/80 and TCP/443
- DNS for your domain — A records for `${DOMAIN}`, `api.${DOMAIN}`,
  `witness.${DOMAIN}` pointed at the box

## First run

```sh
cp .env.example .env
cp witness.toml.example witness.toml

# Edit both:
#   .env         — domain, ACME email, owner, version, metrics token
#   witness.toml — server URL, server pubkey, chain IDs (see below)

docker compose up -d
docker compose logs -f
```

Traefik provisions a Let's Encrypt cert per host via TLS-ALPN-01 on the
first request. First request can take ~30 s while the cert is issued.

## Discover witness chain IDs

The witness needs to be told which chains to poll. Chain IDs aren't
known until users register, so the workflow is:

1. Bring up server + website + witness with an *empty* `chains = []`.
2. Register a user (`fd0 init && fd0 unlock && fd0 sync`).
3. Add the freshly-created chains to `witness.toml`. Example query
   against the server volume:

   ```sh
   docker compose exec fd0-server \
     sqlite3 /data/fd0.db 'SELECT chain_id FROM chains'
   ```

4. `docker compose restart fd0-witness`.

The witness ignores unknown chains gracefully — no need to take the
stack down for a chain-list edit.

## Shared metrics token

All three services read the same token via `METRICS_TOKEN` in `.env`,
so a Prometheus scrape job can carry one `bearer_token` across all
three targets:

```yaml
scrape_configs:
  - job_name: fd0
    scheme: https
    bearer_token: replace-with-METRICS_TOKEN
    static_configs:
      - targets:
          - api.fd0.sh        # fd0-server
          - witness.fd0.sh    # fd0-witness
          - fd0.sh            # fd0-website
```

Missing/wrong token → 404 (the endpoint denies its own existence).

Each service emits:

| | RED HTTP | Go runtime | Domain |
|---|---|---|---|
| fd0-server | ✓ | ✓ | registrations, events pushed/pulled, users, chains, db size |
| fd0-witness | ✓ | ✓ | polls, cosigns, equivocations, consistency failures, tree_size |
| fd0-website | basic | – | – |

## Operational notes

**Backups.** Volumes that hold real state:

- `fd0-server-data` — SQLite DB + translog key. Lose this and clients
  can't sync; the translog key in particular is unrecoverable.
- `fd0-witness-data` — witness archive + cosign key. Lose this and
  prior cosigns are gone (clients pinned to a now-rotated key need a
  re-pin event).
- `traefik-letsencrypt` — ACME state. Replaceable; Let's Encrypt will
  re-issue on next request (subject to rate limits).

Snapshot strategy is up to you — `docker run --rm -v <vol>:/src ...`
+ tar is the lazy starting point.

**Upgrades.** Pin `FD0_VERSION` to a specific tag (e.g. `v1.0.0`)
in `.env` rather than `latest`. To upgrade:

```sh
sed -i 's/^FD0_VERSION=.*/FD0_VERSION=v1.0.1/' .env
docker compose pull
docker compose up -d
```

The server runs SQLite migrations automatically on boot. Witness
storage is forward-compatible across patch and minor versions.

**Rate limiting.** The server's built-in per-identity + per-IP rate
limit is on by default. Tune via env: `FD0_RATELIMIT_WRITES_PER_MIN`,
`FD0_RATELIMIT_BYTES_PER_MIN`, `FD0_RATELIMIT_REGISTER_PER_HOUR`. See
`fd0-server --help` for the full list.

**Health.** `GET /health` on every service returns
`{"status":"ok",...}`. The compose file uses these for HEALTHCHECK
probes; `docker compose ps` will show DOWN if the probe fails.
