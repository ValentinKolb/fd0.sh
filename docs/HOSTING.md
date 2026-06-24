# How fd0.sh is hosted

Reference for the public hosted instance — `https://fd0.sh`, `https://api.fd0.sh`, `https://api2.fd0.sh`, `https://witness.fd0.sh`, `https://witness2.fd0.sh`.

## Operator

- Legal entity: **Kolb Antik GmbH**, Germany ([kolb-antik.com](https://kolb-antik.com))
- Jurisdiction: German civil and commercial law, DSGVO/GDPR
- Source of truth: this repository; published Docker images at `ghcr.io/valentinkolb/`

## Topology

Two independent replicas, each in its own data center:

| Hostname | Location | Self-label |
|---|---|---|
| `api.fd0.sh`  | SWU Ulm — Kolb Antik Proxmox cluster | `swu-ulm` |
| `api2.fd0.sh` | Hetzner Falkenstein — Hetzner Cloud VM | `hetzner-fsn1` |

Each replica runs `fd0-server` against its own SQLite DB, signs its own STHs under its own ed25519 translog key, and runs a paired `fd0-witness` (`witness.fd0.sh`, `witness2.fd0.sh`) that cosigns its STHs. Replicas peer with each other via `FD0_PEERS`: on boot each one resolves its peer's `/v1/server-info`, TOFU-pins the pubkey, and republishes the resolved entry in its own signed response.

The default `fd0` client targets both replicas (`[sync].servers = [api.fd0.sh, api2.fd0.sh]`) and multi-pushes every event to both. Reads fall over to whichever server answers. Server-to-server event gossip is not yet implemented — event propagation across replicas relies on multi-pushing clients until then. See TRANSLOG.md §11 for the wire format and the peer trust model.

## Stack

The two replicas run different distros, container runtimes, and proxies so a CVE or regression in one component cannot affect both.

| Layer | api.fd0.sh (SWU) | api2.fd0.sh (Hetzner) |
|---|---|---|
| OS | Rocky Linux 10 | Debian 13 (Trixie) |
| Container runtime | Podman 5.x + Quadlet | Docker 29 + Compose v5 |
| Reverse proxy | Caddy 2.x | Traefik 3.x |
| Firewall | Proxmox hypervisor layer | UFW + fail2ban + Hetzner Cloud Firewall |
| TLS | Let's Encrypt via TLS-ALPN-01 (both) ||
| Database | SQLite (both, bundled with the binary) ||
| Binaries | `fd0-server`, `fd0-witness`, `fd0-website` from this repo (both) ||

Build artefacts come from the [release-docker workflow](../.github/workflows/release-docker.yml) — multi-arch images signed by GitHub's OIDC.

## Network

- IPv4 + IPv6 dual-stack on every host
- TLS on `443/tcp` + `443/udp` (HTTP/3); HTTP→HTTPS redirect on `80/tcp`
- Certificate renewal handled by the proxy on each host

## What the operator can and cannot see

The zero-knowledge contract in PROTOCOL.md applies to the hosted instance without exception:

| | Visible to operator | Not visible to operator |
|---|---|---|
| Network | TLS-terminated request timing, source IPs, body sizes | Decrypted bodies — ciphertext on the wire and on disk |
| Storage | Ciphertext + signed event headers | Secret values, secret names, scope memberships, passphrases, keys |
| Operational | Stop a replica, change DNS, sign STHs under the server key | Anything in the columns above, even with root on the host |

A server that tries to show different histories to different clients leaves a publishable proof: every STH is signed under the server key and cosigned by the paired witness, and divergent STHs at the same `tree_size` are evidence of equivocation.

## Backups

VM-level snapshots use each provider's primitives:

- **api.fd0.sh (SWU)** — hourly Proxmox snapshots, daily off-site copy to Hetzner S3 object storage in a separate data center. The off-site copy survives a complete SWU incident.
- **api2.fd0.sh (Hetzner)** — daily Hetzner Cloud backups. No additional off-site replication: api.fd0.sh's own copy of the data, populated by multi-pushing clients, is the implicit off-site for api2.

App-level backups run on both replicas:

1. **Daily SQLite snapshots** — `sqlite3 .backup` of `fd0.db` and `witness.db`, gzipped, 30-day rotation. Driven by a systemd timer; output at `/var/backups/fd0/` or `/srv/fd0/backups/`.
2. **Crypto keys off-host** — translog signing key and witness cosign key, exported once and stored in an off-host encrypted vault. These keys are stable for the life of the server; a fresh host restored with the original key needs no re-pinning.

Metrics tokens are rotatable in place and do not need backups.

## Updates

Image updates are manual. The operator pulls a new tag, restarts the service, observes the logs — no auto-update, so a broken or malicious upstream release cannot reach production unobserved. Production pins specific tags once a release line is stable. Schema migrations run on first boot under the new version; the on-disk format is forward-compatible across patch and minor versions per PROTOCOL.md §8.

## Security posture

- Container runtimes confined per OS: SELinux + container-selinux on Rocky; AppArmor + Docker's default seccomp on Debian
- HTTP requests permanently redirected to HTTPS
- `/metrics` bearer-token guarded; missing or wrong token returns `404` so the endpoint does not advertise its existence
- SSH: key-based authentication only, single operator key per host
- Vulnerability monitoring: subscribed to Rocky 10, Debian 13, Podman, Docker, Caddy, and Traefik security advisories; package updates run on a regular cadence

## Incident contact

Security issues affecting the hosted instance or the code: email **mail@valentin-kolb.com** with subject prefix `fd0-security:`. Include the affected version, the construction or code path you believe is wrong, and a reproducer. Non-security operational issues go to GitHub Issues.

DSGVO/GDPR data-subject requests use the same address. fd0's zero-knowledge design means the operator cannot decrypt user data — most requests resolve to "the ciphertext you can already access from your own client; deletion is a chain operation that originates on your device."

---

## Self-hosting

The setup above is reproducible. Two shapes are supported.

### Single server

```bash
cd deploy/server
METRICS_TOKEN=$(openssl rand -hex 32) docker compose up -d
```

Client config:

```toml
# ~/.fd0/config.toml
[sync]
server = "https://your-domain.example"
```

Add your own TLS terminator in front of `:4048`. Done.

### Two replicas (mutual peers)

The shape `fd0.sh` itself runs.

**1. DNS.** Point `api.example.com` and `api2.example.com` at their respective VMs.

**2. Server A.**

```yaml
environment:
  FD0_LABEL: site-a
  FD0_PEERS: https://api2.example.com
  FD0_METRICS_TOKEN: ${METRICS_TOKEN:?}
```

**3. Server B.**

```yaml
environment:
  FD0_LABEL: site-b
  FD0_PEERS: https://api.example.com
  FD0_METRICS_TOKEN: ${METRICS_TOKEN:?}
```

On boot each server resolves the other's `/v1/server-info`, TOFU-pins the pubkey in its own `peers` SQLite table, and republishes the resolved entry. Verify both directions:

```bash
curl -s https://api.example.com/v1/server-info  | python3 -c "import sys,cbor2;d=cbor2.loads(sys.stdin.buffer.read());print(d.get('label'), d.get('peers'))"
curl -s https://api2.example.com/v1/server-info | python3 -c "…"
```

**4. Client config.**

```toml
# ~/.fd0/config.toml
[sync]
servers = ["https://api.example.com", "https://api2.example.com"]
```

The client multi-pushes every event to both, falls over on reads, and runs the safety-number ceremony once per server.

**5. Witness per replica (optional).** Each server has its own translog under its own key, so each needs its own witness to cosign honest STHs.

```yaml
# witness-a — paired with server A
FD0_WITNESS_SERVER_URL: https://api.example.com

# witness-b — paired with server B
FD0_WITNESS_SERVER_URL: https://api2.example.com
```

### Operational notes

- **Event propagation.** Between *live* replicas, only multi-pushing clients propagate events: a single-server client writes to one replica only; events reach the other when any multi-pushing client syncs. Live server-to-server gossip (into the serving tables) is still on the roadmap (TRANSLOG.md §11). For single-authority convergence without gossip, clients can set `[sync].mode = "primary"` (each scope routed to one server). Server-to-server **DR backup** replication is available — see below.
- **DR backup (standby).** A server with `FD0_REPLICATE_FROM=<primary-url>` mirrors that primary's chains (encrypted events + signed STHs) into a write-once local archive (`backup_*` tables), verifying each STH under the primary's key before storing it. The primary must list the standby in its `FD0_PEERS` to authorise the pull. The standby never serves the backup; it is disaster-recovery only — if the primary's disk is lost, the standby holds every event. `FD0_REPLICATE_INTERVAL` (default 30s) sets the cadence; `FD0_PEER_RESOLVE_INTERVAL` sets how fast the primary pins the standby (default 1h — set short when bringing the pair up). Promotion (restoring from the archive) is an operator ceremony, not automatic.
- **Adding a third replica.** Add the new URL to every existing server's `FD0_PEERS` and restart; the new server's `FD0_PEERS` lists the existing two. TOFU-pins establish in both directions on the next resolver tick (default 1h). Clients add the new URL to `[sync].servers`.
- **Removing a replica.** Stop the container, remove the URL from the other servers' `FD0_PEERS` and from clients' `[sync].servers`. On the next boot each surviving server prunes any pinned peer no longer in its `FD0_PEERS` — this also revokes that peer's replication-pull authorization, so the stale row must not linger. (Restart the survivors to apply; the prune is automatic.)
- **Rotating a server's ed25519 key.** Same ceremony as a single-server rotation (TRANSLOG.md §4.3). Every client and every peering server must re-pin. Peers refuse silent rotation; the operator wipes the row (`DELETE FROM peers WHERE url = ?`) and the resolver re-TOFUs on the next tick.
- **Per-replica backups.** Each server has its own SQLite DB and its own ed25519 key. Losing one replica's data does not corrupt the other, but it costs the witness archive for STHs signed under the lost key.

The blocks in [`deploy/`](../deploy/) work behind any reverse proxy that terminates TLS and forwards to the container's port. To reproduce `fd0.sh` end-to-end, follow the Stack section above with the matching distro / runtime / proxy on each host.
