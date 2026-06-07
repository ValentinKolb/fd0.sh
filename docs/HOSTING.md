# How fd0.sh is hosted

The public hosted instance of fd0 — `https://fd0.sh`, `https://api.fd0.sh`, `https://witness.fd0.sh` — is operated by Kolb Antik GmbH from a data center in Germany. This document records who runs it, where, and with what guarantees, in enough detail to reproduce the setup.

## Operator

- Legal entity: **Kolb Antik GmbH**, Germany ([kolb-antik.com](https://kolb-antik.com))
- Operator-of-record for hosting and infrastructure decisions
- Subject to German civil and commercial law, **DSGVO/GDPR-compliant** by jurisdiction

The same entity runs the open-source code from this repository and the published Docker images at `ghcr.io/valentinkolb/`.

## Location

- Data center: **Stadtwerke Ulm (SWU)**, Ulm, Germany — colocation provider; SWU provides the building, power, and connectivity only
- Server: a virtual machine on a high-availability Proxmox cluster **operated by Kolb Antik GmbH** inside that data center
- The VM is dedicated to fd0; no other tenants share it

## What the operator can and cannot see

The zero-knowledge contract in PROTOCOL.md applies to the hosted instance with no exceptions:

| | Visible to operator | Not visible to operator |
|---|---|---|
| Network layer | TLS-terminated request timing, source IP addresses, request sizes | Request bodies — encrypted in transit, ciphertext on disk |
| Storage | SQLite DB containing ciphertext + signed event headers | Secret values, secret names, scope memberships, passphrases, derived keys |
| Operational | Ability to stop the service, change DNS, sign new STHs | None of the above, even with full root on the box |

The transparency log catches operator misbehavior: any STH the operator signs is countersigned by an independent witness, and a server that tries to show different histories to different clients leaves a publishable proof.

## Stack

The two replicas run **deliberately different stacks** so a CVE, regression, or upstream outage in one component never takes down both at once. Identical binaries, different everything else.

| Layer | api.fd0.sh (SWU) | api2.fd0.sh (Hetzner) |
|---|---|---|
| OS | Rocky Linux 10 | Debian 13 (Trixie) |
| Container runtime | Podman 5.x + Quadlet | Docker 29 + Compose v5 |
| Reverse proxy + TLS | Caddy 2.x | Traefik 3.x |
| Firewall | Proxmox layer (host has no firewalld) | UFW + fail2ban + Hetzner Cloud Firewall |
| TLS provider | Let's Encrypt TLS-ALPN-01 (both) ||
| Database | SQLite as bundled with the binary (both) ||
| Binaries | `fd0-server`, `fd0-witness`, `fd0-website` from this repo (both) ||

The stack-diversity choice is operational, not religious. Podman is daemonless and SELinux-confined; Docker is daemon-rooted but better integrated with Traefik labels. Rocky tracks RHEL's slow-and-stable line; Debian tracks community-driven updates. If one combination has a bad day, the other usually does not.

Build artefacts come from the [release-docker workflow](../.github/workflows/release-docker.yml) — multi-arch images signed by GitHub's OIDC and published to `ghcr.io/valentinkolb/`.

## Network

- IPv4 + IPv6 dual-stack
- TLS via Caddy on ports 443/tcp + 443/udp (HTTP/3) with HTTP→HTTPS redirect on 80/tcp
- Firewall rules on the Proxmox layer (host has no `firewalld` enabled — the hypervisor handles it)
- Caddy holds the Let's Encrypt account; certs auto-renew well before expiry

## Replicas

The hosted deployment runs the API on two independent VMs in two different data centers:

| Hostname | Location | Operator | Label |
|---|---|---|---|
| `api.fd0.sh`  | SWU Ulm (Kolb Antik Proxmox cluster) | Kolb Antik GmbH | `swu-ulm` |
| `api2.fd0.sh` | Hetzner (Falkenstein) | Kolb Antik GmbH | `hetzner-fsn1` |

Both servers are full peers — each runs the same `fd0-server` binary against its own SQLite DB and signs its own STHs under its own ed25519 translog key. Both label themselves via `FD0_LABEL` and list each other via `FD0_PEERS`; each `/v1/server-info` response advertises the resolved peer (URL + signed pubkey + label) so clients can discover the topology.

The default `fd0` client is configured (see `internal/fdhome/config.go`) to push every event to BOTH servers per sync round. Events are signed and content-addressed, so the second server's idempotent dedup absorbs the duplicate at near-zero cost. Reads fail over to whichever server answers — a primary outage is transparent to the user.

Until the server-side gossip work lands (TRANSLOG.md §11 peer-replication roadmap), cross-author replication relies entirely on multi-pushing clients. A reader who talks to only one server will eventually see events authored against the other server as soon as ANY multi-pushing client syncs.

## Backups

Three independent layers, each with its own failure model:

1. **VM-level snapshots** — at least hourly on the Kolb Antik Proxmox cluster, with a daily copy replicated to **Hetzner S3 object storage** in a separate data center. Protects against host failure, full VM corruption, and total loss of the primary cluster (the off-site copy survives a complete data-center incident at SWU).
2. **Daily SQLite snapshots** — `sqlite3 .backup` of `fd0.db` and `witness.db`, gzipped, 30-day rotation. Runs as a systemd timer, lives at `/var/backups/fd0/`.
3. **Crypto-key off-host backup** — the server's transparency-log signing key and the witness's cosign key are exported once and stored in an off-host encrypted vault. These keys do not change for the server's lifetime, so a one-time export is sufficient; restoring them on a fresh host lets existing clients keep working without re-pinning.

The metrics token (used for Prometheus scrapes) is rotateable in place; rotation does not require a backup.

## Updates and change management

Image updates are **manual**, not automatic. The operator pulls a new tag from `ghcr.io`, restarts the service, observes the logs. No auto-update — a malicious or broken upstream release cannot reach production unobserved.

Image tags follow semantic versioning. Production pins specific tags rather than `:latest` once a release line is stable.

Schema migrations run on first boot under the new version; the SQLite DB is forward-compatible across patch and minor versions per PROTOCOL.md §8 (conformance).

## Security posture

- Container runtime: Podman daemonless, rootful but with no long-running privileged daemon (versus Docker's daemon as root)
- SELinux: enforcing on the host; container-selinux confines each service
- TLS-only: HTTP requests permanent-redirect to HTTPS
- Metrics endpoint: bearer-token guarded, returns 404 on missing/wrong token (no endpoint-existence leak)
- SSH access: key-based authentication only, single operator key
- Vulnerability monitoring: subscribed to Rocky 10 security advisories and Podman/Caddy upstream releases; `dnf upgrade` runs on a regular cadence

## Incident contact

For security issues affecting the hosted instance (or the code), email **mail@valentin-kolb.com** with subject prefix `fd0-security:`. Include the affected version, the construction or code path you believe is wrong, and any reproducer. Non-security operational issues: GitHub Issues.

For privacy-law requests under DSGVO/GDPR (subject access, deletion), email the same address. Note that fd0's zero-knowledge design means the operator cannot decrypt user data — most data subject requests resolve to "we hold ciphertext you can already access from your own client; delete is a chain operation that originates on your device."

## Self-hosting with replicas

The patterns above are reproducible on any operator setup. Here is the minimum-viable shape — strip what you do not need.

### Single server (no replica)

The simplest deployment. One VM, one `fd0-server` container, your reverse proxy of choice handling TLS.

```bash
cd deploy/server
METRICS_TOKEN=$(openssl rand -hex 32) docker compose up -d
# fd0-server now listens on :4048 inside the container; expose it
# behind your TLS terminator (Caddy, Traefik, nginx, Cloudflare, …).
```

Client side:

```toml
# ~/.fd0/config.toml
[sync]
server = "https://your-domain.example"
```

Done. Skip the rest of this section.

### Two replicas (mutual peers)

The shape `fd0.sh` itself runs — one server in each of two data centers, each labelled, each peering with the other, clients multi-push to both.

**Step 1 — DNS.** Pick two hostnames (`api.example.com` + `api2.example.com`). Point each at its own VM. TLS will use TLS-ALPN-01 on `:443` so port 80 only needs the HTTP→HTTPS redirect.

**Step 2 — Server A.** Boot `fd0-server` with a self-label and the other replica as its peer.

```yaml
# deploy/server/compose.yml — see the inline comments for every knob
environment:
  FD0_LABEL: site-a                              # [a-z0-9-]{0,32}
  FD0_PEERS: https://api2.example.com            # the OTHER replica
  FD0_METRICS_TOKEN: ${METRICS_TOKEN:?}
```

**Step 3 — Server B.** Same shape, swapped peers.

```yaml
environment:
  FD0_LABEL: site-b
  FD0_PEERS: https://api.example.com
  FD0_METRICS_TOKEN: ${METRICS_TOKEN:?}
```

On boot each server resolves the other via `GET /v1/server-info`, TOFU-pins the peer's signing pubkey in its own `peers` SQLite table, and republishes the resolved entry in its own signed `/v1/server-info`. Verify with `curl`:

```bash
curl -s https://api.example.com/v1/server-info  | python3 -c "import sys,cbor2;d=cbor2.loads(sys.stdin.buffer.read());print('label=',d['label']);print('peers=',d.get('peers'))"
curl -s https://api2.example.com/v1/server-info | python3 -c "…"
# Each should list the OTHER server's URL + pubkey + label.
```

**Step 4 — Client config.** Tell clients about both servers.

```toml
# ~/.fd0/config.toml
[sync]
servers = ["https://api.example.com", "https://api2.example.com"]
```

The client now pushes every event to BOTH servers per sync round. Reads fall over: if A is down, the client uses B. First-contact pinning runs separately per URL — the safety-number ceremony happens once per server.

**Step 5 (optional) — One witness per replica.** Each server keeps its own RFC 6962 transparency log under its own ed25519 key. For full equivocation detection you want one witness polling each:

```yaml
# witness1 polls server A
FD0_WITNESS_SERVER_URL: https://api.example.com

# witness2 polls server B
FD0_WITNESS_SERVER_URL: https://api2.example.com
```

Witnesses TOFU-pin their server's pubkey on first poll. Cosigned STHs from each witness anchor each server's history independently.

### Operational notes

- **What replicates today.** Each multi-pushing client puts its own events on every configured server. Events authored against ONLY one server stay there until a multi-pushing client moves them — server-to-server gossip is a future revision (see TRANSLOG.md §11).
- **Adding a third replica later.** New server's `FD0_PEERS` lists the existing two; the existing two have their `FD0_PEERS` extended to include the new one and restarted. TOFU-pins establish in both directions on the next resolver tick (default 1h, or restart for immediate). Clients add the new URL to `[sync].servers`.
- **Removing a replica.** Stop the container, remove the entry from the other servers' `FD0_PEERS`, remove from clients' `[sync].servers`. Surviving servers keep their pinned-peer row in SQLite until you `DELETE FROM peers WHERE url = ?` — harmless, just stale.
- **Rotating a server's ed25519 key.** Same ceremony as a single-server rotation (TRANSLOG.md §4.3). Every client AND every peering server has to re-pin: peers refuse silent rotation precisely so an attacker can't substitute a key behind your back. Wipe the row on each peer (`DELETE FROM peers WHERE url = ?`) and they re-TOFU on next resolver tick.
- **Per-server backups.** Each server has its own SQLite DB and its own ed25519 key. Both need their own backup pipeline — losing one replica's data does not corrupt the other, but it does cost the witness archive for STHs signed under the lost key.

[`deploy/`](../deploy/) ships minimal docker-compose building blocks (one per service) so any reverse-proxy / TLS combination plugs in. The full production recipe with TLS, ACME, multi-arch container images, and per-stack lifecycle is the one this document describes; if you want to reproduce `fd0.sh` end-to-end, follow the Stack section above with the matching combination of distro + runtime + proxy on each host.
