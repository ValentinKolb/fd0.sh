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

| Layer | Software | Version |
|---|---|---|
| OS | Rocky Linux | 10 |
| Container runtime | Podman + Quadlet | 5.x |
| Reverse proxy + TLS | Caddy | 2.x |
| TLS provider | Let's Encrypt | TLS-ALPN-01 |
| Database | SQLite | as bundled with the binaries |
| Binaries | `fd0-server`, `fd0-witness`, `fd0-website` | tagged release from this repo |

Build artefacts come from the [release-docker workflow](../.github/workflows/release-docker.yml) — multi-arch images signed by GitHub's OIDC and published to `ghcr.io/valentinkolb/`.

## Network

- IPv4 + IPv6 dual-stack
- TLS via Caddy on ports 443/tcp + 443/udp (HTTP/3) with HTTP→HTTPS redirect on 80/tcp
- Firewall rules on the Proxmox layer (host has no `firewalld` enabled — the hypervisor handles it)
- Caddy holds the Let's Encrypt account; certs auto-renew well before expiry

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

## Replicating the setup

[`deploy/`](../deploy/) ships minimal docker-compose building blocks (one per service) for anyone who wants to run their own fd0-server or fd0-witness. They're intentionally infrastructure-agnostic — no proxy, no TLS, no opinions — so they plug into whatever you already run.

The full production recipe with TLS, ACME, multi-arch container images, and quadlet-managed lifecycle is the one this document describes; if you want to reproduce `fd0.sh` end-to-end, follow the Stack section above on any modern Linux host with podman and a public IP.
