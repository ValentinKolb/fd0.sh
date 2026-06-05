# Changelog

All notable changes to fd0. Format: terse one-liners grouped by
release. Wire-format breaks are called out explicitly.

## v1.0.0 — Initial release

First public release. Wire protocol, on-disk formats, and HTTP API
are frozen at this version. Future versions preserve compatibility
with v1 events at rest (`PROTOCOL.md` §8 conformance).

### Identity, vault, and unlock

- Ed25519 identity (`super_keypair`) with X25519 ECDH derived for
  sealed-box recipients.
- Per-device encrypted vault (AES-256-GCM) holding `super_priv`,
  per-scope OEKs, chain-tip bindings, and pinned identities.
- Argon2id passphrase unlock with parameter validation; non-default
  parameters survive boot via the vault wrap header.
- YubiKey-PIV unlock (build tag `yubikey`, firmware ≥ 5.7, X25519
  slot 9d). `auth add --yubikey [--touch=...] [--force]`,
  `unlock --method=yubikey|passphrase`, `FD0_YUBIKEY_CARD` env
  override for multi-reader systems.
- Recovery export/import (`fd0 recovery`) under a separate
  passphrase, Argon2id-derived.
- Identity cards (`fd0://card/...`) with safety-number ceremony for
  out-of-band verification.

### Multi-member scopes

- Per-scope event chain with `member.change` and `secret.set` event
  kinds.
- Per-member sealed-box OEK delivery; OEK rotates on every
  `member.change`.
- Projection verification on every `member.change`: existing
  members assert the inviter's claimed projection equals their
  local index.
- Tombstones for deleted secrets; per-secret stable IDs (ULID).

### Server + sync

- HTTP API + SQLite. Stateless per-request authentication via
  Ed25519-signed headers (`fd0-http-request-v1` domain) bound to
  the destination server's translog pubkey (T21 cross-server
  replay defence).
- Replay defence: per-request `(pk, nonce)` UNIQUE + 300s window.
- Token-bucket rate limiting (five buckets:
  `AcquireAuthAttempt`, `AcquireRegister`, `AcquireProof`,
  `AcquireWrite`, `AcquireBytes`).
- Optimistic CAS with `409 divergence` retry hint on stale push.
- Membership discovery via `/sync?discover_memberships=true`.

### Transparency log

- Per-chain RFC 6962 Merkle tree, SHA-256 leaves with domain
  separators (`fd0-translog-{leaf,node,empty,sth,server-info}-v1`).
- Ed25519-signed STHs; mandatory on every `/sync` response carrying
  events. Mandatory inclusion proofs per pulled event; optional
  consistency proof against client-supplied `last_sth_size`.
- First-contact pinning via `/v1/server-info` (TOFU + safety-
  number ceremony, opt-in non-TTY via `FD0_AUTO_PIN`).
- Atomic keyfile-↔-DB lifecycle: 5×2 startup matrix; refuses to
  start on mismatch.

### Witness

- `fd0-witness` binary: passive STH archiver, polls upstream
  servers, detects same-size and different-size equivocation.
- Cosign protocol (`WitnessedSTH`, domain
  `fd0-witness-cosign-v1`): the witness cosigns honest STHs and
  withholds on consistency failure (no signing oracle for forks).
- Client cross-check via `[[witness]]` config and
  `[witness_policy] min_cosigns`. A 409 from the witness archive
  (multi-root at size) is a hard equivocation refusal.
- `/v1/witness/highest` and `/v1/witness/equivocation` probes
  catch first-fetch rollback (T41) and historical equivocation
  across the chain (T35).

### Storage

- Append-only CBOR chain files; vault `chain_tip` binds the
  latest accepted seq+hash; single-file rollback is detected on
  open.
- Local compaction drops superseded `secret.set` events. The
  transparency log is unaffected — anchored by STHs, not local
  events.
- Atomic vault rewrites (`vault.enc.tmp + fsync + rename + fsync
  parent`). `O_NOFOLLOW` on every chain-file and vault open
  (T18 symlink-redirect defence).

### Threat model

- 54 catalogued threats (T01–T54) across six attacker classes (A1
  hosted-server operator through A6 coerced/lost-credential) and
  six trust boundaries (TB1–TB6).
- Every non-📋/⛔ threat has at least one `// THREAT: Txx`
  annotation in production code; `tools/threat-coverage`
  (`make lint`) enforces the doc-↔-code link.
- 8 semgrep rules (`tools/semgrep/`) freeze real bug classes
  surfaced during security review.

### Tooling

- `fd0 doctor`: read-only health check; sections for agent, user
  chain, scopes, auth-method consistency, and orphan files.
- `cmd/fd0-yubikey-record`: hardware-day recorder that captures
  golden vectors against a real YubiKey. CI replays them through
  the pure-software path on every push.
- `cmd/fd0-test-{bad-witness,equiv-inject,mitm}`: adversarial
  test harnesses for integration tests.
- Wire-format compat snapshot at `internal/wirecompat/testdata/v1/`
  pins the on-disk format; `TestWireCompatV1Verify` fails on any
  break.

### Testing

- 17 shell integration tests (~5,500 LoC) including a 563-line
  multi-user e2e and a 91-assertion YubiKey e2e with optional
  200-cycle stress phase (`FD0_YUBIKEY_STRESS=N`).
- 4 rounds of brutal adversarial code review (4 P0 + 20 P1 + 16
  P2 findings total; 10 production-bug-class fixes).
- Performance baseline (`BENCH.md`) covering server-side translog,
  client-side chain replay, and vault unlock.

### Out of scope for v1.0 — deferred to v1.x or later

- Full user-chain sync (subsequent `auth.set` events propagated to
  the server). v1 idempotently registers the genesis only.
- STH archive endpoint (`GET /v1/sth/{cid}?at_size={n}`) — current
  STH only.
- Per-scope sensitivity flag (re-prompt before sign/decrypt on
  high-value scopes).
- Per-event forward secrecy (all events under one OEK era share
  the same key).
- User-chain compaction.
- OS keystore backends (macOS Keychain, Linux Secret Service,
  Windows Credential Manager).
