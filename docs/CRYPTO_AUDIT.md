# Protocol and Cryptographic Composition Audit

Status: internal defensive review completed on 2026-07-23 against the revision
that contains this document.

This review checks whether fd0 composes its cryptographic primitives and
protocol state transitions consistently. It is not a formal proof and does not
replace an independent cryptographic audit.

## Result

The reviewed v1 constructions have explicit implementation and regression-test
evidence. The review found and fixed three additional integrity and migration
defects:

1. Vault mutation paths accepted a caller-supplied identity without checking
   it against the existing vault. `SaveBody`, `AddWrap`, and `RemoveWrap` now
   reject a mismatch before writing.
2. Gap-tolerant replay let a shortened local scope retain the real final event
   while omitting a newer secret version. Replay now requires the full hash
   chain. Sync repairs older compacted files from a pinned,
   transparency-verified server copy while preserving local-only events.
3. Witness databases created before cosigning lacked the
   `witness_signature` column. Startup now migrates those archives
   idempotently, retaining old evidence and enabling new cosigned rows.

No unresolved reportable protocol or cryptographic-composition finding remains
within the reviewed scope. The residual risks and external-review requirement
below still apply.

## Scope

The review followed these paths end to end:

- deterministic encoding, decoding limits, signed inputs, and content hashes;
- Ed25519 identities and their X25519 conversion;
- AES-256-GCM keys, nonces, AAD construction, and vault wrapping;
- libsodium-compatible sealed boxes and OEK delivery;
- Argon2id passphrase derivation and parameter validation;
- YubiKey PIV resolver and software-equivalent open path;
- user and scope replay, membership changes, OEK rotation, and revocation;
- transparency-log hashes, proofs, STHs, server pins, and witness cosigns;
- v1 vault, chain, and additive-CBOR compatibility.

Distribution signing, Electron sandboxing, IPC authorization, local lifecycle,
HTTP limits, and server resource budgets were reviewed and remediated in their
respective security work items. They are outside this document's narrow
cryptographic-composition scope.

## Invariant Matrix

| Surface | Required invariant | Implementation evidence | Verification evidence |
| --- | --- | --- | --- |
| CBOR encoding | Every signed and hashed typed value has one deterministic encoding. | `internal/proto/cbor.go`; all signed-input helpers call `proto.Marshal`. | `internal/proto/golden_test.go`; `internal/proto/proto_test.go`; v1 wire fixture. |
| CBOR decoding | Ambiguous or resource-hostile forms fail; unknown map fields remain additive. | Duplicate keys, tags, indefinite lengths, oversized collections, excessive nesting, and case-insensitive field matches are rejected. | `internal/proto/adversarial_test.go`; `internal/proto/fuzz_test.go`; YubiKey forward-compat test. |
| Domain separation | Signature, hash, KDF-context, and AEAD domains are distinct and prefix-disjoint. | Constants in `internal/proto/domain.go`; dedicated constructors at each call site. | Literal golden pins and pairwise prefix tests in `internal/proto`. |
| User events | The super identity signs kind, sequence, previous hash, identity, and complete active auth set. | `UserEvent.SignedInput`; `chain.ReplayUser`. | Golden signed input, replay, malformed-chain, and v1 wire tests. |
| Scope events | The author, scope, sequence, previous hash, OEK era, deliveries, and encrypted payload are signed. | `ScopeEvent.SignedInput`; `chain.ReplayScope`. | Adversarial, malicious-member, invariant, property, fuzz, and wire tests. |
| HTTP authentication | Method, path, canonical query, timestamp, nonce, body hash, client key, and pinned server key are bound. | `proto.HTTPSignedInput`; server auth verification. | Every-field, body-hash, server-binding, replay, and fuzz tests. |
| AEAD primitive | AES-256-GCM uses only 32-byte keys and 12-byte nonces; tag failure is fatal. | `crypto.AEADSeal` and `crypto.AEADOpen`. | Known behavior, tamper matrix, wrong-size, and property tests. |
| Encrypted super key | Ciphertext is bound to the identity and auth method. | AAD is `DomainEncryptedSuperPriv || user_super_pub || method_id`. | Vault resolver and wrong-context tests. |
| Vault wraps | Each payload-key wrap is bound to identity and the complete wrap header. | AAD includes method ID, type, public parameters, and nonce. | Vault open, tamper, add/remove idempotence, and v1 fixture tests. |
| Vault body | The body is bound to magic, version, identity, every wrap, and body nonce. | `bodyAAD` covers `VaultFileHeader`. | Header/body tamper tests and v1 fixture. |
| Vault ownership | An existing vault cannot be re-sealed under a different identity accidentally. | `readForMutation` gates all existing-vault mutation paths. | Identity-mismatch tests assert the operation fails and file bytes remain unchanged. |
| Scope payloads | Secret bodies and membership projections cannot move between events or payload kinds. | `BodyAAD` and `ProjectionAAD` bind the event context and use distinct canonical payload shapes. | Context-field and cross-payload AEAD tests in `internal/chain/aad_invariants_test.go`. |
| Nonces | Every AES-GCM encryption obtains a fresh 96-bit CSPRNG nonce. | All writers use `crypto.Nonce12`, backed by `crypto/rand`. | Nonce size and sampled uniqueness tests. |
| Passphrase KDF | New passphrase methods use Argon2id with 64 MiB, 3 passes, one lane; hostile parameters cannot panic or exhaust memory. | `DefaultArgon2`; bounded `ValidateArgon2`. | Argon2 known-answer, bounds, resolver, and benchmark tests. |
| Ed25519 to X25519 | Conversion matches libsodium and cannot expose the unused SHA-512 half through slice capacity. | `EdPubToX25519`; `EdPrivToX25519`; typed signing keys. | Pair consistency, bad-input, no-cap-leak, and property tests. |
| Sealed boxes | OEK and YubiKey blobs use libsodium-compatible anonymous boxes and reject wrong recipients, malformed points, or tampering. | `SealAnonymous`; `OpenAnonymous`; decomposed `OpenSealedFromShared`. | Frozen vectors, independent open-path comparison, tamper properties, YubiKey mock and tagged tests. |
| OEK rotation | Every membership change advances the OEK exactly once and delivers it only to the post-mutation member set. | Scope builder, replay state machine, and server validator. | Malicious-member, limits, invariant, property, and removal-panic tests. |
| Replay and revocation | Sequences are contiguous, previous hashes match, authors are current members, omitted local history is repaired before sync, and removed auth methods stop working. | Chain replay, sync reconciliation, agent auth-set checks. | Omitted-event regression, isolated legacy-history repair, rollback, revocation, and integration tests. |
| Transparency log | Leaf, node, and empty hashes are disjoint; proof shape, size, and roots must agree. | `internal/translog`; RFC 6962-style proof verification. | Exhaustive small trees, boundary cases, tamper, fuzz, and stress tests. |
| Server and witness trust | STHs use the pinned server key; witness cosigns bind exact STH, chain, server URL, and witness pin. | STH/server-info/witness signed inputs; explicit first-contact pins. | Wrong-pin, cross-server, cross-chain, tamper, property, and first-contact tests. |

## Compatibility and Migration

| Artifact | Compatibility rule | Evidence |
| --- | --- | --- |
| `vault.enc` v1 | Version 1 remains readable; unsupported versions fail closed. | Committed `internal/wirecompat/testdata/v1/vault.enc` opened through production APIs. |
| User chain v1 | Existing auth events retain their signed bytes and replay semantics. | Committed `user.cbor`, signed-input goldens, and replay tests. |
| Scope chain v1 | Existing membership, OEK delivery, and secret events remain decryptable and replayable. | Committed scope chain fixture and full replay to plaintext. |
| Optional map fields | Readers ignore unknown map keys; new security semantics must still be signature-bound by the new typed schema. | Decoder configuration and forward-compat tests. |
| Legacy optional fields | Missing `omitempty` fields decode to their documented zero-value fallback. | Push-floor, per-server state, YubiKey policy, and pinned-server tests. |
| Server indexes | Derived membership state is versioned and rebuildable from authoritative chains. | Store schema-state migration and rebuild tests. |
| Legacy compacted scopes | Reads fail closed; sync replaces the file only from a pinned, transparency-verified full pull and transactionally replays local-only events. | `TestReplayScopeRejectsOmittedCurrentSecretWithRealFinalTip`; `integration_scope_history_repair.sh`. |
| Legacy witness archives | Missing nullable cosign column is added in place; old rows remain evidence but not verified cosigns. | `TestOpenMigratesLegacyWitnessArchive` covers old-row reads, new inserts, HTTP serving, and idempotent reopen. |

The decoder deliberately does not promise that every well-formed alternative
CBOR byte representation is rejected. Security decisions operate on typed
values and reconstruct deterministic signed/hash inputs. HTTP body signatures,
where raw bytes matter, bind the exact body hash.

Schema evolution has two hard constraints:

- Security-relevant fields in signed structures require a protocol/domain
  version change and a coordinated rollout. An older typed signer cannot bind a
  field it does not know.
- Security-relevant additions to `VaultBody` require a vault version migration
  or minimum-writer gate. Older writers decode unknown fields additively but
  cannot preserve them when re-sealing the typed body.

## Verification Commands

The audit uses these reproducible suites:

```sh
go test ./internal/proto ./internal/crypto ./internal/crypto/yubikey \
  ./internal/vault ./internal/chain ./internal/translog \
  ./internal/wirecompat ./internal/agent ./internal/witness ./internal/cli

go test -tags=yubikey ./internal/crypto/yubikey ./internal/vault ./internal/agent
go test -race ./internal/proto ./internal/crypto ./internal/vault ./internal/translog
go test ./internal/wirecompat -run TestWireCompatV1Verify
bash tests/run_isolated_integration.sh tests/integration_scope_history_repair.sh
```

Repository-wide tests, vet, Desktop checks, website build, and isolated
integration tests remain release gates in addition to these focused suites.

## Residual Risk

- AES-GCM nonces are random rather than statefully allocated. Collision risk is
  negligible at fd0's intended scale but not mathematically impossible.
- Routine `SaveBody` operations retain the current payload key until an auth
  method rotation. This is documented behavior, not per-write forward secrecy.
- Memory wiping in Go is best-effort. The agent reduces exposure with locked
  memory and bounded unlock lifetime, but the runtime cannot provide a formal
  no-copy guarantee for every transient value.
- Compromise of an authorized member or unlocked endpoint permits all actions
  that principal is authorized to perform. fd0 limits persistence through
  revocation and OEK rotation; it cannot retract plaintext already observed.
- A coordinated rollback of all client state remains outside the v1 threat
  model unless another device or witness retains a newer checkpoint.
- Hardware behavior depends on the YubiKey PIV implementation and platform
  middleware in addition to fd0's software checks.
- Existing frozen sealed-box vectors and the independent NaCl-compatible open
  path provide implementation evidence, but the fixture set was not generated
  by a separately maintained implementation.

## External Review Gate

Before declaring protocol v1 stable for a 1.0 release, commission an independent
review covering:

1. the constructions and invariants in this document;
2. interoperability vectors produced by an implementation outside this Go
   module;
3. YubiKey PIV behavior on supported hardware and operating systems;
4. rollback, recovery, membership rotation, and witness ceremonies as complete
   user workflows;
5. the final release artifacts and update/install trust chain.

Treat external findings as protocol release blockers until validated and either
fixed or explicitly accepted in `docs/THREATS.md`.
