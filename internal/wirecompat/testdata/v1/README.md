# Wire-format compat snapshot v1

Golden-file snapshot pinning the on-disk format produced by fd0 v1.0. `TestWireCompatV1Verify` fails on any change to vault.enc / chain CBOR layout, vault wrap construction, AAD inputs, or replay semantics that breaks compatibility with these files.

## Files

| File | Source |
|---|---|
| `vault.enc` | `vault.Save()` — header + 1 passphrase wrap, body AEAD-sealed |
| `user.cbor` | `chain.AppendUser()` — single auth.set genesis with 1 method |
| `s_*.cbor` | `chain.AppendScope()` — genesis member.change + 1 secret.set |

## Reproducibility

The identity (`user_super_pub`) is derived from a fixed `sha-512("fd0-wire-compat-v1-identity")[:32]` seed, so regenerating from the same code reliably produces the same pubkey. Random nonces inside AEAD wraps and the OEK make the binary bytes non-deterministic across regenerations; the test asserts that the snapshot decrypts cleanly and replays to the expected state, not byte equality.

## When to regenerate

Only when a wire-format break is intentional. Bump to `testdata/v2/`, duplicate the regenerator and verifier with v2 expectations, and leave the v1 snapshot in place so old-format coverage stays (useful for migration logic if a future version adds one).

```sh
WIRE_COMPAT_REGEN=1 go test ./internal/wirecompat \
    -run TestWireCompatV1Regenerate
```

## Snapshot details (v1)

- **Passphrase**: `fd0-wire-compat-v1`
- **Method ID**: `am_compatv1aaaaaaaaaaaaaaaaaaa`
- **Identity seed source**: `sha-512("fd0-wire-compat-v1-identity")[:32]`
- **Public key (deterministic)**:
  `08b3b16e241a462cc7b4423780ca3dca8688111d4b2c86c7da8809ae7a5a0f7e`
- **Scope label**: `compat-test-scope`
- **Secret name**: `API_KEY` with payload `compat-v1-payload-stable-bytes`
