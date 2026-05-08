# YubiKey golden vectors

`v1.json` pins the YubiKey-PIV sealed-box open path against drift. CI
replays each `(sealed, shared, plaintext)` vector through the pure-
software `OpenSealedFromShared` and asserts equality.

The slot's private key is **never** in the fixture. We record the
on-card ECDH output (`shared`) instead — that lets the test reproduce
the post-ECDH path without any secret material.

## Layout

```
v1.json
├── version              schema version, currently 1
├── recorded_at          RFC 3339 timestamp of the recording run
├── firmware             YubiKey firmware string (e.g. "5.7.1")
├── slot                 PIV slot ("9d" = Key Management, default)
├── card_x25519_pub_hex  the slot's 32-byte X25519 pubkey
└── vectors[]
    ├── name             short label
    ├── sealed_hex       full crypto_box_seal blob
    ├── shared_hex       on-card ECDH output for sealed_hex's ephPub
    └── plaintext_hex    expected open() output
```

## Hardware-day workflow

```sh
# 1. Plug in the YubiKey.
go run -tags=yubikey ./cmd/fd0-yubikey-record \
    > internal/crypto/yubikey/testdata/golden/v1.json

# 2. Verify the fixture replays under the pure-Go path.
go test ./internal/crypto/yubikey/... -run TestGolden

# 3. Commit the JSON. The diff is the recording.
git add internal/crypto/yubikey/testdata/golden/v1.json
git commit -m "yubikey: record golden vectors (firmware <X.Y.Z>)"
```

The placeholder `vectors: []` ships with the repo so the replay test
runs (and skips cleanly) until real vectors land. CI passes either
way.

## Regenerating

Only when:

- A YubiKey firmware bug surfaces and we want to pin pre-fix vs post-
  fix behaviour with two fixtures.
- The recorder gets a new field (bump the schema, write `v2.json`,
  keep `v1.json` for migration coverage).

Otherwise: don't. The vectors are wire-format frozen by design.

## What this catches

- A change to `OpenSealedFromShared` that breaks compatibility with
  real hardware output — caught at CI on next push.
- A change to `ParseSealed` that moves the eph/ct boundary — caught
  at vector load time.

## What this does NOT catch

- Bugs in the on-card ECDH itself (firmware bugs in the YubiKey).
  Those would have to be diagnosed against the libsodium reference
  separately; the recorder's self-check (cmd/fd0-yubikey-record)
  surfaces obvious cases by attempting to open every recorded vector
  before writing the fixture.
