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
# 1. Plug in the YubiKey. Read the firmware version (e.g. via `ykman info`).

# 2. Run the recorder. --output writes via temp+rename so a recording
#    failure leaves the existing fixture untouched. DO NOT use shell
#    redirect (`> v1.json`) — that truncates before the recorder runs.
go run -tags=yubikey ./cmd/fd0-yubikey-record \
    --firmware 5.7.1 \
    --output internal/crypto/yubikey/testdata/golden/v1.json

# 3. Verify the fixture replays under the pure-Go path.
go test ./internal/crypto/yubikey/... -run TestGolden

# 4. Commit. The diff is the recording.
git add internal/crypto/yubikey/testdata/golden/v1.json
git commit -m "yubikey: record golden vectors (firmware 5.7.1)"
```

`v1.json` carries 8 recorded vectors against YubiKey firmware 5.7.4,
slot 9d, spanning plaintext lengths 0, 13, 32, 64, 256, 1024 bytes.
CI replays them through the pure-Go path on every push to detect
open-path drift. When the fixture is intentionally empty (vectors
array `[]`), the replay test skips cleanly with a hint pointing at
this workflow.

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
