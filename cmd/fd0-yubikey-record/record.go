// Package main provides the fd0-yubikey-record binary, which captures
// golden vectors from a connected YubiKey for offline replay testing.
//
// The recorder lives in two halves:
//
//   - record.go (this file): the pure-software recording loop. It
//     takes a yubikey.Card, generates plaintexts, seals them, runs
//     ECDH via the card, and self-verifies each tuple before
//     appending it to the fixture. It compiles in both build
//     configurations and is fully unit-testable via MockCard.
//
//   - main.go / main_stub.go: thin entry points. The yubikey-tagged
//     main opens a real card; the no-tag stub prints a hint and exits.
//
// Splitting it this way means the entire recording logic is exercised
// in CI without hardware. Hardware day only verifies the wiring at
// the seam between yubikey.Open and Record.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/crypto/yubikey"
)

// recordOptions controls Record's behaviour. The defaults are tuned
// for a hardware-day session: a handful of vectors at varied
// plaintext lengths, deterministic enough to diff fixture-on-fixture
// across firmware revisions if needed.
type recordOptions struct {
	// Count is the number of vectors to capture. Each vector touches
	// the card once for ECDH, so the recording wall-time scales
	// linearly with this value.
	Count int
	// PlaintextSizes drives the per-vector payload size. If shorter
	// than Count the slice cycles. Empty / nil ⇒ default sizes.
	// All entries MUST be >= 0; Record validates this before the loop
	// so a negative value never reaches make([]byte, n).
	PlaintextSizes []int
	// Firmware is the YubiKey firmware string written into the
	// fixture. Hardware-day callers either pass --firmware or rely
	// on the recorder reading it from the card; today's stub leaves
	// this empty and the caller is responsible for setting it.
	Firmware string
	// Rand is the entropy source used for plaintext generation.
	// Default crypto/rand.Reader; tests use a deterministic source.
	Rand io.Reader
	// Now is the timestamp written into the fixture. Default
	// time.Now in UTC; tests pass a fixed time.
	Now func() time.Time
}

// fixtureSlot is hard-coded because v1 supports exactly one PIV slot
// (SlotKeyManagement = 0x9d). Surfacing it as a flag would let the
// caller write a fixture whose declared slot doesn't match what the
// recorder actually opened — LoadGoldenFixture would then reject the
// recording at replay time. Keep the two in lockstep here.
const fixtureSlot = "9d"

// defaultPlaintextSizes covers the realistic spread of fd0 sealed-
// box payloads (seal-of-K_unlock = 32, OEK delivery ~ 32, plus
// padding for future fields). The 0 case pins the empty-plaintext
// edge.
var defaultPlaintextSizes = []int{0, 13, 32, 64, 256, 1024}

// Record drives the YubiKey through `opts.Count` sealed-box rounds,
// self-verifies each one, and returns a complete GoldenFixture ready
// for serialisation.
//
// On any failure — bad ECDH output, AEAD verify failure during the
// self-check, length mismatch — Record returns immediately with an
// error rather than committing a partial fixture. A partial recording
// is worse than no recording: it would silently pin a bad path.
func Record(card yubikey.Card, opts recordOptions) (yubikey.GoldenFixture, error) {
	if card == nil {
		return yubikey.GoldenFixture{}, errors.New("recorder: card is nil")
	}
	if opts.Count <= 0 {
		return yubikey.GoldenFixture{}, fmt.Errorf("recorder: count must be > 0, got %d", opts.Count)
	}
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC().Truncate(time.Second) }
	}
	sizes := opts.PlaintextSizes
	if len(sizes) == 0 {
		sizes = defaultPlaintextSizes
	}
	for i, s := range sizes {
		if s < 0 {
			return yubikey.GoldenFixture{}, fmt.Errorf("recorder: PlaintextSizes[%d] = %d, must be >= 0", i, s)
		}
	}

	pub, err := card.PublicX25519()
	if err != nil {
		return yubikey.GoldenFixture{}, fmt.Errorf("recorder: card pubkey: %w", err)
	}
	if len(pub) != 32 {
		return yubikey.GoldenFixture{}, fmt.Errorf("recorder: card pubkey is %d bytes, want 32", len(pub))
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)

	vectors := make([]yubikey.GoldenVector, 0, opts.Count)
	for i := 0; i < opts.Count; i++ {
		size := sizes[i%len(sizes)]
		plain := make([]byte, size)
		if size > 0 {
			if _, err := io.ReadFull(opts.Rand, plain); err != nil {
				return yubikey.GoldenFixture{}, fmt.Errorf("recorder: vector[%d] rng: %w", i, err)
			}
		}

		sealed, err := crypto.SealAnonymous(plain, pub)
		if err != nil {
			return yubikey.GoldenFixture{}, fmt.Errorf("recorder: vector[%d] seal: %w", i, err)
		}
		eph, ct, err := crypto.ParseSealed(sealed)
		if err != nil {
			return yubikey.GoldenFixture{}, fmt.Errorf("recorder: vector[%d] parse: %w", i, err)
		}
		shared, err := card.SharedSecret(eph[:])
		if err != nil {
			return yubikey.GoldenFixture{}, fmt.Errorf("recorder: vector[%d] ECDH: %w", i, err)
		}

		// Self-check: open the just-sealed blob via the same path the
		// replay test will use. If this fails, the card returned a
		// shared secret that doesn't match a software ECDH against
		// the claimed pubkey — refuse to write a poisoned fixture.
		gotPlain, openErr := crypto.OpenSealedFromSharedErr(eph, pubArr, ct, shared)
		if openErr != nil {
			return yubikey.GoldenFixture{}, fmt.Errorf("recorder: vector[%d] self-check open failed (card produced inconsistent shared secret): %w", i, openErr)
		}
		if !equalBytes(gotPlain, plain) {
			return yubikey.GoldenFixture{}, fmt.Errorf("recorder: vector[%d] self-check plaintext mismatch — card or open path is buggy; refusing to write fixture", i)
		}

		vectors = append(vectors, yubikey.GoldenVector{
			Name:         fmt.Sprintf("vec%02d-len%d", i, size),
			SealedHex:    hex.EncodeToString(sealed),
			SharedHex:    hex.EncodeToString(shared),
			PlaintextHex: hex.EncodeToString(plain),
		})
	}

	return yubikey.GoldenFixture{
		Version:          yubikey.FixtureVersion,
		RecordedAt:       opts.Now(),
		Firmware:         opts.Firmware,
		Slot:             fixtureSlot,
		CardX25519PubHex: hex.EncodeToString(pub),
		Vectors:          vectors,
	}, nil
}

// equalBytes is constant-time over the longer slice. Comparing
// plaintexts directly with bytes.Equal would early-exit on first
// mismatch; for a self-check this is fine, but a constant-time
// equal removes the (theoretical) timing side channel during a
// recording session that walks varied payload lengths.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
