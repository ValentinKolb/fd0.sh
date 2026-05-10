package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/crypto/yubikey"
)

// fixedTime returns a deterministic clock for fixtures captured under
// test. Real hardware-day runs use time.Now().
func fixedTime() func() time.Time {
	t := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// TestRecord_HappyPath runs the full recorder against a software
// MockCard and asserts every produced vector is consistent: it loads
// via the package's own loader and replays through the open path
// back to the recorded plaintext.
func TestRecord_HappyPath(t *testing.T) {
	t.Parallel()
	card := mustMockCard(t)

	rng, err := newSeededRand("happy-path-seed")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := Record(card, recordOptions{
		Count:    6,
		Firmware: "MOCK-FIRMWARE",
		Rand:     rng,
		Now:      fixedTime(),
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	if fixture.Version != yubikey.FixtureVersion {
		t.Fatalf("version: got %d want %d", fixture.Version, yubikey.FixtureVersion)
	}
	if fixture.Slot != "9d" {
		t.Fatalf("slot: got %q want %q", fixture.Slot, "9d")
	}
	if fixture.Firmware != "MOCK-FIRMWARE" {
		t.Fatalf("firmware: got %q want %q", fixture.Firmware, "MOCK-FIRMWARE")
	}
	if fixture.RecordedAt.IsZero() {
		t.Fatalf("recorded_at is zero — recorder did not stamp time")
	}
	if got, want := len(fixture.Vectors), 6; got != want {
		t.Fatalf("vectors len: got %d want %d", got, want)
	}

	cardPubHex := fixture.CardX25519PubHex
	cardPubBytes, err := hex.DecodeString(cardPubHex)
	if err != nil {
		t.Fatalf("card pub hex: %v", err)
	}
	wantPub, _ := card.PublicX25519()
	if !bytes.Equal(cardPubBytes, wantPub) {
		t.Fatalf("recorded card pub != live card pub")
	}

	// Round-trip through the loader. A valid recording MUST pass
	// LoadGoldenFixture with no errors — that proves the on-disk
	// shape matches the schema.
	dir := t.TempDir()
	path := filepath.Join(dir, "v1.json")
	body, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := yubikey.LoadGoldenFixture(path)
	if err != nil {
		t.Fatalf("LoadGoldenFixture round-trip failed: %v", err)
	}
	if len(loaded.Vectors) != len(fixture.Vectors) {
		t.Fatalf("loader vectors len: got %d want %d", len(loaded.Vectors), len(fixture.Vectors))
	}

	// Replay each vector through the same open path the test suite
	// uses on real hardware-day fixtures. This is the strongest
	// assertion: the recorder produces fixtures that the replay
	// test (golden_test.go) will accept as valid.
	cardPubArr, _ := loaded.CardPub()
	for i, v := range loaded.Vectors {
		sealed, _ := hex.DecodeString(v.SealedHex)
		shared, _ := hex.DecodeString(v.SharedHex)
		wantPlain, _ := hex.DecodeString(v.PlaintextHex)
		eph, ct, err := crypto.ParseSealed(sealed)
		if err != nil {
			t.Fatalf("vector[%d] parse: %v", i, err)
		}
		gotPlain, ok := crypto.OpenSealedFromShared(eph, cardPubArr, ct, shared)
		if !ok {
			t.Fatalf("vector[%d] replay open !ok", i)
		}
		if !bytes.Equal(gotPlain, wantPlain) {
			t.Fatalf("vector[%d] plaintext mismatch", i)
		}
	}
}

func TestRecord_RejectsNilCard(t *testing.T) {
	t.Parallel()
	_, err := Record(nil, recordOptions{Count: 1, Firmware: "x"})
	if err == nil {
		t.Fatalf("expected error for nil card, got nil")
	}
}

func TestRecord_RejectsZeroCount(t *testing.T) {
	t.Parallel()
	card := mustMockCard(t)
	for _, n := range []int{0, -1, -100} {
		_, err := Record(card, recordOptions{Count: n, Firmware: "x"})
		if err == nil {
			t.Fatalf("count=%d: expected error, got nil", n)
		}
	}
}

func TestRecord_FixtureSlotIsHardcoded(t *testing.T) {
	t.Parallel()
	card := mustMockCard(t)
	fixture, err := Record(card, recordOptions{
		Count:    1,
		Firmware: "x",
		Now:      fixedTime(),
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if fixture.Slot != "9d" {
		t.Fatalf("fixture slot: got %q want %q (v1 only supports SlotKeyManagement)", fixture.Slot, "9d")
	}
}

func TestRecord_RejectsNegativePlaintextSize(t *testing.T) {
	t.Parallel()
	card := mustMockCard(t)
	_, err := Record(card, recordOptions{
		Count:          1,
		PlaintextSizes: []int{-1},
		Firmware:       "x",
	})
	if err == nil {
		t.Fatalf("expected error on negative plaintext size, got nil")
	}
}

func TestRecord_PropagatesPubkeyError(t *testing.T) {
	t.Parallel()
	stub := &errCard{pubErr: errors.New("pub-broken")}
	_, err := Record(stub, recordOptions{Count: 1, Firmware: "x"})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestRecord_PropagatesECDHError(t *testing.T) {
	t.Parallel()
	stub := &errCard{
		pub:       make([]byte, 32),
		sharedErr: errors.New("ecdh-broken"),
	}
	_, err := Record(stub, recordOptions{Count: 1, Firmware: "x"})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

// A card that returns a wrong shared (correct length, non-zero, just
// not the actual ECDH output) MUST cause Record to fail at the
// self-check rather than commit a poisoned fixture.
func TestRecord_RejectsBadCardOutput(t *testing.T) {
	t.Parallel()
	stub := &errCard{
		pub:    make([]byte, 32),
		shared: bytes.Repeat([]byte{0xAB}, 32), // valid length, wrong content
	}
	// fill pub with a deterministic non-zero so SealAnonymous accepts
	// it (any 32-byte value works as an X25519 pub for sealing
	// purposes; the AEAD downstream is what fails).
	for i := range stub.pub {
		stub.pub[i] = 0x01
	}
	_, err := Record(stub, recordOptions{Count: 1, Firmware: "x"})
	if err == nil {
		t.Fatalf("expected self-check failure, got nil")
	}
	// Stricter: BOTH must hold — the AEAD sentinel proves the open
	// path identified the failure, and the "self-check" context
	// proves Record framed it correctly. A bare AEAD error without
	// recorder context would mean the message lost its breadcrumb.
	if !errors.Is(err, crypto.ErrSealedAEAD) || !contains(err.Error(), "self-check") {
		t.Fatalf("error should be ErrSealedAEAD wrapped with 'self-check' context, got: %v", err)
	}
}

func TestRecord_DefaultPlaintextSizes_CycleCorrectly(t *testing.T) {
	t.Parallel()
	card := mustMockCard(t)
	count := len(defaultPlaintextSizes) * 2
	fixture, err := Record(card, recordOptions{
		Count:    count,
		Firmware: "x",
		Now:      fixedTime(),
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	for i, v := range fixture.Vectors {
		want := defaultPlaintextSizes[i%len(defaultPlaintextSizes)]
		plain, _ := hex.DecodeString(v.PlaintextHex)
		if len(plain) != want {
			t.Fatalf("vector[%d] plain len: got %d want %d", i, len(plain), want)
		}
	}
}

func TestRecord_CustomPlaintextSizes(t *testing.T) {
	t.Parallel()
	card := mustMockCard(t)
	custom := []int{7, 11, 17}
	fixture, err := Record(card, recordOptions{
		Count:          6,
		PlaintextSizes: custom,
		Firmware:       "x",
		Now:            fixedTime(),
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	for i, v := range fixture.Vectors {
		want := custom[i%len(custom)]
		plain, _ := hex.DecodeString(v.PlaintextHex)
		if len(plain) != want {
			t.Fatalf("vector[%d] plain len: got %d want %d", i, len(plain), want)
		}
	}
}

// ---- helpers ----

func mustMockCard(t *testing.T) *yubikey.MockCard {
	t.Helper()
	c, err := yubikey.NewMockCardFromPriv(deterministicScalar("mock-card-priv"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func deterministicScalar(label string) []byte {
	out := make([]byte, 32)
	copy(out, []byte(label))
	return out
}

// newSeededRand returns an io.Reader that emits a deterministic
// stream derived from `seed`. Used so test runs produce identical
// fixtures across machines and runs — useful when a future test
// wants to assert byte-identical output.
func newSeededRand(seed string) (io.Reader, error) {
	// Simple deterministic stream: cycle the seed bytes. Not a
	// security primitive; it's only used to feed plaintext bytes.
	return &cyclingReader{src: []byte(seed)}, nil
}

type cyclingReader struct {
	src []byte
	pos int
}

func (r *cyclingReader) Read(p []byte) (int, error) {
	if len(r.src) == 0 {
		for i := range p {
			p[i] = 0
		}
		return len(p), nil
	}
	for i := range p {
		p[i] = r.src[r.pos]
		r.pos = (r.pos + 1) % len(r.src)
	}
	return len(p), nil
}

// errCard is a Card whose every method can be made to fail. Used
// here AND in open_test.go but copied to keep the cmd package
// self-contained (no test-only export from the yubikey package).
type errCard struct {
	pub       []byte
	pubErr    error
	shared    []byte
	sharedErr error
}

func (c *errCard) PublicX25519() ([]byte, error) {
	if c.pubErr != nil {
		return nil, c.pubErr
	}
	return append([]byte(nil), c.pub...), nil
}

func (c *errCard) SharedSecret(ephPub []byte) ([]byte, error) {
	if c.sharedErr != nil {
		return nil, c.sharedErr
	}
	if len(c.shared) > 0 {
		return append([]byte(nil), c.shared...), nil
	}
	out := make([]byte, 32)
	out[0] = 0xAA
	return out, nil
}

func (c *errCard) PINRetries() (int, error) { return 3, nil }
func (c *errCard) Close() error              { return nil }

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
