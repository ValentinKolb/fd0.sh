package yubikey

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
)

// Golden-vector fixtures pin the YubiKey-PIV sealed-box open path
// against drift. Hardware day captures real card outputs; CI replays
// them against the pure-software OpenSealedFromShared path. If anyone
// later changes the open path's algorithm and the change does not
// match what a real card produces, the replay fails before any user
// runs into it.
//
// The fixture intentionally records the ON-CARD ECDH output (shared)
// rather than the slot's private key. The slot priv never leaves
// hardware; replay therefore needs no scalar multiplication, no
// secrets handling, and reproduces 100% of the post-ECDH path. A
// fixture that travels in source control is safe.

// FixtureVersion is the wire-format version of golden-vector fixtures.
// Bump when the JSON schema changes in a backwards-incompatible way.
const FixtureVersion = 1

// GoldenFixture is the on-disk JSON shape produced by the recorder
// (cmd/fd0-yubikey-record on hardware day) and consumed by the
// replay test.
type GoldenFixture struct {
	// Version pins the schema; loader rejects unknown values so a
	// future format never silently mis-parses.
	Version int `json:"version"`
	// RecordedAt is an RFC 3339 timestamp marking the recording run.
	// Informational; not used by the verifier.
	RecordedAt time.Time `json:"recorded_at"`
	// Firmware is the YubiKey firmware version reported at record
	// time, e.g. "5.7.1". Lets a future debugger correlate vectors
	// with firmware-specific behaviour.
	Firmware string `json:"firmware"`
	// Slot is the PIV slot the recording targeted, e.g. "9d".
	Slot string `json:"slot"`
	// CardX25519PubHex is the slot's 32-byte X25519 pubkey, hex-encoded.
	// Same value all vectors in this fixture were sealed to; the
	// libsodium nonce derivation binds the recipient pub into the
	// open path.
	CardX25519PubHex string `json:"card_x25519_pub_hex"`
	// Vectors are the per-message recorded tuples.
	Vectors []GoldenVector `json:"vectors"`
}

// GoldenVector pins one (sealed, shared, plaintext) triple. Replay
// asserts:
//
//	ParseSealed(sealed) → (ephPub, ct)
//	OpenSealedFromShared(ephPub, card_pub, ct, shared) == plaintext
//
// The recorder is responsible for ensuring `shared` is the actual
// on-card ECDH output for `ephPub`; if not, AEAD authentication
// fails and the recorder will refuse to emit the vector (see
// recorder self-check, subtask 5).
type GoldenVector struct {
	// Name is a short label for diagnostics.
	Name string `json:"name"`
	// SealedHex is the full crypto_box_seal blob, hex-encoded.
	SealedHex string `json:"sealed_hex"`
	// SharedHex is the 32-byte X25519 shared secret produced on-card
	// for this vector's embedded ephemeral pubkey, hex-encoded.
	SharedHex string `json:"shared_hex"`
	// PlaintextHex is the expected open() output, hex-encoded
	// (empty string for empty plaintext, NOT JSON null).
	PlaintextHex string `json:"plaintext_hex"`
}

// ErrFixtureBadVersion is returned by LoadGoldenFixture when the
// fixture's version is unsupported.
var ErrFixtureBadVersion = errors.New("yubikey: golden fixture version unsupported")

// LoadGoldenFixture reads a golden-vector JSON file from disk and
// validates structural invariants:
//
//   - Version is exactly FixtureVersion.
//   - card_x25519_pub_hex decodes to 32 bytes.
//   - Each vector's sealed_hex / shared_hex / plaintext_hex decodes.
//   - sealed_hex is at least SealedMinLen bytes (32 + 16).
//   - shared_hex is exactly 32 bytes.
//
// Cryptographic verification (ECDH consistency, AEAD success) happens
// at replay time via OpenSealedFromShared; LoadGoldenFixture only
// catches malformed files.
func LoadGoldenFixture(path string) (*GoldenFixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("yubikey: read fixture %q: %w", path, err)
	}
	return parseGoldenFixture(raw, path)
}

// fixtureRequiredFields is the set of JSON keys every well-formed
// fixture must carry. We assert presence explicitly because Go's JSON
// decoder happily defaults missing strings to "" and missing slices to
// nil, which would silently turn a malformed fixture into a "valid
// empty" one.
var fixtureRequiredFields = []string{
	"version", "recorded_at", "firmware", "slot",
	"card_x25519_pub_hex", "vectors",
}

// vectorRequiredFields is the per-tuple equivalent of
// fixtureRequiredFields.
var vectorRequiredFields = []string{
	"name", "sealed_hex", "shared_hex", "plaintext_hex",
}

func parseGoldenFixture(raw []byte, path string) (*GoldenFixture, error) {
	// Hand-edited JSON occasionally arrives with a UTF-8 BOM that
	// json.Decoder rejects with a confusing error. Strip it so manual
	// fixture editing is forgiving.
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})

	// First pass: validate field presence at the top level and inside
	// each vector. Done before the typed decode so missing-vs-empty is
	// detectable per JSON semantics, not per Go zero-value semantics.
	var presence struct {
		Top     map[string]json.RawMessage `json:"-"`
		Vectors []map[string]json.RawMessage
	}
	if err := json.Unmarshal(raw, &presence.Top); err != nil {
		return nil, fmt.Errorf("yubikey: decode fixture %q: %w", path, err)
	}
	for _, k := range fixtureRequiredFields {
		if _, ok := presence.Top[k]; !ok {
			return nil, fmt.Errorf("yubikey: fixture %q missing required field %q", path, k)
		}
	}
	if rawVectors, ok := presence.Top["vectors"]; ok {
		if err := json.Unmarshal(rawVectors, &presence.Vectors); err != nil {
			return nil, fmt.Errorf("yubikey: fixture %q vectors: %w", path, err)
		}
		for i, v := range presence.Vectors {
			for _, k := range vectorRequiredFields {
				if _, ok := v[k]; !ok {
					return nil, fmt.Errorf("yubikey: fixture %q vector[%d] missing required field %q", path, i, k)
				}
			}
		}
	}

	// Second pass: typed decode with strict unknown-field rejection
	// and an explicit io.EOF check after the first JSON value so
	// trailing garbage cannot ride along undetected.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f GoldenFixture
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("yubikey: decode fixture %q: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("yubikey: fixture %q: trailing data after first JSON value: %v", path, err)
	}

	if f.Version != FixtureVersion {
		return nil, fmt.Errorf("%w: have %d, want %d (%s)", ErrFixtureBadVersion, f.Version, FixtureVersion, path)
	}
	if err := validateSlot(f.Slot); err != nil {
		return nil, fmt.Errorf("yubikey: fixture %q: %w", path, err)
	}
	cardPub, err := hex.DecodeString(f.CardX25519PubHex)
	if err != nil {
		return nil, fmt.Errorf("yubikey: fixture %q: card_x25519_pub_hex: %w", path, err)
	}
	if len(cardPub) != 32 {
		return nil, fmt.Errorf("yubikey: fixture %q: card_x25519_pub_hex is %d bytes, want 32", path, len(cardPub))
	}
	for i, v := range f.Vectors {
		if err := v.validate(); err != nil {
			return nil, fmt.Errorf("yubikey: fixture %q vector[%d] %q: %w", path, i, v.Name, err)
		}
	}
	return &f, nil
}

// validateSlot rejects fixtures whose slot string is not one of the
// PIV slots fd0 supports. v1 only uses Key Management ("9d").
func validateSlot(s string) error {
	switch s {
	case "9d":
		return nil
	}
	return fmt.Errorf("slot %q not supported (v1 expects \"9d\")", s)
}

// CardPub decodes the fixture's card pubkey to bytes. Callers should
// have first run LoadGoldenFixture, which already validates length.
func (f *GoldenFixture) CardPub() ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(f.CardX25519PubHex)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("yubikey: card pub is %d bytes, want 32", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// validate runs the per-vector structural checks.
func (v GoldenVector) validate() error {
	sealed, err := hex.DecodeString(v.SealedHex)
	if err != nil {
		return fmt.Errorf("sealed_hex: %w", err)
	}
	// Match ParseSealed's lower bound rather than re-implementing it —
	// single source of truth lives in package crypto.
	if len(sealed) < crypto.SealedMinLen {
		return fmt.Errorf("sealed_hex is %d bytes, want >= %d", len(sealed), crypto.SealedMinLen)
	}
	shared, err := hex.DecodeString(v.SharedHex)
	if err != nil {
		return fmt.Errorf("shared_hex: %w", err)
	}
	if len(shared) != 32 {
		return fmt.Errorf("shared_hex is %d bytes, want 32", len(shared))
	}
	if _, err := hex.DecodeString(v.PlaintextHex); err != nil {
		return fmt.Errorf("plaintext_hex: %w", err)
	}
	return nil
}

