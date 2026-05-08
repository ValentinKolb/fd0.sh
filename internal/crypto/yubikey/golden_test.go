package yubikey

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
)

const goldenFixturePath = "testdata/golden/v1.json"

// TestGolden_Replay walks every vector in testdata/golden/v1.json and
// asserts the pure-software open path produces the recorded plaintext.
//
// On a fresh repo (placeholder fixture, vectors == [])  the test skips
// cleanly with a hint pointing at the recorder. After hardware day the
// same test becomes a sharp regression detector.
func TestGolden_Replay(t *testing.T) {
	t.Parallel()
	f, err := LoadGoldenFixture(goldenFixturePath)
	if err != nil {
		t.Fatalf("load %q: %v", goldenFixturePath, err)
	}
	if len(f.Vectors) == 0 {
		t.Skipf("no golden vectors yet; capture via `go run -tags=yubikey ./cmd/fd0-yubikey-record > %s`", goldenFixturePath)
	}
	cardPub, err := f.CardPub()
	if err != nil {
		t.Fatalf("decode card pub: %v", err)
	}
	if isAllZero32(cardPub) {
		t.Fatalf("card_x25519_pub_hex is all-zero — fixture still holds the placeholder pubkey but vectors are populated")
	}
	for i, v := range f.Vectors {
		name := v.Name
		if name == "" {
			name = fmt.Sprintf("vector[%d]", i)
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sealed := mustHex(t, v.SealedHex)
			shared := mustHex(t, v.SharedHex)
			wantPlain := mustHex(t, v.PlaintextHex)
			eph, ct, err := crypto.ParseSealed(sealed)
			if err != nil {
				t.Fatalf("ParseSealed: %v", err)
			}
			gotPlain, ok := crypto.OpenSealedFromShared(eph, cardPub, ct, shared)
			if !ok {
				t.Fatalf("OpenSealedFromShared returned !ok — recorded vector does not replay through the current open path")
			}
			if !bytes.Equal(gotPlain, wantPlain) {
				t.Fatalf("plaintext mismatch:\n  got  = %x\n  want = %x", gotPlain, wantPlain)
			}
		})
	}
}

// TestGolden_PlaceholderShape pins the empty fixture committed to the
// repo so accidental edits are caught at CI time. Once the recorder
// writes real vectors the test asserts a different (recorded-shape)
// invariant.
func TestGolden_PlaceholderShape(t *testing.T) {
	t.Parallel()
	f, err := LoadGoldenFixture(goldenFixturePath)
	if err != nil {
		t.Fatalf("placeholder must remain loadable: %v", err)
	}
	if f.Version != FixtureVersion {
		t.Fatalf("placeholder version=%d, want %d", f.Version, FixtureVersion)
	}
	if f.Slot != "9d" {
		t.Fatalf("placeholder slot=%q, want %q", f.Slot, "9d")
	}
	cardPub, err := f.CardPub()
	if err != nil {
		t.Fatalf("decode card pub: %v", err)
	}

	if len(f.Vectors) == 0 {
		// Pristine placeholder. Pin the recorded-at sentinel + the
		// firmware tag so casual edits to the file are caught.
		if !f.RecordedAt.IsZero() {
			t.Fatalf("placeholder recorded_at=%v, want zero time (real recordings overwrite this)", f.RecordedAt)
		}
		if f.Firmware != "PLACEHOLDER" {
			t.Fatalf("placeholder firmware=%q, want %q", f.Firmware, "PLACEHOLDER")
		}
		if !isAllZero32(cardPub) {
			t.Fatalf("placeholder vectors=[] but pubkey is non-zero — half-edited fixture")
		}
		return
	}

	// Recorded fixture. The placeholder sentinels must be gone — the
	// recorder is responsible for filling them with real values.
	if f.RecordedAt.IsZero() {
		t.Fatalf("recorded fixture has zero recorded_at — recorder did not stamp a timestamp")
	}
	if f.Firmware == "PLACEHOLDER" || f.Firmware == "" {
		t.Fatalf("recorded fixture has placeholder firmware %q — recorder did not stamp a firmware string", f.Firmware)
	}
	if isAllZero32(cardPub) {
		t.Fatalf("recorded fixture has all-zero pubkey — recorder did not stamp the card pub")
	}
}

// TestLoadGoldenFixture_Roundtrip exercises the loader with a
// programmatically-generated valid fixture (a software MockCard
// produces the shared) so we cover the parse → validate path without
// needing a hardware-recorded file in source control.
func TestLoadGoldenFixture_Roundtrip(t *testing.T) {
	t.Parallel()
	card, err := NewMockCard(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cardPub, _ := card.PublicX25519()

	plain := []byte("roundtrip payload")
	sealed, err := crypto.SealAnonymous(plain, cardPub)
	if err != nil {
		t.Fatal(err)
	}
	eph, _, err := crypto.ParseSealed(sealed)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := card.SharedSecret(eph[:])
	if err != nil {
		t.Fatal(err)
	}

	f := GoldenFixture{
		Version:          FixtureVersion,
		RecordedAt:       time.Now().UTC().Truncate(time.Second),
		Firmware:         "MOCK",
		Slot:             "9d",
		CardX25519PubHex: hex.EncodeToString(cardPub),
		Vectors: []GoldenVector{{
			Name:         "mock-roundtrip",
			SealedHex:    hex.EncodeToString(sealed),
			SharedHex:    hex.EncodeToString(shared),
			PlaintextHex: hex.EncodeToString(plain),
		}},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "v1.json")
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadGoldenFixture(path)
	if err != nil {
		t.Fatalf("LoadGoldenFixture: %v", err)
	}
	if len(loaded.Vectors) != 1 {
		t.Fatalf("vectors len: have %d, want 1", len(loaded.Vectors))
	}
	cp, _ := loaded.CardPub()
	gotPlain, ok := crypto.OpenSealedFromShared(eph, cp, sealed[crypto.SealedEphPubLen:], shared)
	if !ok {
		t.Fatalf("OpenSealedFromShared !ok on roundtrip vector")
	}
	if !bytes.Equal(gotPlain, plain) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestLoadGoldenFixture_RejectsUnknownVersion(t *testing.T) {
	t.Parallel()
	body := []byte(`{"version":99,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9d","card_x25519_pub_hex":"0000000000000000000000000000000000000000000000000000000000000000","vectors":[]}`)
	path := writeTempFixture(t, body)
	_, err := LoadGoldenFixture(path)
	if !errors.Is(err, ErrFixtureBadVersion) {
		t.Fatalf("want ErrFixtureBadVersion, got %v", err)
	}
}

func TestLoadGoldenFixture_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	body := []byte(`{"version":1,"surprise":42,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9d","card_x25519_pub_hex":"0000000000000000000000000000000000000000000000000000000000000000","vectors":[]}`)
	path := writeTempFixture(t, body)
	_, err := LoadGoldenFixture(path)
	if err == nil {
		t.Fatalf("expected unknown-field error, got nil")
	}
	if !strings.Contains(err.Error(), "surprise") {
		t.Fatalf("error should name the surprise field, got: %v", err)
	}
}

func TestLoadGoldenFixture_RejectsBadCardPubHex(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"non-hex":   "ZZ",
		"too-short": "0011",
		"too-long":  strings.Repeat("00", 64),
	}
	for name, badPub := range cases {
		t.Run(name, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"version":1,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9d","card_x25519_pub_hex":%q,"vectors":[]}`, badPub))
			path := writeTempFixture(t, body)
			_, err := LoadGoldenFixture(path)
			if err == nil {
				t.Fatalf("expected error on %q, got nil", badPub)
			}
		})
	}
}

func TestLoadGoldenFixture_RejectsBadVector(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{
			name: "sealed_hex too short",
			body: `{"version":1,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9d","card_x25519_pub_hex":"0000000000000000000000000000000000000000000000000000000000000000","vectors":[{"name":"x","sealed_hex":"00","shared_hex":"0000000000000000000000000000000000000000000000000000000000000000","plaintext_hex":""}]}`,
		},
		{
			name: "shared_hex wrong length",
			body: `{"version":1,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9d","card_x25519_pub_hex":"0000000000000000000000000000000000000000000000000000000000000000","vectors":[{"name":"x","sealed_hex":"` + strings.Repeat("00", 48) + `","shared_hex":"00","plaintext_hex":""}]}`,
		},
		{
			name: "plaintext_hex bad encoding",
			body: `{"version":1,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9d","card_x25519_pub_hex":"0000000000000000000000000000000000000000000000000000000000000000","vectors":[{"name":"x","sealed_hex":"` + strings.Repeat("00", 48) + `","shared_hex":"` + strings.Repeat("00", 32) + `","plaintext_hex":"ZZ"}]}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			path := writeTempFixture(t, []byte(c.body))
			_, err := LoadGoldenFixture(path)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestLoadGoldenFixture_RejectsTrailingGarbage(t *testing.T) {
	t.Parallel()
	// Two complete JSON objects in one file. json.Unmarshal in the
	// presence pass refuses extra content with "invalid character …
	// after top-level value"; the typed decoder pass catches it via
	// the explicit io.EOF check. Either layer suffices — any error
	// is acceptable here, what matters is the second object cannot
	// silently sneak in.
	body := []byte(`{"version":1,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9d","card_x25519_pub_hex":"0000000000000000000000000000000000000000000000000000000000000000","vectors":[]} {"second":"object"}`)
	path := writeTempFixture(t, body)
	_, err := LoadGoldenFixture(path)
	if err == nil {
		t.Fatalf("expected error on trailing JSON, got nil")
	}
}

func TestLoadGoldenFixture_RejectsMissingTopLevelField(t *testing.T) {
	t.Parallel()
	cases := []string{"version", "recorded_at", "firmware", "slot", "card_x25519_pub_hex", "vectors"}
	full := map[string]any{
		"version":             1,
		"recorded_at":         "0001-01-01T00:00:00Z",
		"firmware":            "x",
		"slot":                "9d",
		"card_x25519_pub_hex": strings.Repeat("00", 32),
		"vectors":             []any{},
	}
	for _, missing := range cases {
		t.Run("missing_"+missing, func(t *testing.T) {
			t.Parallel()
			m := make(map[string]any, len(full))
			for k, v := range full {
				if k != missing {
					m[k] = v
				}
			}
			body, _ := json.Marshal(m)
			path := writeTempFixture(t, body)
			_, err := LoadGoldenFixture(path)
			if err == nil {
				t.Fatalf("expected error when %q is missing, got nil", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Fatalf("error should name %q, got: %v", missing, err)
			}
		})
	}
}

func TestLoadGoldenFixture_RejectsMissingVectorField(t *testing.T) {
	t.Parallel()
	cases := []string{"name", "sealed_hex", "shared_hex", "plaintext_hex"}
	fullVec := map[string]any{
		"name":          "x",
		"sealed_hex":    strings.Repeat("00", 48),
		"shared_hex":    strings.Repeat("00", 32),
		"plaintext_hex": "",
	}
	base := map[string]any{
		"version":             1,
		"recorded_at":         "0001-01-01T00:00:00Z",
		"firmware":            "x",
		"slot":                "9d",
		"card_x25519_pub_hex": strings.Repeat("00", 32),
	}
	for _, missing := range cases {
		t.Run("missing_"+missing, func(t *testing.T) {
			t.Parallel()
			vec := make(map[string]any, len(fullVec))
			for k, v := range fullVec {
				if k != missing {
					vec[k] = v
				}
			}
			full := map[string]any{}
			for k, v := range base {
				full[k] = v
			}
			full["vectors"] = []any{vec}
			body, _ := json.Marshal(full)
			path := writeTempFixture(t, body)
			_, err := LoadGoldenFixture(path)
			if err == nil {
				t.Fatalf("expected error when vector is missing %q, got nil", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Fatalf("error should name %q, got: %v", missing, err)
			}
		})
	}
}

func TestLoadGoldenFixture_RejectsBadSlot(t *testing.T) {
	t.Parallel()
	body := []byte(`{"version":1,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9c","card_x25519_pub_hex":"0000000000000000000000000000000000000000000000000000000000000000","vectors":[]}`)
	path := writeTempFixture(t, body)
	_, err := LoadGoldenFixture(path)
	if err == nil {
		t.Fatalf("expected error on slot=9c, got nil")
	}
	if !strings.Contains(err.Error(), "slot") {
		t.Fatalf("error should mention slot, got: %v", err)
	}
}

func TestLoadGoldenFixture_TolerantToBOM(t *testing.T) {
	t.Parallel()
	body := []byte(`{"version":1,"recorded_at":"0001-01-01T00:00:00Z","firmware":"x","slot":"9d","card_x25519_pub_hex":"0000000000000000000000000000000000000000000000000000000000000000","vectors":[]}`)
	body = append([]byte{0xEF, 0xBB, 0xBF}, body...)
	path := writeTempFixture(t, body)
	if _, err := LoadGoldenFixture(path); err != nil {
		t.Fatalf("BOM should be silently stripped, got %v", err)
	}
}

func TestLoadGoldenFixture_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := LoadGoldenFixture(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatalf("expected error for missing file, got nil")
	}
}

// ---- helpers ----

func writeTempFixture(t *testing.T, body []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func isAllZero32(b [32]byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}

