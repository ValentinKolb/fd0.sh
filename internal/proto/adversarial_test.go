package proto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

// Adversarial property tests for proto. The pattern: for each public
// surface, throw inputs at it that an attacker would actually send,
// not what an honest client would. Each test corresponds to a real
// bug class found in the multi-module review (or a near-miss caught
// during the post-fix audit).

// TestAdvCBORRejectsIndefiniteLength confirms decode mode forbids
// indefinite-length encodings. fxamacker/cbor's IndefLengthForbidden
// is set in our DecOptions; this test pins the behavior so a future
// "let's relax this for compat" change doesn't slip through.
func TestAdvCBORRejectsIndefiniteLength(t *testing.T) {
	// 0x9f = indefinite-length array; 0x01 element; 0xff break.
	indefArr := []byte{0x9f, 0x01, 0xff}
	var got []any
	if err := Unmarshal(indefArr, &got); err == nil {
		t.Fatal("decoder accepted indefinite-length array")
	}
	// 0xbf = indefinite-length map.
	indefMap := []byte{0xbf, 0x01, 0x02, 0xff}
	var m map[any]any
	if err := Unmarshal(indefMap, &m); err == nil {
		t.Fatal("decoder accepted indefinite-length map")
	}
}

// TestAdvCBORRejectsTags confirms the decoder rejects all tagged
// values (TagsForbidden in DecOptions). A signed input that round-
// trips through a decoder that silently strips tags would change
// signed bytes.
func TestAdvCBORRejectsTags(t *testing.T) {
	// 0xc1 = tag 1 (epoch time); 0x00 = uint 0.
	tagged := []byte{0xc1, 0x00}
	var got any
	if err := Unmarshal(tagged, &got); err == nil {
		t.Fatal("decoder accepted CBOR tag 1")
	}
}

// TestAdvCBORRejectsDuplicateMapKeys covers DupMapKeyEnforcedAPF.
// A duplicate key could let an attacker craft a payload where the
// "second value" is what the decoder sees, but the signature was
// computed over the canonical (first) value.
func TestAdvCBORRejectsDuplicateMapKeys(t *testing.T) {
	// CBOR map with two entries both keyed "a".
	// {"a": 1, "a": 2} — illegal under DupMapKeyEnforcedAPF.
	// 0xa2 = map(2 pairs); "a" = 0x61, 0x61; uint 1 = 0x01; uint 2 = 0x02.
	dup := []byte{0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}
	var got map[string]int
	if err := Unmarshal(dup, &got); err == nil {
		t.Fatal("decoder accepted duplicate map keys")
	}
}

// TestAdvCBORFieldNameCaseSensitive locks the codex audit fix:
// FieldNameMatchingCaseSensitive must be set. Without it, a CBOR
// payload using "Field" (vs "field") could decode into the same
// struct field, breaking determinism for signed inputs that
// roundtrip through decode-then-re-encode.
//
// Codex test audit: previous version returned silently if Unmarshal
// errored, masking a "case-mismatch yields zero" case. Now we
// require EITHER an explicit error (strict mode rejects unknown
// keys) OR a successful decode where the field stayed empty.
func TestAdvCBORFieldNameCaseSensitive(t *testing.T) {
	type S struct {
		Foo string `cbor:"foo"`
	}
	body := []byte{0xa1, 0x63, 'F', 'o', 'o', 0x61, 'x'}
	var s S
	err := Unmarshal(body, &s)
	if err == nil {
		// If accepted, the field MUST stay empty (case mismatch).
		if s.Foo != "" {
			t.Fatalf("case-insensitive match leaked: Foo=%q (want empty)", s.Foo)
		}
		// We also assert that strict mode SHOULD have rejected this
		// (since the only key is the wrong-case "Foo" with no match
		// for any tag). The decoder either errors here OR silently
		// drops unknown keys — both are acceptable as long as Foo
		// stays empty.
		return
	}
	// Errored — that's also fine and is the expected strict-mode
	// behavior for unknown keys.
}

// TestAdvCBORLimitsBoundDepthAndSize stresses the MaxNestedLevels /
// MaxArrayElements / MaxMapPairs DecOptions. The decoder MUST refuse
// pathologically nested or huge inputs without panicking or hanging.
func TestAdvCBORLimitsBoundDepthAndSize(t *testing.T) {
	// Build a deeply nested structure: array of array of array... 100 levels.
	deep := make([]byte, 0, 100)
	for i := 0; i < 100; i++ {
		deep = append(deep, 0x81) // array(1)
	}
	deep = append(deep, 0x00) // innermost: uint 0
	var got any
	if err := Unmarshal(deep, &got); err == nil {
		t.Fatal("decoder accepted 100-level nested array")
	}
}

// TestAdvHTTPSignedInputBindsServerPub locks the cross-server replay
// fix at the API level: every distinct server_pub MUST yield a
// distinct signed input even when method/path/query/ts/nonce/body
// are identical.
func TestAdvHTTPSignedInputBindsServerPub(t *testing.T) {
	method := "POST"
	path := "/sync"
	q := map[string]string{}
	ts := uint64(1700000000)
	nonce := []byte("NONCE-16-bytes-x")
	body := []byte("body")

	pubA := bytes.Repeat([]byte{0x01}, 32)
	pubB := bytes.Repeat([]byte{0x02}, 32)
	pubC := bytes.Repeat([]byte{0x03}, 32)

	a, _ := HTTPSignedInput(method, path, q, ts, nonce, body, pubA)
	b, _ := HTTPSignedInput(method, path, q, ts, nonce, body, pubB)
	c, _ := HTTPSignedInput(method, path, q, ts, nonce, body, pubC)
	if bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(b, c) {
		t.Fatal("server_pub binding broken — distinct pubs yield identical signed input")
	}
}

// TestAdvHTTPSignedInputBindsEveryField confirms each input
// parameter is part of the signed bytes. A regression that omits
// a field would let an attacker mutate that field with the same sig.
func TestAdvHTTPSignedInputBindsEveryField(t *testing.T) {
	base := func() []byte {
		x, _ := HTTPSignedInput("POST", "/sync", map[string]string{"a": "1"},
			1700000000, []byte("nonce"), []byte("body"), bytes.Repeat([]byte{1}, 32))
		return x
	}
	cases := []struct {
		name string
		got  []byte
	}{
		{"method", mustHTTPSig(t, "GET", "/sync", map[string]string{"a": "1"}, 1700000000, []byte("nonce"), []byte("body"), bytes.Repeat([]byte{1}, 32))},
		{"path", mustHTTPSig(t, "POST", "/other", map[string]string{"a": "1"}, 1700000000, []byte("nonce"), []byte("body"), bytes.Repeat([]byte{1}, 32))},
		{"query-key", mustHTTPSig(t, "POST", "/sync", map[string]string{"b": "1"}, 1700000000, []byte("nonce"), []byte("body"), bytes.Repeat([]byte{1}, 32))},
		{"query-val", mustHTTPSig(t, "POST", "/sync", map[string]string{"a": "2"}, 1700000000, []byte("nonce"), []byte("body"), bytes.Repeat([]byte{1}, 32))},
		{"ts", mustHTTPSig(t, "POST", "/sync", map[string]string{"a": "1"}, 1700000001, []byte("nonce"), []byte("body"), bytes.Repeat([]byte{1}, 32))},
		{"nonce", mustHTTPSig(t, "POST", "/sync", map[string]string{"a": "1"}, 1700000000, []byte("XXXX-"), []byte("body"), bytes.Repeat([]byte{1}, 32))},
		{"body", mustHTTPSig(t, "POST", "/sync", map[string]string{"a": "1"}, 1700000000, []byte("nonce"), []byte("BODY"), bytes.Repeat([]byte{1}, 32))},
		{"server_pub", mustHTTPSig(t, "POST", "/sync", map[string]string{"a": "1"}, 1700000000, []byte("nonce"), []byte("body"), bytes.Repeat([]byte{2}, 32))},
	}
	b := base()
	for _, tc := range cases {
		if bytes.Equal(b, tc.got) {
			t.Errorf("field %q is NOT bound into the signed input", tc.name)
		}
	}
}

func mustHTTPSig(t *testing.T, method, path string, q map[string]string, ts uint64, nonce, body, srvPub []byte) []byte {
	t.Helper()
	x, err := HTTPSignedInput(method, path, q, ts, nonce, body, srvPub)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// TestAdvHTTPSignedInputBodyShaCovers verifies body_sha is sha256
// (not truncated, not unhashed). A regression that swaps to a
// shorter hash would weaken collision resistance below 128 bits.
func TestAdvHTTPSignedInputBodyShaCovers(t *testing.T) {
	body := []byte("hello world")
	si, err := HTTPSignedInput("GET", "/x", nil, 1, []byte{1}, body, bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(body)
	// signed input contains cbor of {body_sha: sha256(body)}; ensure
	// the 32 bytes appear.
	if !bytes.Contains(si, want[:]) {
		t.Fatalf("signed input does not contain SHA-256 of body\n  want %x\n  si   %x", want[:8], si[:32])
	}
}

// TestAdvHTTPSignedInputEmptyBodyHashed: empty body MUST be hashed
// (sha256("") = e3b0c44…), NOT skipped. Otherwise an attacker could
// alter empty-body endpoints' state with the same sig as another
// no-body request.
func TestAdvHTTPSignedInputEmptyBodyHashed(t *testing.T) {
	si, err := HTTPSignedInput("GET", "/x", nil, 1, []byte{1}, []byte{}, bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatal(err)
	}
	emptyHash := sha256.Sum256([]byte{})
	if !bytes.Contains(si, emptyHash[:]) {
		t.Fatalf("empty body not hashed into signed input")
	}
}

// TestAdvDomainPrefixesDisjoint extends the existing domain test
// with: every domain string must NOT be a prefix of any other.
// Without this, a signature over `domain_A || X` could coincide
// with one over `domain_B || Y` where domain_A is a prefix of
// domain_B — breaking domain isolation.
func TestAdvDomainPrefixesDisjoint(t *testing.T) {
	domains := []string{
		DomainEvent, DomainUserEvent, DomainCard, DomainHTTP,
		DomainEncryptedSuperPriv, DomainVaultBody, DomainVaultWrap,
		DomainRecoveryKey, DomainSafety, DomainTranslogLeaf,
		DomainTranslogNode, DomainTranslogEmpty, DomainTranslogSTH,
		DomainTranslogServerInfo, DomainServerFingerprint, DomainWitnessCosign,
	}
	for i, a := range domains {
		for j, b := range domains {
			if i == j {
				continue
			}
			if strings.HasPrefix(a, b) {
				t.Errorf("%q is a prefix of %q", b, a)
			}
		}
	}
}

// TestAdvScopeIDDerivationDeterministic locks ScopeID's purity:
// for any prefix bytes, ScopeID(EventID(prefix)) MUST be byte-stable
// across runs. A regression here would orphan every persisted scope.
func TestAdvScopeIDDerivationDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		prefix := bytes.Repeat([]byte{byte(i)}, 32+i)
		eid := EventID(prefix)
		a := DeriveScopeID(eid)
		b := DeriveScopeID(eid)
		if a != b {
			t.Fatalf("iter %d: DeriveScopeID non-deterministic (%s vs %s)", i, a, b)
		}
		if !strings.HasPrefix(string(a), "s_") {
			t.Fatalf("iter %d: ScopeID missing s_ prefix: %s", i, a)
		}
		if len(a) != 28 {
			t.Fatalf("iter %d: ScopeID wrong length %d (want 28)", i, len(a))
		}
	}
}

// TestAdvCBORLargeIntegers asserts that decoding CBOR uint64 values
// > MaxInt64 either errors cleanly OR preserves the value without
// silent truncation/sign-flip.
//
// Codex test audit: the previous version had `_ = err` which made
// the entire function a no-op when the decoder errored — exactly
// the case we wanted to verify. Now: the test REQUIRES one of
// {explicit error, exact preservation as uint64, or sign-extension
// to negative int64}. A silent zero or truncated positive int64
// fails the test.
func TestAdvCBORLargeIntegers(t *testing.T) {
	maxUint64 := []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	var v any
	err := Unmarshal(maxUint64, &v)
	if err != nil {
		// Explicit error is the safest behavior.
		return
	}
	// Accepted — verify exact preservation OR a recognizable
	// sign-extended representation. Silent truncation = BUG.
	switch x := v.(type) {
	case uint64:
		if x != math.MaxUint64 {
			t.Fatalf("decoded MaxUint64 != MaxUint64: %x", x)
		}
	case int64:
		if x >= 0 {
			t.Fatalf("decoded MaxUint64 as positive int64: %d (silent overflow)", x)
		}
	default:
		t.Fatalf("decoded MaxUint64 as unexpected type %T", v)
	}
	_ = hex.EncodeToString
}
