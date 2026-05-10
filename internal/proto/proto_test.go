package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// ----- CBOR determinism + roundtrip -----

func TestMarshalDeterministic(t *testing.T) {
	// Same value → byte-identical output, every call.
	v := UserEvent{
		Kind:         KindAuthSet,
		Seq:          5,
		PrevHash:     bytes.Repeat([]byte{0xab}, 32),
		UserSuperPub: bytes.Repeat([]byte{0x01}, 32),
		Payload: AuthSetPayload{Active: []AuthMethod{
			{MethodID: "am_b", MethodType: AuthPassphrase, PublicParams: []byte{1, 2, 3}},
			{MethodID: "am_a", MethodType: AuthYubikey, PublicParams: []byte{4, 5}},
		}},
		Signature: bytes.Repeat([]byte{0xff}, 64),
	}
	a, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("non-deterministic encoding: a=%x b=%x", a, b)
	}
}

func TestUserEventRoundtrip(t *testing.T) {
	in := UserEvent{
		Kind: KindAuthSet, Seq: 42, PrevHash: bytes.Repeat([]byte{0x55}, 32),
		UserSuperPub: bytes.Repeat([]byte{0xaa}, 32),
		Payload: AuthSetPayload{Active: []AuthMethod{{
			MethodID: "am_x", MethodType: AuthPassphrase,
			PublicParams: []byte{1}, EncryptedSuperPriv: []byte{2, 3},
		}}},
		Signature: bytes.Repeat([]byte{0x77}, 64),
	}
	b, err := Marshal(&in)
	if err != nil {
		t.Fatal(err)
	}
	var out UserEvent
	if err := Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	b2, err := Marshal(&out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatal("re-encode of decoded value is not byte-stable")
	}
}

func TestScopeEventScopePtrEncoding(t *testing.T) {
	// Genesis: Scope must encode as CBOR null. Decode into a generic map
	// and inspect the raw `scope` value byte to assert.
	genesis := SignedPrefix{
		Kind:   KindMemberChange,
		Scope:  nil,
		Author: bytes.Repeat([]byte{1}, 32),
	}
	b, err := Marshal(genesis)
	if err != nil {
		t.Fatal(err)
	}
	var asMap map[string]cborRaw
	if err := Unmarshal(b, &asMap); err != nil {
		t.Fatal(err)
	}
	got, ok := asMap["scope"]
	if !ok {
		t.Fatal("scope key missing from genesis encoding")
	}
	if len(got) != 1 || got[0] != 0xf6 {
		t.Fatalf("genesis scope must be CBOR null (0xf6), got %x", got)
	}

	successor := SignedPrefix{
		Kind:   KindSecretSet,
		Scope:  ScopePtr(MustParseScopeID("s_aaaaaaaaaaaaaaaaaaaaaaaaaa")),
		Author: bytes.Repeat([]byte{1}, 32),
	}
	b2, err := Marshal(successor)
	if err != nil {
		t.Fatal(err)
	}
	var asMap2 map[string]cborRaw
	if err := Unmarshal(b2, &asMap2); err != nil {
		t.Fatal(err)
	}
	got2, ok := asMap2["scope"]
	if !ok {
		t.Fatal("scope key missing from successor encoding")
	}
	if len(got2) > 0 && got2[0] == 0xf6 {
		t.Fatal("successor scope must not encode as null")
	}
	// Re-decode the raw bytes as a string to confirm content.
	var asStr string
	if err := Unmarshal(got2, &asStr); err != nil {
		t.Fatal(err)
	}
	if asStr != "s_aaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("expected scope_id 's_aaaaaaaaaaaaaaaaaaaaaaaaaa', got %q", asStr)
	}
}

// cborRaw is a thin alias matching cbor.RawMessage so we can inspect the
// wire form without depending on a specific decoder shape.
type cborRaw []byte

func (r *cborRaw) UnmarshalCBOR(data []byte) error {
	*r = append((*r)[:0], data...)
	return nil
}

// ----- EventID stability -----

func TestEventIDStable(t *testing.T) {
	prefix := []byte("any prefix bytes here")
	id1 := EventID(prefix)
	id2 := EventID(prefix)
	if id1 != id2 {
		t.Fatalf("EventID not deterministic: %s vs %s", id1, id2)
	}
	if !bytes.HasPrefix([]byte(id1), []byte("e_")) {
		t.Fatalf("EventID missing 'e_' prefix: %s", id1)
	}
	if len(id1) < 10 {
		t.Fatalf("EventID too short: %s", id1)
	}
	// Different input → different ID.
	if EventID([]byte("other")) == id1 {
		t.Fatal("collision on trivially-different input")
	}
}

func TestScopeIDDerivation(t *testing.T) {
	id := DeriveScopeID("e_abc123")
	if !bytes.HasPrefix([]byte(id.String()), []byte("s_")) {
		t.Fatalf("DeriveScopeID missing prefix: %s", id)
	}
	if id == DeriveScopeID("e_other") {
		t.Fatal("DeriveScopeID collision")
	}
}

// ----- Hash chain linkage -----

func TestHashPrefixDeterministic(t *testing.T) {
	in := []byte("event prefix")
	h1 := HashPrefix(in)
	h2 := HashPrefix(in)
	if h1 != h2 {
		t.Fatal("HashPrefix not deterministic")
	}
	// Different input → different hash.
	if HashPrefix([]byte("other")) == h1 {
		t.Fatal("HashPrefix trivial collision")
	}
}

// ----- Domain separator disjunction -----

func TestDomainSeparatorsDisjoint(t *testing.T) {
	// PROTOCOL.md §1.1: every two domain separators must be (a) distinct and
	// (b) neither a prefix of the other. Pairwise check across all of them.
	all := []string{
		DomainEvent,
		DomainUserEvent,
		DomainCard,
		DomainHTTP,
		DomainEncryptedSuperPriv,
		DomainVaultBody,
		DomainVaultWrap,
		DomainRecoveryKey,
		DomainSafety,
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			a, b := all[i], all[j]
			if a == b {
				t.Fatalf("duplicate domain separator: %q", a)
			}
			if bytes.HasPrefix([]byte(a), []byte(b)) || bytes.HasPrefix([]byte(b), []byte(a)) {
				t.Fatalf("domain prefix collision: %q vs %q", a, b)
			}
		}
	}
}

// ----- HTTPSignedInput stability -----

func TestHTTPSignedInputStable(t *testing.T) {
	q := map[string]string{"b": "2", "a": "1"}
	srvPub := bytes.Repeat([]byte{0xAB}, 32)
	a, err := HTTPSignedInput("POST", "/sync", q, 1700000000, []byte{1, 2, 3, 4}, []byte("body"), srvPub)
	if err != nil {
		t.Fatal(err)
	}
	q2 := map[string]string{"a": "1", "b": "2"}
	b, err := HTTPSignedInput("POST", "/sync", q2, 1700000000, []byte{1, 2, 3, 4}, []byte("body"), srvPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("HTTPSignedInput is not key-order stable")
	}
	c, err := HTTPSignedInput("post", "/sync", q, 1700000000, []byte{1, 2, 3, 4}, []byte("body"), srvPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, c) {
		t.Fatal("HTTP method case-folding inconsistent")
	}
}

func TestHTTPSignedInputBodyHash(t *testing.T) {
	srvPub := bytes.Repeat([]byte{0xCD}, 32)
	a, _ := HTTPSignedInput("GET", "/x", nil, 1, []byte{}, []byte("hello"), srvPub)
	b, _ := HTTPSignedInput("GET", "/x", nil, 1, []byte{}, []byte("hellp"), srvPub)
	if bytes.Equal(a, b) {
		t.Fatal("body change must change signed input")
	}
}

// TestHTTPSignedInputServerPubBinding locks the codex 🔴 fix:
// changing server_pub MUST yield a different signed input so a
// signature for server-A cannot be replayed against server-B.
func TestHTTPSignedInputServerPubBinding(t *testing.T) {
	pubA := bytes.Repeat([]byte{0x01}, 32)
	pubB := bytes.Repeat([]byte{0x02}, 32)
	a, _ := HTTPSignedInput("POST", "/sync", nil, 1700000000, []byte{1}, []byte("body"), pubA)
	b, _ := HTTPSignedInput("POST", "/sync", nil, 1700000000, []byte{1}, []byte("body"), pubB)
	if bytes.Equal(a, b) {
		t.Fatal("server_pub binding broken — same signed input across servers")
	}
}

// ----- VaultBody backwards/forwards compatibility -----

// TestScopeVaultDataPushFloorRoundtrip verifies the new field roundtrips
// with the rest of the struct when set explicitly.
func TestScopeVaultDataPushFloorRoundtrip(t *testing.T) {
	in := ScopeVaultData{
		Label:     "work",
		OEKs:      []OEKEntry{{Version: 1, Key: bytes.Repeat([]byte{0xaa}, 32)}},
		ChainTip:  ChainTip{Seq: 5, Hash: bytes.Repeat([]byte{0xbb}, 32)},
		PushFloor: 6,
	}
	b, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out ScopeVaultData
	if err := Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.PushFloor != 6 {
		t.Fatalf("PushFloor not preserved: got %d, want 6", out.PushFloor)
	}
}

// TestScopeVaultDataPushFloorDefaultsToZero ensures decode of a vault
// produced by an OLDER fd0 (no push_floor key) yields PushFloor=0,
// which is the safe "push everything" sentinel — server idempotent dedup
// makes a one-time full re-push harmless on upgrade.
//
// We construct an explicit legacy fixture: a struct shape WITHOUT the
// PushFloor field, marshal it to CBOR (so the on-wire bytes are exactly
// what an older fd0 would have written), then decode into the current
// ScopeVaultData and verify the missing key defaults to zero.
func TestScopeVaultDataPushFloorDefaultsToZero(t *testing.T) {
	// Pre-PushFloor on-disk shape — no push_floor key emitted.
	type legacyScopeVaultData struct {
		Label    string     `cbor:"label,omitempty"`
		OEKs     []OEKEntry `cbor:"oeks"`
		ChainTip ChainTip   `cbor:"chain_tip"`
	}
	legacy := legacyScopeVaultData{
		Label:    "work",
		OEKs:     []OEKEntry{{Version: 1, Key: bytes.Repeat([]byte{0x11}, 32)}},
		ChainTip: ChainTip{Seq: 7, Hash: bytes.Repeat([]byte{0x22}, 32)},
	}
	wire, err := Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the encoded bytes must NOT contain the literal key
	// "push_floor" — we are simulating a producer that doesn't know
	// about the field.
	if bytes.Contains(wire, []byte("push_floor")) {
		t.Fatal("legacy fixture unexpectedly contains push_floor key")
	}
	var out ScopeVaultData
	if err := Unmarshal(wire, &out); err != nil {
		t.Fatalf("decode legacy shape into current struct: %v", err)
	}
	if out.PushFloor != 0 {
		t.Fatalf("PushFloor must default to 0 when absent, got %d", out.PushFloor)
	}
	if out.Label != "work" || out.ChainTip.Seq != 7 {
		t.Fatal("other fields must be preserved across legacy→current decode")
	}
	if len(out.OEKs) != 1 || out.OEKs[0].Version != 1 {
		t.Fatal("OEKs must round-trip from legacy shape")
	}
}

// TestYubikeyPublicParamsForwardCompat: a future v2 may add fields
// (e.g. firmware string, pin_policy hint, touch_policy hint). The
// CBOR decoder MUST silently ignore unknown keys so a v1 reader
// loading a v2-shaped wrap still succeeds, with the known fields
// intact. Pin this so a future strict-decoder change can't break
// rolling deployments.
//
// We synthesise a v2 shape via map[string]any → Marshal → decode
// into v1 YubikeyPublicParams. Known fields must round-trip;
// unknown fields must be silently dropped without an error.
func TestYubikeyPublicParamsForwardCompat(t *testing.T) {
	v2 := map[string]any{
		"x25519_pub":      bytes.Repeat([]byte{0x55}, 32),
		"sealed_k_unlock": bytes.Repeat([]byte{0x66}, 80),
		"slot":            uint8(0x9d),
		// Hypothetical v2 additions:
		"firmware":        "5.7.4",
		"pin_policy_hint": "once",
		"touch_policy":    "never",
	}
	b, err := Marshal(v2)
	if err != nil {
		t.Fatalf("marshal v2: %v", err)
	}
	var out YubikeyPublicParams
	if err := Unmarshal(b, &out); err != nil {
		t.Fatalf("v1 decoder rejected v2 shape: %v (this would block rolling deployment)", err)
	}
	if !bytes.Equal(out.X25519Pub, bytes.Repeat([]byte{0x55}, 32)) {
		t.Fatalf("X25519Pub did not round-trip from v2 shape: %x", out.X25519Pub)
	}
	if !bytes.Equal(out.SealedKUnlock, bytes.Repeat([]byte{0x66}, 80)) {
		t.Fatalf("SealedKUnlock did not round-trip from v2 shape")
	}
	if out.Slot != 0x9d {
		t.Fatalf("Slot did not round-trip from v2 shape: 0x%02x", out.Slot)
	}
}

// TestYubikeyPublicParamsRoundtrip exercises the new struct used by the
// `auth add --yubikey` flow.
func TestYubikeyPublicParamsRoundtrip(t *testing.T) {
	in := YubikeyPublicParams{
		X25519Pub:     bytes.Repeat([]byte{0x33}, 32),
		SealedKUnlock: bytes.Repeat([]byte{0x44}, 80),
		Slot:          0x9d,
	}
	b, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out YubikeyPublicParams
	if err := Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in.X25519Pub, out.X25519Pub) ||
		!bytes.Equal(in.SealedKUnlock, out.SealedKUnlock) ||
		in.Slot != out.Slot {
		t.Fatal("YubikeyPublicParams roundtrip mismatch")
	}
}

// ----- Sanity: signed-input domain prefix is preserved -----

func TestUserEventSignedInputHasDomain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ev := UserEvent{
		Kind: KindAuthSet, Seq: 0,
		UserSuperPub: pub,
		Payload: AuthSetPayload{Active: []AuthMethod{{
			MethodID: "x", MethodType: AuthPassphrase, PublicParams: []byte{}, EncryptedSuperPriv: []byte{},
		}}},
		Signature: bytes.Repeat([]byte{0}, 64),
	}
	si, err := ev.SignedInput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(si, []byte(DomainUserEvent)) {
		t.Fatal("UserEvent signed input must start with DomainUserEvent")
	}
	_ = priv
}

func TestScopeEventSignedInputHasDomain(t *testing.T) {
	ev := ScopeEvent{
		SignedPrefix: SignedPrefix{
			Kind: KindMemberChange, Author: bytes.Repeat([]byte{1}, 32),
		},
	}
	si, err := ev.SignedInput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(si, []byte(DomainEvent)) {
		t.Fatal("ScopeEvent signed input must start with DomainEvent")
	}
}

func TestIdentityCardSignedInputHasDomain(t *testing.T) {
	c := IdentityCard{Version: 1, ShortID: "x", SuperPub: bytes.Repeat([]byte{1}, 32), IssuedAt: 1, ExpiresAt: 2}
	si, err := c.SignedInput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(si, []byte(DomainCard)) {
		t.Fatal("Card signed input must start with DomainCard")
	}
}
