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
		Scope:  ScopePtr("s_test"),
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
	if asStr != "s_test" {
		t.Fatalf("expected scope_id 's_test', got %q", asStr)
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
	id := ScopeID("e_abc123")
	if !bytes.HasPrefix([]byte(id), []byte("s_")) {
		t.Fatalf("ScopeID missing prefix: %s", id)
	}
	if id == ScopeID("e_other") {
		t.Fatal("ScopeID collision")
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
	a, err := HTTPSignedInput("POST", "/sync", q, 1700000000, []byte{1, 2, 3, 4}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	// Re-issue with map keys in opposite insertion order.
	q2 := map[string]string{"a": "1", "b": "2"}
	b, err := HTTPSignedInput("POST", "/sync", q2, 1700000000, []byte{1, 2, 3, 4}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("HTTPSignedInput is not key-order stable")
	}
	// Method-case matters: lowercase should be normalised to uppercase.
	c, err := HTTPSignedInput("post", "/sync", q, 1700000000, []byte{1, 2, 3, 4}, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, c) {
		t.Fatal("HTTP method case-folding inconsistent")
	}
}

func TestHTTPSignedInputBodyHash(t *testing.T) {
	a, _ := HTTPSignedInput("GET", "/x", nil, 1, []byte{}, []byte("hello"))
	b, _ := HTTPSignedInput("GET", "/x", nil, 1, []byte{}, []byte("hellp"))
	if bytes.Equal(a, b) {
		t.Fatal("body change must change signed input")
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
