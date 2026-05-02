package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Golden-byte tests for the canonical CBOR encoding of every
// fd0 wire type that contributes to a SIGNED INPUT or to
// content-addressed event IDs. The bytes are pinned by SHA-256
// hash. If a future Go version, fxamacker/cbor version, or refactor
// silently changes the encoding, these tests fail BEFORE the
// change ships → before any user's signature breaks.
//
// To regenerate (only when the wire format INTENTIONALLY changes
// — and you're prepared to break every existing signature):
//
//	go test ./internal/proto/ -run TestGolden -v 2>&1 | tee golden.out
//	# read the printed actual hashes, paste into the wantHex constants.

// goldenCheck marshals v and asserts SHA-256(bytes) matches wantHex.
func goldenCheck(t *testing.T, name string, v any, wantHex string) {
	t.Helper()
	b, err := Marshal(v)
	if err != nil {
		t.Fatalf("%s: Marshal: %v", name, err)
	}
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if got != wantHex {
		t.Errorf("%s: golden encoding drift\n  want SHA-256: %s\n  got  SHA-256: %s\n  bytes:        %x",
			name, wantHex, got, b)
	}
}

// TestGoldenAuthMethod pins the encoding of the AuthMethod struct
// that appears inside auth.set events. A drift here invalidates
// every existing user chain's signature.
func TestGoldenAuthMethod(t *testing.T) {
	v := AuthMethod{
		MethodID:           "am_x",
		MethodType:         AuthPassphrase,
		PublicParams:       []byte{0x01, 0x02, 0x03, 0x04},
		EncryptedSuperPriv: []byte{0xff},
	}
	goldenCheck(t, "AuthMethod", v,
		"275daaad23ed9ef9c3b3b4bf1b8e1132564f5ee7ef47f506c9de305d4778eef2")
}

// TestGoldenSignedPrefixSecretSet pins the canonical encoding of a
// scope-event SignedPrefix for a secret.set. SignedPrefix encoding
// drives both event_id (content-addressed) AND the SignedInput for
// the Ed25519 signature — drift breaks both.
func TestGoldenSignedPrefixSecretSet(t *testing.T) {
	scope := "s_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	v := SignedPrefix{
		Kind:       KindSecretSet,
		Scope:      &scope,
		PrevHash:   []byte{0xAB, 0xAB, 0xAB},
		Author:     []byte{0xCD, 0xCD, 0xCD, 0xCD},
		Seq:        7,
		OEKVersion: 3,
		Payload: Payload{
			EncBody: []byte{0x42, 0x43},
		},
	}
	goldenCheck(t, "SignedPrefix(secret.set)", v,
		"e6bbd6995c1a401a5e85364afa44dffa80747fc80411456ef4d74bf3d5949980")
}

// TestGoldenIdentityCardSigned pins the IdentityCard signed-input
// encoding (excluding signature). Drift orphans every user's card
// pin.
func TestGoldenIdentityCardSigned(t *testing.T) {
	c := IdentityCard{
		Version:   1,
		ShortID:   "abcdefgh",
		SuperPub:  []byte{0xAA, 0xBB, 0xCC, 0xDD},
		IssuedAt:  1700000000,
		ExpiresAt: 1700864000,
	}
	si, err := c.SignedInput()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(si)
	got := hex.EncodeToString(sum[:])
	const want = "564ed3fa8e847d81f6de255bf71acb7a45cf4eb0fbc43ea458ea69fc3db097b3"
	if got != want {
		t.Errorf("IdentityCard.SignedInput drift\n  want SHA-256: %s\n  got  SHA-256: %s",
			want, got)
	}
}

// TestGoldenDomainConstants pins the literal domain separator
// strings. Any change here breaks every signature in every fd0
// vault and chain in existence.
func TestGoldenDomainConstants(t *testing.T) {
	pins := map[string]string{
		"DomainEvent":              "fd0-event-v1",
		"DomainUserEvent":          "fd0-user-event-v1",
		"DomainCard":               "fd0-card-v1",
		"DomainHTTP":               "fd0-http-request-v1",
		"DomainEncryptedSuperPriv": "fd0-encrypted-super-priv-v1",
		"DomainVaultBody":          "fd0-vault-body-v1",
		"DomainVaultWrap":          "fd0-vault-wrap-v1",
		"DomainRecoveryKey":        "fd0-recovery-key-v1",
		"DomainSafety":             "fd0-safety-v1",
		"DomainTranslogLeaf":       "fd0-translog-leaf-v1",
		"DomainTranslogNode":       "fd0-translog-node-v1",
		"DomainTranslogEmpty":      "fd0-translog-empty-v1",
		"DomainTranslogSTH":        "fd0-translog-sth-v1",
		"DomainTranslogServerInfo": "fd0-translog-server-info-v1",
		"DomainServerFingerprint":  "fd0-server-fingerprint-v1",
		"DomainWitnessCosign":      "fd0-witness-cosign-v1",
	}
	got := map[string]string{
		"DomainEvent":              DomainEvent,
		"DomainUserEvent":          DomainUserEvent,
		"DomainCard":               DomainCard,
		"DomainHTTP":               DomainHTTP,
		"DomainEncryptedSuperPriv": DomainEncryptedSuperPriv,
		"DomainVaultBody":          DomainVaultBody,
		"DomainVaultWrap":          DomainVaultWrap,
		"DomainRecoveryKey":        DomainRecoveryKey,
		"DomainSafety":             DomainSafety,
		"DomainTranslogLeaf":       DomainTranslogLeaf,
		"DomainTranslogNode":       DomainTranslogNode,
		"DomainTranslogEmpty":      DomainTranslogEmpty,
		"DomainTranslogSTH":        DomainTranslogSTH,
		"DomainTranslogServerInfo": DomainTranslogServerInfo,
		"DomainServerFingerprint":  DomainServerFingerprint,
		"DomainWitnessCosign":      DomainWitnessCosign,
	}
	for k, want := range pins {
		if got[k] != want {
			t.Errorf("%s drift: want %q, got %q (every signature using this domain is now invalid)",
				k, want, got[k])
		}
	}
}
