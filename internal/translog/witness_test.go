package translog

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func mkSTHForTest(t *testing.T, serverPriv ed25519.PrivateKey, chainID string, size uint64) STH {
	t.Helper()
	root := EmptyRoot()
	if size > 0 {
		// For non-empty trees we just need a valid-looking 32-byte root.
		// The cosign verification only checks structural validity, not
		// that the root corresponds to a real tree (that's the server's
		// problem, verified by the storage layer).
		root = make([]byte, HashSize)
		for i := range root {
			root[i] = byte(i + int(size))
		}
	}
	head := TreeHead{ChainID: chainID, TreeSize: size, RootHash: root, Timestamp: 1}
	sth, err := SignSTH(serverPriv, head)
	if err != nil {
		t.Fatal(err)
	}
	return sth
}

func TestWitnessCosignRoundtrip(t *testing.T) {
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessPub, witnessPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	w, err := SignWitnessedSTH(witnessPriv, sth, "https://server.example")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyWitnessedSTH(serverPub, witnessPub, "https://server.example", "scope:s_test", w); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestWitnessCosignRejectsServerURLMismatch(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	w, _ := SignWitnessedSTH(witnessPriv, sth, "https://server-A.example")

	// Cosign for server A presented as cosign for server B → rejected.
	if err := VerifyWitnessedSTH(serverPub, witnessPub, "https://server-B.example", "scope:s_test", w); err == nil {
		t.Fatal("cosign for server A must not validate against server B")
	}
}

func TestWitnessCosignRejectsTamperedSTH(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	w, _ := SignWitnessedSTH(witnessPriv, sth, "https://server.example")

	// Flip a byte in the embedded STH's root_hash. Cosign is over
	// (sth, server_url) so any change to the STH invalidates it.
	w.STH.Head.RootHash = append([]byte(nil), w.STH.Head.RootHash...)
	w.STH.Head.RootHash[0] ^= 0x01
	if err := VerifyWitnessedSTH(serverPub, witnessPub, "https://server.example", "scope:s_test", w); err == nil {
		t.Fatal("tampered embedded STH must invalidate cosign")
	}
}

func TestWitnessCosignRejectsTamperedSig(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	w, _ := SignWitnessedSTH(witnessPriv, sth, "https://server.example")

	w.WitnessSig = append([]byte(nil), w.WitnessSig...)
	w.WitnessSig[0] ^= 0x01
	if err := VerifyWitnessedSTH(serverPub, witnessPub, "https://server.example", "scope:s_test", w); err == nil {
		t.Fatal("tampered witness sig must be rejected")
	}
}

func TestWitnessCosignRejectsWrongWitnessPin(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	w, _ := SignWitnessedSTH(witnessPriv, sth, "https://server.example")

	// Verifier pins a DIFFERENT witness pub. Embedded pub == real
	// witness pub but the pin disagrees → rejected.
	if err := VerifyWitnessedSTH(serverPub, otherPub, "https://server.example", "scope:s_test", w); err == nil {
		t.Fatal("cosign verified under wrong pinned witness pub")
	}
}

func TestWitnessCosignRejectsWrongServerPin(t *testing.T) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherServerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	w, _ := SignWitnessedSTH(witnessPriv, sth, "https://server.example")

	// Verifier pins a DIFFERENT server pub. The witness cosign is
	// fine, but the embedded STH must verify under the SERVER's pub
	// — and it doesn't.
	if err := VerifyWitnessedSTH(otherServerPub, witnessPub, "https://server.example", "scope:s_test", w); err == nil {
		t.Fatal("cosign with valid witness sig but wrong server pub must be rejected")
	}
}

func TestWitnessCosignRejectsTamperedEmbeddedPub(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	w, _ := SignWitnessedSTH(witnessPriv, sth, "https://server.example")

	// Embedded pub gets swapped to something other than the pinned
	// pub. Even if signature would still verify against the pin,
	// later code reading w.WitnessPub would be misled, so we reject.
	w.WitnessPub = append([]byte(nil), otherPub...)
	if err := VerifyWitnessedSTH(serverPub, witnessPub, "https://server.example", "scope:s_test", w); err == nil {
		t.Fatal("WitnessPub field tampering must be rejected")
	}
}

func TestWitnessCosignRejectsChainIDMismatch(t *testing.T) {
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_real", 5)
	w, _ := SignWitnessedSTH(witnessPriv, sth, "https://server.example")
	// Verifier expects a DIFFERENT chain. The cosign is otherwise
	// valid; without the chain check (codex fix #4) it would be
	// accepted as confirmation for the wrong chain.
	if err := VerifyWitnessedSTH(serverPub, witnessPub, "https://server.example", "scope:s_other", w); err == nil {
		t.Fatal("cosign for chain X must not validate against chain Y")
	}
}

func TestWitnessCosignRejectsEmptyChainID(t *testing.T) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	w, _ := SignWitnessedSTH(witnessPriv, sth, "https://server.example")
	if err := VerifyWitnessedSTH(witnessPub, witnessPub, "https://server.example", "", w); err == nil {
		t.Fatal("empty expectedChainID must be rejected")
	}
}

func TestWitnessCosignRejectsEmptyServerURL(t *testing.T) {
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	sth := mkSTHForTest(t, serverPriv, "scope:s_test", 5)
	if _, err := SignWitnessedSTH(witnessPriv, sth, ""); err == nil {
		t.Fatal("signing with empty serverURL must fail")
	}
}
