package translog

import (
	"bytes"
	"crypto/ed25519"
	"math/rand"
	"testing"
)

// Property tests for the witness cosign primitives. Where the focused
// tests in witness_test.go pin specific scenarios, these run the same
// invariants over many seeded random shapes. Failures print the seed
// for repro.
//
// Properties under test:
//
//   1. Roundtrip   — sign + verify with matching pins ALWAYS succeeds.
//   2. Tamper      — flipping ANY single byte in (sth, server_url,
//                    chain_id, witness_pub, witness_sig) ALWAYS rejects.
//   3. Cross-replay — a cosign for (server_A, chain_X) MUST NOT validate
//                    under (server_B, chain_X), (server_A, chain_Y), or
//                    any other pinned witness pub.
//   4. Determinism — same inputs MUST yield byte-identical cosign.
//   5. Empty-string fields — empty server_url/chain_id MUST reject.

const witnessPropIters = 200

// keyseedFromInt produces a deterministic ed25519 keypair from an
// integer seed so failures are reproducible. Standard library has no
// such helper; we hash the int into the 32-byte seed.
func keyseed(t *testing.T, seed int64) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	seedBytes := make([]byte, 32)
	r.Read(seedBytes)
	priv := ed25519.NewKeyFromSeed(seedBytes)
	return priv.Public().(ed25519.PublicKey), priv
}

// randomChainID returns a chain id with prefix and pseudo-random body.
func randomChainID(r *rand.Rand) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 26)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	if r.Intn(2) == 0 {
		return "scope:s_" + string(b)
	}
	return "user:" + string(b[:8])
}

// randomServerURL returns a syntactically-plausible URL.
func randomServerURL(r *rand.Rand) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789-"
	host := make([]byte, 8+r.Intn(16))
	for i := range host {
		host[i] = charset[r.Intn(len(charset))]
	}
	port := 1024 + r.Intn(60000)
	if r.Intn(2) == 0 {
		return "https://" + string(host) + ".example"
	}
	// IPv4 with port, common in the test suite.
	return "http://127.0.0.1:" + itoa(port) + "/" + string(host[:4])
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// randomSTH builds a server-signed STH with random size + root +
// timestamp. The signature is real (over the deterministic key from
// `keyseed`) so VerifySTH passes when expected.
func randomSTH(t *testing.T, srvPriv ed25519.PrivateKey, chainID string, r *rand.Rand) STH {
	t.Helper()
	size := uint64(r.Intn(1 << 20))
	var root []byte
	if size == 0 {
		root = EmptyRoot()
	} else {
		root = make([]byte, HashSize)
		r.Read(root)
	}
	head := TreeHead{
		ChainID:   chainID,
		TreeSize:  size,
		RootHash:  root,
		Timestamp: uint64(r.Int63()),
	}
	sth, err := SignSTH(srvPriv, head)
	if err != nil {
		t.Fatal(err)
	}
	return sth
}

// TestPropertyWitnessCosignRoundtrip — sign + verify with matching
// pins ALWAYS succeeds, across many random STH shapes + key pairs.
func TestPropertyWitnessCosignRoundtrip(t *testing.T) {
	for i := 0; i < witnessPropIters; i++ {
		seed := int64(0x10000 + i)
		r := rand.New(rand.NewSource(seed))
		srvPub, srvPriv := keyseed(t, seed)
		wPub, wPriv := keyseed(t, seed+1)
		chainID := randomChainID(r)
		serverURL := randomServerURL(r)
		sth := randomSTH(t, srvPriv, chainID, r)

		w, err := SignWitnessedSTH(wPriv, sth, serverURL)
		if err != nil {
			t.Fatalf("seed=%#x: sign: %v", seed, err)
		}
		if err := VerifyWitnessedSTH(srvPub, wPub, serverURL, chainID, w); err != nil {
			t.Fatalf("seed=%#x: verify roundtrip failed: %v", seed, err)
		}
	}
}

// TestPropertyWitnessCosignTamperRejectsAllFields — flipping any
// single byte in any field of WitnessedSTH MUST reject. This is the
// strongest "honest sig + dishonest payload" test we can do.
func TestPropertyWitnessCosignTamperRejectsAllFields(t *testing.T) {
	for i := 0; i < witnessPropIters; i++ {
		seed := int64(0x20000 + i)
		r := rand.New(rand.NewSource(seed))
		srvPub, srvPriv := keyseed(t, seed)
		wPub, wPriv := keyseed(t, seed+1)
		chainID := randomChainID(r)
		serverURL := randomServerURL(r)
		sth := randomSTH(t, srvPriv, chainID, r)
		w, _ := SignWitnessedSTH(wPriv, sth, serverURL)

		// Six tamper targets — pick one per iteration.
		switch i % 6 {
		case 0:
			tamper := w
			tamper.STH.Head.RootHash = append([]byte(nil), w.STH.Head.RootHash...)
			tamper.STH.Head.RootHash[r.Intn(len(tamper.STH.Head.RootHash))] ^= 0x01
			if err := VerifyWitnessedSTH(srvPub, wPub, serverURL, chainID, tamper); err == nil {
				t.Fatalf("seed=%#x: tampered RootHash accepted", seed)
			}
		case 1:
			tamper := w
			tamper.STH.Signature = append([]byte(nil), w.STH.Signature...)
			tamper.STH.Signature[r.Intn(len(tamper.STH.Signature))] ^= 0x01
			if err := VerifyWitnessedSTH(srvPub, wPub, serverURL, chainID, tamper); err == nil {
				t.Fatalf("seed=%#x: tampered server Signature accepted", seed)
			}
		case 2:
			tamper := w
			tamper.WitnessSig = append([]byte(nil), w.WitnessSig...)
			tamper.WitnessSig[r.Intn(len(tamper.WitnessSig))] ^= 0x01
			if err := VerifyWitnessedSTH(srvPub, wPub, serverURL, chainID, tamper); err == nil {
				t.Fatalf("seed=%#x: tampered WitnessSig accepted", seed)
			}
		case 3:
			tamper := w
			tamper.ServerURL = serverURL + "x"
			if err := VerifyWitnessedSTH(srvPub, wPub, serverURL, chainID, tamper); err == nil {
				t.Fatalf("seed=%#x: tampered ServerURL accepted", seed)
			}
		case 4:
			tamper := w
			tamper.STH.Head.ChainID = chainID + "_evil"
			if err := VerifyWitnessedSTH(srvPub, wPub, serverURL, chainID, tamper); err == nil {
				t.Fatalf("seed=%#x: tampered embedded ChainID accepted", seed)
			}
		case 5:
			// WitnessPub field is NOT covered by the cosign
			// signature (the signed input embeds the pub via the
			// signing operation, not via the field). Only the
			// explicit `embedded == pin` equality check in
			// VerifyWitnessedSTH protects it. Codex review caught
			// the original tamper test missed this — without the
			// equality check, a tampered WitnessPub would be
			// silently trusted by downstream code reading the
			// field. Mutate it and assert reject.
			tamper := w
			tamper.WitnessPub = append([]byte(nil), w.WitnessPub...)
			tamper.WitnessPub[r.Intn(len(tamper.WitnessPub))] ^= 0x01
			if err := VerifyWitnessedSTH(srvPub, wPub, serverURL, chainID, tamper); err == nil {
				t.Fatalf("seed=%#x: tampered WitnessPub accepted", seed)
			}
		}
	}
}

// TestPropertyWitnessCosignNoCrossReplay — a cosign for one
// (server_url, chain_id) MUST NOT validate when verified against any
// other (server, chain) tuple. Fuzzes the cross-replay surface that
// the (server_url binding) and the (chain_id binding) collectively
// close.
func TestPropertyWitnessCosignNoCrossReplay(t *testing.T) {
	for i := 0; i < witnessPropIters; i++ {
		seed := int64(0x30000 + i)
		r := rand.New(rand.NewSource(seed))
		srvPub, srvPriv := keyseed(t, seed)
		wPub, wPriv := keyseed(t, seed+1)
		chainA := "scope:s_" + randomChainID(r)[7:]
		chainB := "scope:s_" + randomChainID(r)[7:]
		if chainA == chainB {
			chainB = chainA + "_b"
		}
		urlA := randomServerURL(r)
		urlB := urlA + "_b"
		sth := randomSTH(t, srvPriv, chainA, r)
		w, _ := SignWitnessedSTH(wPriv, sth, urlA)

		// Cosign for (urlA, chainA) tested under all 3 wrong pairs:
		for _, pair := range []struct{ u, c string }{
			{urlB, chainA},
			{urlA, chainB},
			{urlB, chainB},
		} {
			if err := VerifyWitnessedSTH(srvPub, wPub, pair.u, pair.c, w); err == nil {
				t.Fatalf("seed=%#x: cosign for (urlA,chainA) verified under (%s,%s)",
					seed, pair.u, pair.c)
			}
		}
	}
}

// TestPropertyWitnessCosignDeterministic — identical (priv, sth,
// serverURL) inputs MUST yield byte-identical cosign bytes. ed25519 is
// deterministic, but a regression here would be a serialisation drift
// (e.g. CBOR map order) that silently changes signatures.
func TestPropertyWitnessCosignDeterministic(t *testing.T) {
	for i := 0; i < 100; i++ {
		seed := int64(0x40000 + i)
		r := rand.New(rand.NewSource(seed))
		_, srvPriv := keyseed(t, seed)
		_, wPriv := keyseed(t, seed+1)
		chainID := randomChainID(r)
		serverURL := randomServerURL(r)
		sth := randomSTH(t, srvPriv, chainID, r)
		w1, _ := SignWitnessedSTH(wPriv, sth, serverURL)
		w2, _ := SignWitnessedSTH(wPriv, sth, serverURL)
		if !bytes.Equal(w1.WitnessSig, w2.WitnessSig) {
			t.Fatalf("seed=%#x: WitnessSig non-deterministic", seed)
		}
	}
}

// TestPropertyWitnessCosignWrongPubsReject — for every roundtrip pair
// (srvPub, wPub), verifying under a DIFFERENT pin MUST fail. Fuzzes
// against signing-oracle bugs that ignore the verifier-supplied pin.
func TestPropertyWitnessCosignWrongPubsReject(t *testing.T) {
	for i := 0; i < witnessPropIters; i++ {
		seed := int64(0x50000 + i)
		r := rand.New(rand.NewSource(seed))
		srvPub, srvPriv := keyseed(t, seed)
		wPub, wPriv := keyseed(t, seed+1)
		otherSrvPub, _ := keyseed(t, seed+1000)
		otherWPub, _ := keyseed(t, seed+1001)

		chainID := randomChainID(r)
		serverURL := randomServerURL(r)
		sth := randomSTH(t, srvPriv, chainID, r)
		w, _ := SignWitnessedSTH(wPriv, sth, serverURL)

		// Wrong server pub.
		if err := VerifyWitnessedSTH(otherSrvPub, wPub, serverURL, chainID, w); err == nil {
			t.Fatalf("seed=%#x: wrong server pub accepted", seed)
		}
		// Wrong witness pub.
		if err := VerifyWitnessedSTH(srvPub, otherWPub, serverURL, chainID, w); err == nil {
			t.Fatalf("seed=%#x: wrong witness pub accepted", seed)
		}
		// Both wrong.
		if err := VerifyWitnessedSTH(otherSrvPub, otherWPub, serverURL, chainID, w); err == nil {
			t.Fatalf("seed=%#x: both wrong pubs accepted", seed)
		}
	}
}

// TestPropertyWitnessCosignEdgeStringsReject — empty / very-long
// server_url / chain_id and pathological STH shapes must not panic
// AND must not silently accept.
func TestPropertyWitnessCosignEdgeStringsReject(t *testing.T) {
	srvPub, srvPriv := keyseed(t, 1)
	wPub, wPriv := keyseed(t, 2)
	chainID := "scope:s_test"
	serverURL := "https://server.example"

	// Sign with empty serverURL → must error at sign-time.
	root := make([]byte, HashSize)
	root[0] = 1
	head := TreeHead{ChainID: chainID, TreeSize: 1, RootHash: root, Timestamp: 1}
	sth, _ := SignSTH(srvPriv, head)
	if _, err := SignWitnessedSTH(wPriv, sth, ""); err == nil {
		t.Fatal("sign with empty serverURL should error")
	}

	// Verify with empty expectedServerURL → must error.
	w, _ := SignWitnessedSTH(wPriv, sth, serverURL)
	if err := VerifyWitnessedSTH(srvPub, wPub, "", chainID, w); err == nil {
		t.Fatal("verify with empty expectedServerURL should error")
	}
	// Verify with empty expectedChainID → must error.
	if err := VerifyWitnessedSTH(srvPub, wPub, serverURL, "", w); err == nil {
		t.Fatal("verify with empty expectedChainID should error")
	}
	// Wrong-size pins must error, not panic.
	if err := VerifyWitnessedSTH(srvPub, []byte{1, 2, 3}, serverURL, chainID, w); err == nil {
		t.Fatal("short witness pin must reject")
	}
	if err := VerifyWitnessedSTH([]byte{1, 2}, wPub, serverURL, chainID, w); err == nil {
		t.Fatal("short server pin must reject")
	}
	// Very-long serverURL — sign + verify roundtrip should still
	// work (we don't impose length limits on the signed payload).
	long := serverURL + string(make([]byte, 8000))
	w2, err := SignWitnessedSTH(wPriv, sth, long)
	if err != nil {
		t.Fatalf("sign long serverURL: %v", err)
	}
	if err := VerifyWitnessedSTH(srvPub, wPub, long, chainID, w2); err != nil {
		t.Fatalf("verify long serverURL: %v", err)
	}
}
