package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// Property tests for the WitnessCheckClient threshold logic. Each
// test stands up N in-process witness HTTP servers, programs each to
// respond with a chosen behavior (matching cosign / divergent root /
// 404 / 5xx / bad sig), and asserts CrossCheckSTH's return value
// matches the expected outcome.
//
// Properties under test:
//
//   1. Threshold math    — matching < min_cosigns ⇒ insufficient.
//   2. Equivocation wins — any divergent root ⇒ ErrWitnessEquivocation
//                          regardless of how many other witnesses match.
//   3. 409 wins          — any witness that itself reports multi-root
//                          (HTTP 409) ⇒ ErrWitnessEquivocation.
//   4. Lag = no-confirm  — 404 NEVER counts toward threshold (codex
//                          fix #3 — there is no soft-tolerance knob).
//   5. Bad cosigns skip  — invalid signatures are NOT positive
//                          confirmation; they don't drag the cross-
//                          check toward equivocation either.

// witnessFake is a single in-process witness HTTP server with
// programmable per-(server, chain, size) responses.
type witnessFake struct {
	srv         *httptest.Server
	pub         ed25519.PublicKey
	priv        ed25519.PrivateKey
	respond     func(serverURL, chainID string, treeSize uint64) (status int, w *translog.WitnessedSTH)
}

func newWitnessFake(t *testing.T, seed int64) *witnessFake {
	t.Helper()
	pub, priv := keyseedCli(t, seed)
	wf := &witnessFake{pub: pub, priv: priv}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/witness/sth/", func(w http.ResponseWriter, r *http.Request) {
		// Parse path: /v1/witness/sth/<server_b64>/<chain>?tree_size=N
		rest := strings.TrimPrefix(r.URL.Path, "/v1/witness/sth/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			http.Error(w, "bad path", http.StatusBadRequest)
			return
		}
		serverURL, _ := decodeB64URL(parts[0])
		chainID := parts[1]
		var size uint64
		fmt.Sscanf(r.URL.Query().Get("tree_size"), "%d", &size)
		status, body := wf.respond(serverURL, chainID, size)
		if body == nil {
			http.Error(w, "respond returned nil", status)
			return
		}
		buf, _ := proto.Marshal(body)
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(status)
		w.Write(buf)
	})
	wf.srv = httptest.NewServer(mux)
	t.Cleanup(wf.srv.Close)
	return wf
}

// keyseedCli mirrors translog.keyseed (cli package can't import test
// helpers from translog).
func keyseedCli(t *testing.T, seed int64) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	sb := make([]byte, 32)
	r.Read(sb)
	priv := ed25519.NewKeyFromSeed(sb)
	return priv.Public().(ed25519.PublicKey), priv
}

// decodeB64URL uses the stdlib decoder so the fake witness rejects
// the same malformed inputs production rejects. Codex review caught
// that the previous hand-rolled "drop invalid chars" decoder masked
// real production decode failures.
func decodeB64URL(s string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// makeServerSignedSTH builds a real server-signed STH. Called from
// HTTP handler goroutines (no *testing.T available) so it panics
// on misuse rather than calling t.Fatal.
func makeServerSignedSTH(srvPriv ed25519.PrivateKey, chainID string, size uint64, root []byte) translog.STH {
	if len(root) != 32 {
		panic(fmt.Sprintf("root must be 32 bytes, got %d", len(root)))
	}
	if size == 0 {
		root = translog.EmptyRoot()
	}
	head := translog.TreeHead{ChainID: chainID, TreeSize: size, RootHash: root, Timestamp: 1}
	sth, err := translog.SignSTH(srvPriv, head)
	if err != nil {
		panic(err)
	}
	return sth
}

// makeFixture wires N fakes into a WitnessCheckClient with the
// supplied min_cosigns. Returns everything the per-test logic needs.
type fixture struct {
	srvPub    ed25519.PublicKey
	srvPriv   ed25519.PrivateKey
	serverURL string
	chainID   string
	fakes     []*witnessFake
	wcc       *WitnessCheckClient
}

func makeFixture(t *testing.T, nWitnesses, minCosigns int) *fixture {
	t.Helper()
	srvPub, srvPriv := keyseedCli(t, 42)
	const chainID = "scope:s_proptest_propertytestpropt"
	const serverURL = "https://srv.example"
	cfg := fdhome.Config{}
	fakes := make([]*witnessFake, nWitnesses)
	for i := range fakes {
		fakes[i] = newWitnessFake(t, int64(100+i))
		cfg.Witnesses = append(cfg.Witnesses, fdhome.WitnessConfig{
			URL:    fakes[i].srv.URL,
			PubHex: hex.EncodeToString(fakes[i].pub),
		})
	}
	cfg.WitnessP = fdhome.WitnessPolicy{MinCosigns: minCosigns}
	wcc, err := NewWitnessCheckClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{
		srvPub: srvPub, srvPriv: srvPriv,
		serverURL: serverURL, chainID: chainID,
		fakes: fakes, wcc: wcc,
	}
}

// programMatching makes a witness fake return a valid WitnessedSTH
// that matches the supplied STH.
func programMatching(f *fixture, idx int, sth translog.STH) {
	w, _ := translog.SignWitnessedSTH(f.fakes[idx].priv, sth, f.serverURL)
	f.fakes[idx].respond = func(_, _ string, _ uint64) (int, *translog.WitnessedSTH) {
		return 200, &w
	}
}

// programDivergent makes the fake sign a DIFFERENT root at the
// requested size. The cosign is internally valid; the cross-check
// must classify this as equivocation.
func programDivergent(f *fixture, idx int) {
	bogus := make([]byte, 32)
	for i := range bogus {
		bogus[i] = 0xEE
	}
	f.fakes[idx].respond = func(_, chainID string, size uint64) (int, *translog.WitnessedSTH) {
		sth := makeServerSignedSTH(f.srvPriv, chainID, size, bogus)
		w, _ := translog.SignWitnessedSTH(f.fakes[idx].priv, sth, f.serverURL)
		return 200, &w
	}
}

// programLagging makes the fake return 404.
func programLagging(f *fixture, idx int) {
	f.fakes[idx].respond = func(_, _ string, _ uint64) (int, *translog.WitnessedSTH) {
		return 404, &translog.WitnessedSTH{}
	}
}

// program409 makes the fake return 409 (multi-root archive evidence).
func program409(f *fixture, idx int) {
	f.fakes[idx].respond = func(_, _ string, _ uint64) (int, *translog.WitnessedSTH) {
		return 409, &translog.WitnessedSTH{}
	}
}

// programBadSig makes the fake return a STH whose witness sig is
// flipped — internally invalid cosign.
func programBadSig(f *fixture, idx int) {
	f.fakes[idx].respond = func(_, chainID string, size uint64) (int, *translog.WitnessedSTH) {
		root := make([]byte, 32)
		root[0] = 1
		sth := makeServerSignedSTH(f.srvPriv, chainID, size, root)
		w, _ := translog.SignWitnessedSTH(f.fakes[idx].priv, sth, f.serverURL)
		w.WitnessSig = append([]byte(nil), w.WitnessSig...)
		w.WitnessSig[0] ^= 0x01
		return 200, &w
	}
}

// ---- properties ----

// TestPropertyThresholdMath: with K matching out of N witnesses and
// MinCosigns = M, CrossCheckSTH passes iff K >= M.
func TestPropertyThresholdMath(t *testing.T) {
	for n := 1; n <= 5; n++ {
		for m := 1; m <= n; m++ {
			for k := 0; k <= n; k++ {
				name := fmt.Sprintf("n=%d_m=%d_k=%d", n, m, k)
				t.Run(name, func(t *testing.T) {
					f := makeFixture(t, n, m)
					sth := makeServerSignedSTH(f.srvPriv, f.chainID, 7, mkRoot(1))
					for i := 0; i < n; i++ {
						if i < k {
							programMatching(f, i, sth)
						} else {
							// non-matching: lag (=no confirmation)
							programLagging(f, i)
						}
					}
					err := f.wcc.CrossCheckSTH(context.Background(), canon.MustParseURL(f.serverURL), f.srvPub, sth)
					if k >= m {
						if err != nil {
							t.Fatalf("expected pass (k=%d >= m=%d), got %v", k, m, err)
						}
					} else {
						if err == nil {
							t.Fatalf("expected insufficient (k=%d < m=%d), got nil", k, m)
						}
					}
				})
			}
		}
	}
}

// TestPropertyEquivocationAlwaysWins: any divergent root cosign MUST
// trigger ErrWitnessEquivocation regardless of (a) how many other
// witnesses respond with matching cosigns and (b) the order in
// which witnesses are configured. The "div-last" ordering is
// critical — codex review caught that a buggy implementation that
// short-circuits as soon as MinCosigns matching responses are
// collected would slip through if divergent witnesses always come
// first. Exercising "matching first then divergent" flushes that.
func TestPropertyEquivocationAlwaysWins(t *testing.T) {
	for n := 2; n <= 5; n++ {
		for kBad := 1; kBad <= n; kBad++ {
			for _, ordering := range []string{"div-first", "div-last"} {
				t.Run(fmt.Sprintf("n=%d_bad=%d_%s", n, kBad, ordering), func(t *testing.T) {
					f := makeFixture(t, n, 1)
					sth := makeServerSignedSTH(f.srvPriv, f.chainID, 9, mkRoot(2))
					for i := 0; i < n; i++ {
						isDivergent := i < kBad
						if ordering == "div-last" {
							isDivergent = i >= n-kBad
						}
						if isDivergent {
							programDivergent(f, i)
						} else {
							programMatching(f, i, sth)
						}
					}
					err := f.wcc.CrossCheckSTH(context.Background(), canon.MustParseURL(f.serverURL), f.srvPub, sth)
					if err == nil || !strings.Contains(err.Error(), "equivocation") {
						t.Fatalf("expected equivocation (n=%d bad=%d order=%s), got %v",
							n, kBad, ordering, err)
					}
				})
			}
		}
	}
}

// TestPropertyMultiRootArchiveAlwaysWins: a witness that returns 409
// (its own archive holds multi-root evidence) MUST trigger
// ErrWitnessEquivocation regardless of other witnesses' responses.
func TestPropertyMultiRootArchiveAlwaysWins(t *testing.T) {
	for n := 2; n <= 4; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			f := makeFixture(t, n, 1)
			sth := makeServerSignedSTH(f.srvPriv, f.chainID, 11, mkRoot(3))
			// One 409 + rest matching → equivocation.
			program409(f, 0)
			for i := 1; i < n; i++ {
				programMatching(f, i, sth)
			}
			err := f.wcc.CrossCheckSTH(context.Background(), canon.MustParseURL(f.serverURL), f.srvPub, sth)
			if err == nil || !strings.Contains(err.Error(), "equivocation") {
				t.Fatalf("expected equivocation from 409, got %v", err)
			}
		})
	}
}

// TestPropertyLagNeverCounts: 404 from a witness MUST NOT count as
// matching. This is the codex-fix-#3 invariant — there is no
// soft-tolerance knob that lets lag satisfy the threshold.
func TestPropertyLagNeverCounts(t *testing.T) {
	for n := 1; n <= 5; n++ {
		t.Run(fmt.Sprintf("n=%d_all_lag", n), func(t *testing.T) {
			f := makeFixture(t, n, 1)
			sth := makeServerSignedSTH(f.srvPriv, f.chainID, 13, mkRoot(4))
			for i := 0; i < n; i++ {
				programLagging(f, i)
			}
			err := f.wcc.CrossCheckSTH(context.Background(), canon.MustParseURL(f.serverURL), f.srvPub, sth)
			if err == nil {
				t.Fatalf("all-lag with min_cosigns=1 must not pass (n=%d)", n)
			}
			if !strings.Contains(err.Error(), "insufficient") {
				t.Fatalf("expected insufficient cosigns, got %v", err)
			}
		})
	}
}

// TestPropertyBadCosignDoesNotCount: a witness that returns a STH
// with an invalid witness sig MUST NOT count as matching, but ALSO
// MUST NOT trigger equivocation (it's just a faulty/compromised
// witness, not a smoking gun about the server).
func TestPropertyBadCosignDoesNotCount(t *testing.T) {
	for n := 2; n <= 4; n++ {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			f := makeFixture(t, n, 1)
			sth := makeServerSignedSTH(f.srvPriv, f.chainID, 15, mkRoot(5))
			// All bad cosigns → should fail with insufficient,
			// NOT with equivocation.
			for i := 0; i < n; i++ {
				programBadSig(f, i)
			}
			err := f.wcc.CrossCheckSTH(context.Background(), canon.MustParseURL(f.serverURL), f.srvPub, sth)
			if err == nil {
				t.Fatalf("all-bad-cosign must not pass")
			}
			if strings.Contains(err.Error(), "equivocation") {
				t.Fatalf("bad cosign should not be classified as equivocation: %v", err)
			}
			if !strings.Contains(err.Error(), "insufficient") {
				t.Fatalf("expected insufficient classification, got %v", err)
			}
		})
	}
}

// TestPropertyDisabledByEmptyConfig: with no [[witness]] entries OR
// MinCosigns=0, NewWitnessCheckClient returns nil and CrossCheckSTH
// is a no-op (cannot fail).
func TestPropertyDisabledByEmptyConfig(t *testing.T) {
	cases := []fdhome.Config{
		{},
		{WitnessP: fdhome.WitnessPolicy{MinCosigns: 0}},
		{Witnesses: []fdhome.WitnessConfig{{URL: "https://x", PubHex: hex.EncodeToString(make([]byte, 32))}}, WitnessP: fdhome.WitnessPolicy{MinCosigns: 0}},
	}
	for i, c := range cases {
		wcc, err := NewWitnessCheckClient(c)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if wcc != nil {
			t.Fatalf("case %d: expected nil client, got %v", i, wcc)
		}
		// nil receiver must be safe.
		if err := wcc.CrossCheckSTH(context.Background(), canon.URL{}, nil, translog.STH{}); err != nil {
			t.Fatalf("case %d: nil client cross-check returned %v, want nil", i, err)
		}
	}
}

// TestPropertyMisconfiguredHexFailsLoudly: bad hex / wrong-length pub
// MUST fail at config-load, not silently downgrade.
func TestPropertyMisconfiguredHexFailsLoudly(t *testing.T) {
	cases := []struct {
		name string
		cfg  fdhome.Config
	}{
		{"bad-hex", fdhome.Config{
			Witnesses: []fdhome.WitnessConfig{{URL: "https://x", PubHex: "not-hex"}},
			WitnessP:  fdhome.WitnessPolicy{MinCosigns: 1},
		}},
		{"short-pub", fdhome.Config{
			Witnesses: []fdhome.WitnessConfig{{URL: "https://x", PubHex: "abcd"}},
			WitnessP:  fdhome.WitnessPolicy{MinCosigns: 1},
		}},
		{"empty-url", fdhome.Config{
			Witnesses: []fdhome.WitnessConfig{{URL: "", PubHex: hex.EncodeToString(make([]byte, 32))}},
			WitnessP:  fdhome.WitnessPolicy{MinCosigns: 1},
		}},
		{"min-exceeds-count", fdhome.Config{
			Witnesses: []fdhome.WitnessConfig{{URL: "https://x", PubHex: hex.EncodeToString(make([]byte, 32))}},
			WitnessP:  fdhome.WitnessPolicy{MinCosigns: 5},
		}},
		// Codex review caught a real production bug: duplicate
		// (URL, pub) entries would each count as a separate
		// matching cosign, letting a single response satisfy
		// min_cosigns=N. Now rejected at config-load.
		{"duplicate-witness-exact", fdhome.Config{
			Witnesses: []fdhome.WitnessConfig{
				{URL: "https://x", PubHex: hex.EncodeToString(mkRoot(1))},
				{URL: "https://x", PubHex: hex.EncodeToString(mkRoot(1))},
			},
			WitnessP: fdhome.WitnessPolicy{MinCosigns: 2},
		}},
		{"duplicate-witness-trailing-slash", fdhome.Config{
			// canonical TrimRight makes these identical → also
			// must be rejected.
			Witnesses: []fdhome.WitnessConfig{
				{URL: "https://x", PubHex: hex.EncodeToString(mkRoot(1))},
				{URL: "https://x/", PubHex: hex.EncodeToString(mkRoot(1))},
			},
			WitnessP: fdhome.WitnessPolicy{MinCosigns: 1},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewWitnessCheckClient(tc.cfg); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func mkRoot(seed byte) []byte {
	r := make([]byte, 32)
	for i := range r {
		r[i] = seed
	}
	return r
}
