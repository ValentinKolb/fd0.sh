package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// httpFixture spins up a Store, primes it with one verified +
// cosigned STH, and returns an httptest.Server fronting the witness
// HTTPServer. Caller must Close the returned server.
type httpFixture struct {
	store      *Store
	srv        *httptest.Server
	serverURL  string
	chainID    string
	witnessPub ed25519.PublicKey
	serverPub  ed25519.PublicKey
	sth        translog.STH
}

func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	witnessPub, witnessPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	const upstream = "https://server.example"
	const chain = "scope:s_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(i)
	}
	head := translog.TreeHead{ChainID: chain, TreeSize: 7, RootHash: root, Timestamp: 1}
	sth, err := translog.SignSTH(serverPriv, head)
	if err != nil {
		t.Fatal(err)
	}
	wsth, err := translog.SignWitnessedSTH(witnessPriv, sth, upstream)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Insert(context.Background(), upstream, sth, 100, wsth.WitnessSig); err != nil {
		t.Fatal(err)
	}

	hs := &HTTPServer{Store: store, WitnessPub: witnessPub, Log: slog.Default()}
	srv := httptest.NewServer(hs.Handler())
	t.Cleanup(srv.Close)

	return &httpFixture{
		store: store, srv: srv, serverURL: upstream, chainID: chain,
		witnessPub: witnessPub, serverPub: serverPub, sth: sth,
	}
}

func TestHTTPServerInfoReturnsWitnessPub(t *testing.T) {
	f := newHTTPFixture(t)
	resp, err := http.Get(f.srv.URL + "/v1/server-info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var info struct {
		WitnessPub []byte `cbor:"witness_pub"`
		PubHex     string `cbor:"witness_pub_hex"`
	}
	if err := proto.Unmarshal(body, &info); err != nil {
		t.Fatal(err)
	}
	if !equalBytes(info.WitnessPub, f.witnessPub) {
		t.Fatal("witness_pub mismatch")
	}
}

func TestHTTPLatestSTHHappyPath(t *testing.T) {
	f := newHTTPFixture(t)
	url := f.srv.URL + "/v1/sth/" + EncodeServerURL(f.serverURL) + "/" + f.chainID
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	var w translog.WitnessedSTH
	if err := proto.Unmarshal(body, &w); err != nil {
		t.Fatal(err)
	}
	// End-to-end: the WitnessedSTH the server hands back must
	// verify under (server_pub, witness_pub, expected_url) — this
	// is exactly what a client would do.
	if err := translog.VerifyWitnessedSTH(f.serverPub, f.witnessPub, f.serverURL, f.chainID, w); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if w.STH.Head.TreeSize != 7 {
		t.Fatalf("expected size 7, got %d", w.STH.Head.TreeSize)
	}
}

func TestHTTPLookupAtSpecificSize(t *testing.T) {
	f := newHTTPFixture(t)
	url := f.srv.URL + "/v1/sth/" + EncodeServerURL(f.serverURL) + "/" + f.chainID + "?tree_size=7"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestHTTPLookupAtUnknownSize404(t *testing.T) {
	f := newHTTPFixture(t)
	url := f.srv.URL + "/v1/sth/" + EncodeServerURL(f.serverURL) + "/" + f.chainID + "?tree_size=999"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for un-observed size, got %d", resp.StatusCode)
	}
}

func TestHTTPRejectsBadServerB64(t *testing.T) {
	f := newHTTPFixture(t)
	url := f.srv.URL + "/v1/sth/" + "not-base64-!@#" + "/" + f.chainID
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for bad b64, got %d", resp.StatusCode)
	}
}

func TestHTTPRejectsBadChainPrefix(t *testing.T) {
	f := newHTTPFixture(t)
	url := f.srv.URL + "/v1/sth/" + EncodeServerURL(f.serverURL) + "/wrongprefix:abc"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("expected 400 for bad chain prefix, got %d", resp.StatusCode)
	}
}

func TestHTTPRejectsNonGET(t *testing.T) {
	f := newHTTPFixture(t)
	url := f.srv.URL + "/v1/server-info"
	req, _ := http.NewRequest("POST", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 405 {
		t.Fatalf("expected 405 for POST, got %d", resp.StatusCode)
	}
}

func TestHTTPLookupReturns404WhenCosignMissing(t *testing.T) {
	// Insert a row with NO cosign — simulates the back-compat path
	// (or a witness that ran without --key configured). The HTTP
	// endpoint MUST refuse to hand back a structurally-incomplete
	// WitnessedSTH; clients that get 404 will retry next sync.
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	witnessPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	root := make([]byte, 32)
	root[0] = 1
	head := translog.TreeHead{ChainID: "scope:s_xx", TreeSize: 1, RootHash: root, Timestamp: 1}
	sth, _ := translog.SignSTH(serverPriv, head)
	if _, err := store.Insert(context.Background(), "https://x", sth, 1, nil); err != nil {
		t.Fatal(err)
	}
	hs := &HTTPServer{Store: store, WitnessPub: witnessPub, Log: slog.Default()}
	srv := httptest.NewServer(hs.Handler())
	defer srv.Close()
	url := srv.URL + "/v1/sth/" + EncodeServerURL("https://x") + "/scope:s_xx"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 for cosign-less row, got %d", resp.StatusCode)
	}
}
