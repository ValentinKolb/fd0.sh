package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/server/ratelimit"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	srv, err := New(Config{
		Bind:    "",
		DBPath:  filepath.Join(dir, "fd0.db"),
		Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	t.Cleanup(func() {
		ts.Close()
		_ = srv.Close()
	})
	return srv, ts
}

func TestRegisterAndAppend(t *testing.T) {
	_, ts := newTestServer(t)
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub, 0, nil, []proto.AuthMethod{{
		MethodID: "am_x", MethodType: proto.AuthPassphrase,
		PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0xff},
	}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := proto.Marshal(map[string]any{"event": g})
	resp, err := http.Post(ts.URL+"/users", "application/cbor", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("register: %d %s", resp.StatusCode, b)
	}
	var reg struct {
		ShortID string `cbor:"shortId"`
		EventID string `cbor:"event_id"`
	}
	rb, _ := io.ReadAll(resp.Body)
	if err := proto.Unmarshal(rb, &reg); err != nil {
		t.Fatal(err)
	}
	if reg.ShortID == "" {
		t.Fatal("no shortId")
	}
	// Fetch latest.
	r2, err := http.Get(ts.URL + "/users/" + reg.ShortID + "/events?latest=true")
	if err != nil {
		t.Fatal(err)
	}
	if r2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r2.Body)
		t.Fatalf("fetch: %d %s", r2.StatusCode, b)
	}
	rb2, _ := io.ReadAll(r2.Body)
	var got struct {
		UserSuperPub []byte `cbor:"user_super_pub"`
		Event        proto.UserEvent `cbor:"event"`
		ChainTipSeq  uint64 `cbor:"chain_tip_seq"`
	}
	if err := proto.Unmarshal(rb2, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.UserSuperPub, pub) {
		t.Fatalf("pub mismatch")
	}
	// Append a second auth.set (authenticated).
	prefix, _ := g.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	e2, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub, 0, tipHash[:], []proto.AuthMethod{{
		MethodID: "am_y", MethodType: proto.AuthPassphrase,
		PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0xee},
	}})
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := proto.Marshal(map[string]any{"event": e2})
	url := ts.URL + "/users/" + reg.ShortID + "/events"
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body2))
	signRequest(t, req, body2, pub, priv)
	r3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r3.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r3.Body)
		t.Fatalf("append: %d %s", r3.StatusCode, b)
	}
}

// TestRateLimitRegister420 verifies the per-IP register limiter kicks in
// after the configured budget and produces a Retry-After header.
func TestRateLimitRegister420(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(Config{
		DBPath:  filepath.Join(dir, "fd0.db"),
		Version: "test",
		// 1 register per "hour" — enough to allow the first call and
		// reject the second.
		RateLimit: ratelimit.Config{RegisterPerHour: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	mkBody := func(t *testing.T) []byte {
		pub, priv, err := crypto.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub, 0, nil, []proto.AuthMethod{{
			MethodID: "am_x", MethodType: proto.AuthPassphrase,
			PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0xff},
		}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := proto.Marshal(map[string]any{"event": g})
		return body
	}
	// 1st: ok
	resp, err := http.Post(ts.URL+"/users", "application/cbor", bytes.NewReader(mkBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("first register should succeed: %d %s", resp.StatusCode, b)
	}
	// 2nd: limited
	resp2, err := http.Post(ts.URL+"/users", "application/cbor", bytes.NewReader(mkBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusTooManyRequests {
		b, _ := io.ReadAll(resp2.Body)
		t.Fatalf("second register should be 429, got %d %s", resp2.StatusCode, b)
	}
	if resp2.Header.Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After header")
	}
}

// TestRateLimitWritesAfterAuth verifies the per-identity write limiter
// kicks in on /sync after the configured budget. The limiter is checked
// AFTER signature verification to prevent attackers from burning a
// victim's bucket via spoofed Authorization headers — we exercise that
// by sending well-formed signatures from one identity and confirming the
// rejection comes back as 429 (not 401).
func TestRateLimitWritesAfterAuth(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(Config{
		DBPath:  filepath.Join(dir, "fd0.db"),
		Version: "test",
		// Allow 2 writes/min; on the 3rd we expect 429.
		// Bytes budget set very high to avoid that path firing instead.
		RateLimit: ratelimit.Config{
			IdentityWritesPerMin: 2,
			IdentityBytesPerMin:  1 << 30,
			RegisterPerHour:      100,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	postSync := func() *http.Response {
		// Empty pull, empty push. Server runs through verifyHTTPSig
		// (which is where the rate-limit check sits) before noticing
		// there's nothing to do.
		body, _ := proto.Marshal(map[string]any{
			"pull": map[string]any{
				"scopes":          map[string]any{},
				"limit_per_scope": uint64(0),
			},
			"push": []any{},
		})
		req, _ := http.NewRequest("POST", ts.URL+"/sync", bytes.NewReader(body))
		signRequest(t, req, body, pub, priv)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for i := 0; i < 2; i++ {
		r := postSync()
		if r.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(r.Body)
			t.Fatalf("write %d should succeed within budget: %d %s", i, r.StatusCode, b)
		}
		r.Body.Close()
	}
	r := postSync()
	if r.StatusCode != http.StatusTooManyRequests {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("3rd write should be 429, got %d %s", r.StatusCode, b)
	}
	if r.Header.Get("Retry-After") == "" {
		t.Fatal("429 must set Retry-After")
	}
	r.Body.Close()
}

// TestRateLimitDisabled confirms the kill switch.
func TestRateLimitDisabled(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(Config{
		DBPath:            filepath.Join(dir, "fd0.db"),
		Version:           "test",
		RateLimitDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 20 registrations in a row from the same IP must all succeed when
	// rate limiting is disabled.
	for i := 0; i < 20; i++ {
		pub, priv, err := crypto.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub, 0, nil, []proto.AuthMethod{{
			MethodID: "am_x", MethodType: proto.AuthPassphrase,
			PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0xff},
		}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := proto.Marshal(map[string]any{"event": g})
		resp, err := http.Post(ts.URL+"/users", "application/cbor", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("iter %d: %d %s", i, resp.StatusCode, b)
		}
	}
}

// signRequest computes fd0-sig and sets the Authorization header.
func signRequest(t *testing.T, r *http.Request, body, pub, priv []byte) {
	t.Helper()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	ts := uint64(time.Now().Unix())
	qmap := map[string]string{}
	for k, vs := range r.URL.Query() {
		qmap[k] = vs[0]
	}
	si, err := proto.HTTPSignedInput(r.Method, r.URL.Path, qmap, ts, nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	sig := crypto.Sign(priv, si)
	r.Header.Set("Authorization",
		"fd0-sig v1 pk="+base64.StdEncoding.EncodeToString(pub)+
			", nonce="+base64.StdEncoding.EncodeToString(nonce)+
			", ts="+strconv.FormatUint(ts, 10)+
			", sig="+base64.StdEncoding.EncodeToString(sig))
}
