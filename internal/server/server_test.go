package server

import (
	"bytes"
	"context"
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
	"github.com/valentinkolb/fd0.sh/internal/translog"
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
	srv, ts := newTestServer(t)
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), 0, nil, []proto.AuthMethod{{
		MethodID: "am_x", MethodType: proto.AuthPassphrase,
		PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0xff},
	}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := proto.Marshal(map[string]any{"event": g})
	resp, err := http.Post(ts.URL+"/v1/users", "application/cbor", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
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
	// Fetch latest. Codex security audit fix: this endpoint now
	// requires HTTP-sig auth (super_priv must match the chain's
	// user_super_pub) — a plain http.Get returns 401.
	req2, _ := http.NewRequest("GET", ts.URL+"/v1/users/"+reg.ShortID+"/events?latest=true", nil)
	signRequest(t, srv, req2, nil, pub.Bytes(), priv.Bytes())
	r2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
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
	if !bytes.Equal(got.UserSuperPub, pub.Bytes()) {
		t.Fatalf("pub mismatch")
	}
	// Append a second auth.set (authenticated).
	prefix, _ := g.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	e2, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), 0, tipHash[:], []proto.AuthMethod{{
		MethodID: "am_y", MethodType: proto.AuthPassphrase,
		PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0xee},
	}})
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := proto.Marshal(map[string]any{"event": e2})
	url := ts.URL + "/v1/users/" + reg.ShortID + "/events"
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body2))
	signRequest(t, srv, req, body2, pub.Bytes(), priv.Bytes())
	r3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r3.Body.Close()
	if r3.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r3.Body)
		t.Fatalf("append: %d %s", r3.StatusCode, b)
	}
}

// TestTranslogEndpoints exercises the four new GET endpoints from
// TRANSLOG.md §5: server-info (self-signed pubkey publication),
// current STH, inclusion proof, consistency proof. Also confirms that
// a /users register response carries an STH + inclusion proof and
// that a follow-up authenticated append response carries an STH +
// inclusion proof + consistency proof when last_sth_size is supplied.
//
// This is the C3 end-to-end smoke test for the translog wire-up.
func TestTranslogEndpoints(t *testing.T) {
	srv, ts := newTestServer(t)

	// /v1/server-info — unauthenticated, returns a self-signed
	// ServerInfo whose embedded pubkey verifies the signature.
	r1, err := http.Get(ts.URL + "/v1/server-info")
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("server-info: %d", r1.StatusCode)
	}
	rb1, _ := io.ReadAll(r1.Body)
	var info translog.ServerInfo
	if err := proto.Unmarshal(rb1, &info); err != nil {
		t.Fatalf("server-info decode: %v", err)
	}
	if err := translog.VerifyServerInfo(info); err != nil {
		t.Fatalf("server-info verify: %v", err)
	}
	// pubkey on the wire must match what the store actually holds.
	if !bytes.Equal(info.ServerPub, srv.store.TranslogPub()) {
		t.Fatal("server-info pub doesn't match store's installed translog pub")
	}

	// Register a user → response must carry sth + inclusion_proof.
	pub, priv, _ := crypto.GenerateIdentity()
	g, _ := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), 0, nil, []proto.AuthMethod{{
		MethodID: "am_z", MethodType: proto.AuthPassphrase,
		PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0x42},
	}})
	body, _ := proto.Marshal(map[string]any{"event": g})
	r2, err := http.Post(ts.URL+"/v1/users", "application/cbor", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(r2.Body)
		t.Fatalf("register: %d %s", r2.StatusCode, b)
	}
	rb2, _ := io.ReadAll(r2.Body)
	var reg struct {
		ShortID        string                  `cbor:"shortId"`
		EventID        string                  `cbor:"event_id"`
		STH            translog.STH            `cbor:"sth"`
		InclusionProof translog.InclusionProof `cbor:"inclusion_proof"`
	}
	if err := proto.Unmarshal(rb2, &reg); err != nil {
		t.Fatal(err)
	}
	if reg.STH.Head.TreeSize != 1 {
		t.Fatalf("register STH size: got %d want 1", reg.STH.Head.TreeSize)
	}
	if err := translog.VerifySTH(info.ServerPub, reg.STH); err != nil {
		t.Fatalf("register STH verify: %v", err)
	}
	prefix, _ := g.PrevHashInput()
	leafHash := translog.LeafHashOfPrevInput(prefix)
	if err := translog.VerifyInclusion(leafHash, 0, reg.STH.Head.TreeSize, reg.InclusionProof.AuditPath, reg.STH.Head.RootHash); err != nil {
		t.Fatalf("register inclusion proof verify: %v", err)
	}

	// /v1/sth/{chainId} — same root as the register response.
	chainID := "user:" + reg.ShortID
	r3, err := http.Get(ts.URL + "/v1/sth/" + chainID)
	if err != nil {
		t.Fatal(err)
	}
	if r3.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r3.Body)
		t.Fatalf("sth: %d %s", r3.StatusCode, b)
	}
	rb3, _ := io.ReadAll(r3.Body)
	var stoSTH translog.STH
	if err := proto.Unmarshal(rb3, &stoSTH); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stoSTH.Head.RootHash, reg.STH.Head.RootHash) {
		t.Fatal("/v1/sth root mismatch with register response")
	}

	// /v1/proof/inclusion — same proof bytes.
	r4, err := http.Get(ts.URL + "/v1/proof/inclusion?chain_id=" + chainID + "&leaf_index=0&tree_size=1")
	if err != nil {
		t.Fatal(err)
	}
	if r4.StatusCode != http.StatusOK {
		t.Fatalf("inclusion: %d", r4.StatusCode)
	}
	rb4, _ := io.ReadAll(r4.Body)
	var inc translog.InclusionProof
	if err := proto.Unmarshal(rb4, &inc); err != nil {
		t.Fatal(err)
	}
	if err := translog.VerifyInclusion(leafHash, 0, 1, inc.AuditPath, stoSTH.Head.RootHash); err != nil {
		t.Fatalf("/v1/proof/inclusion verify: %v", err)
	}

	// Append a second event WITH last_sth_size=1 → response must
	// include a consistency proof from size 1 to size 2.
	tipHash := proto.HashPrefix(prefix)
	e2, _ := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), 0, tipHash[:], []proto.AuthMethod{{
		MethodID: "am_z2", MethodType: proto.AuthPassphrase,
		PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0x43},
	}})
	body2, _ := proto.Marshal(map[string]any{"event": e2, "last_sth_size": uint64(1)})
	url := ts.URL + "/v1/users/" + reg.ShortID + "/events"
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body2))
	signRequest(t, srv, req, body2, pub.Bytes(), priv.Bytes())
	r5, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r5.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r5.Body)
		t.Fatalf("append: %d %s", r5.StatusCode, b)
	}
	rb5, _ := io.ReadAll(r5.Body)
	var app struct {
		EventID          string                     `cbor:"event_id"`
		Seq              uint64                     `cbor:"seq"`
		STH              translog.STH               `cbor:"sth"`
		InclusionProof   translog.InclusionProof    `cbor:"inclusion_proof"`
		ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof"`
	}
	if err := proto.Unmarshal(rb5, &app); err != nil {
		t.Fatal(err)
	}
	if app.STH.Head.TreeSize != 2 {
		t.Fatalf("append STH size: got %d want 2", app.STH.Head.TreeSize)
	}
	if app.ConsistencyProof == nil {
		t.Fatal("append response missing consistency_proof despite last_sth_size=1")
	}
	if err := translog.VerifyConsistency(1, 2, app.ConsistencyProof.Nodes, reg.STH.Head.RootHash, app.STH.Head.RootHash); err != nil {
		t.Fatalf("consistency proof verify: %v", err)
	}

	// /v1/proof/consistency direct fetch must return the same proof.
	r6, err := http.Get(ts.URL + "/v1/proof/consistency?chain_id=" + chainID + "&from_size=1&to_size=2")
	if err != nil {
		t.Fatal(err)
	}
	if r6.StatusCode != http.StatusOK {
		t.Fatalf("consistency: %d", r6.StatusCode)
	}
	rb6, _ := io.ReadAll(r6.Body)
	var cons translog.ConsistencyProof
	if err := proto.Unmarshal(rb6, &cons); err != nil {
		t.Fatal(err)
	}
	if len(cons.Nodes) != len(app.ConsistencyProof.Nodes) {
		t.Fatal("/v1/proof/consistency length mismatch")
	}
	for i := range cons.Nodes {
		if !bytes.Equal(cons.Nodes[i], app.ConsistencyProof.Nodes[i]) {
			t.Fatalf("/v1/proof/consistency node[%d] mismatch", i)
		}
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
		g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), 0, nil, []proto.AuthMethod{{
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
	resp, err := http.Post(ts.URL+"/v1/users", "application/cbor", bytes.NewReader(mkBody(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("first register should succeed: %d %s", resp.StatusCode, b)
	}
	// 2nd: limited
	resp2, err := http.Post(ts.URL+"/v1/users", "application/cbor", bytes.NewReader(mkBody(t)))
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
	// Register pub as a known user so the auth middleware accepts
	// signed requests (codex audit fix: server.IsUserRegistered).
	if err := srv.Store().RegisterUser(context.Background(), pub.Bytes(), "test_short_id"); err != nil {
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
		req, _ := http.NewRequest("POST", ts.URL+"/v1/sync", bytes.NewReader(body))
		signRequest(t, srv, req, body, pub.Bytes(), priv.Bytes())
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
		g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: priv}, pub.Bytes(), 0, nil, []proto.AuthMethod{{
			MethodID: "am_x", MethodType: proto.AuthPassphrase,
			PublicParams: make([]byte, 16), EncryptedSuperPriv: []byte{0xff},
		}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := proto.Marshal(map[string]any{"event": g})
		resp, err := http.Post(ts.URL+"/v1/users", "application/cbor", bytes.NewReader(body))
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
// serverPub is the receiving server's translog pubkey; the signed
// input includes it to defeat cross-server replay.
func signRequest(t *testing.T, srv *Server, r *http.Request, body, pub, priv []byte) {
	t.Helper()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	ts := uint64(time.Now().Unix())
	qmap := map[string]string{}
	for k, vs := range r.URL.Query() {
		qmap[k] = vs[0]
	}
	srvPub := srv.Store().TranslogPub()
	si, err := proto.HTTPSignedInput(r.Method, r.URL.Path, qmap, ts, nonce, body, []byte(srvPub))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := crypto.SignBytes(priv, si)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization",
		"fd0-sig v1 pk="+base64.StdEncoding.EncodeToString(pub)+
			", nonce="+base64.StdEncoding.EncodeToString(nonce)+
			", ts="+strconv.FormatUint(ts, 10)+
			", sig="+base64.StdEncoding.EncodeToString(sig))
}
