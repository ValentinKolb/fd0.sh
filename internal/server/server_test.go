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
	g, err := chain.BuildUserAuthSet(priv, pub, 0, nil, []proto.AuthMethod{{
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
	e2, err := chain.BuildUserAuthSet(priv, pub, 0, tipHash[:], []proto.AuthMethod{{
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
