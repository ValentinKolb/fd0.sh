package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

func TestInspectServerReturnsVerifiedCanonicalPreview(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	info, err := translog.SignServerInfo(priv, 42, "test-primary", nil)
	if err != nil {
		t.Fatal(err)
	}
	server := serverInfoTestServer(t, func() translog.ServerInfo { return info })

	preview, err := InspectServer(context.Background(), server.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if preview.URL != server.URL || preview.Label != "test-primary" {
		t.Fatalf("preview=%+v", preview)
	}
	if !ed25519.PublicKey(info.ServerPub).Equal(preview.ServerPub) {
		t.Fatal("preview returned the wrong server key")
	}
	if preview.Fingerprint == "" {
		t.Fatal("preview fingerprint is empty")
	}
}

func TestInspectServerRejectsInvalidSelfSignature(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	info, err := translog.SignServerInfo(priv, 42, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	info.Signature[0] ^= 0x80
	server := serverInfoTestServer(t, func() translog.ServerInfo { return info })

	if _, err := InspectServer(context.Background(), server.URL); !errors.Is(err, ErrServerInfoUnsigned) {
		t.Fatalf("err=%v, want ErrServerInfoUnsigned", err)
	}
}

func TestPinServerRejectsPreviewCommitIdentityChange(t *testing.T) {
	_, firstPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, secondPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := translog.SignServerInfo(firstPriv, 1, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := translog.SignServerInfo(secondPriv, 2, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := serverInfoTestServer(t, func() translog.ServerInfo {
		if requests.Add(1) == 1 {
			return first
		}
		return second
	})
	preview, err := InspectServer(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	serverURL, err := canon.ParseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{Body: &proto.VaultBody{}}
	if err := session.pinServer(context.Background(), serverURL, preview.ServerPub); !errors.Is(err, ErrServerIdentityChanged) {
		t.Fatalf("err=%v, want ErrServerIdentityChanged", err)
	}
	if len(session.Body.PinnedServers) != 0 {
		t.Fatal("changed identity was persisted")
	}
}

func serverInfoTestServer(t *testing.T, current func() translog.ServerInfo) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/server-info" {
			http.NotFound(w, r)
			return
		}
		body, err := proto.Marshal(current())
		if err != nil {
			t.Error(err)
			http.Error(w, "encode", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}
