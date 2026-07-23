package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/httpguard"
)

func TestSyncHTTPClientRejectsRedirects(t *testing.T) {
	if syncHTTPClient.CheckRedirect == nil {
		t.Fatal("sync HTTP client follows redirects")
	}
}

func TestFetchServerInfoRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
	}))
	defer server.Close()

	_, err := fetchServerInfo(context.Background(), server.URL)
	if !errors.Is(err, httpguard.ErrResponseTooLarge) {
		t.Fatalf("fetchServerInfo error = %v, want ErrResponseTooLarge", err)
	}
}
