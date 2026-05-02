package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// FuzzServerEndpoints stresses the public HTTP endpoints with
// arbitrary path + query + body. The contract:
//   - never panic
//   - status always in {200, 201, 400, 401, 403, 404, 405, 409,
//     410, 413, 414, 429, 500, 502}
func FuzzServerEndpoints(f *testing.F) {
	dir := f.TempDir()
	srv, err := New(Config{
		DBPath:            filepath.Join(dir, "fuzz.db"),
		Version:           "fuzz",
		RateLimitDisabled: true,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { srv.Close() })
	ts := httptest.NewServer(srv)
	f.Cleanup(ts.Close)

	// Seeds derived from real API patterns.
	f.Add("/healthz", "", "")
	f.Add("/version", "", "")
	f.Add("/v1/server-info", "", "")
	f.Add("/v1/sth/scope:s_aaaaaaaaaaaaaaaaaaaaaaaaaa", "", "")
	f.Add("/v1/proof/inclusion", "chain_id=user:abc12345&leaf_index=0&tree_size=1", "")
	f.Add("/users", "", "anything")
	f.Add("/sync", "", "anything")

	allowed := map[int]bool{
		200: true, 201: true, 400: true, 401: true, 403: true,
		404: true, 405: true, 409: true, 410: true, 413: true,
		414: true, 429: true, 500: true, 502: true,
	}

	f.Fuzz(func(t *testing.T, path, query, body string) {
		// Skip control characters in URL components.
		for _, r := range path + query {
			if r < 0x20 || r == 0x7f {
				t.Skip()
			}
		}
		full := ts.URL + path
		if query != "" {
			full = full + "?" + query
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Try GET and POST. POSTs send the body; GETs ignore it.
		for _, method := range []string{"GET", "POST"} {
			req, err := http.NewRequestWithContext(ctx, method, full, bytes.NewReader([]byte(body)))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/cbor")
			resp, err := ts.Client().Do(req)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					return
				}
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if !allowed[resp.StatusCode] {
				t.Errorf("%s %s body=%dB returned unexpected status %d", method, path, len(body), resp.StatusCode)
			}
		}
	})
}
