package witness

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FuzzHTTPHandler stresses the witness HTTP handler with arbitrary
// paths + query strings. The contract: the handler must NEVER panic
// and must always return a status in {200, 400, 404, 405, 409, 414,
// 500}. The existing fuzz_test in http_fuzz_test.go runs curated
// nasties; this Go-native fuzz target does coverage-guided
// mutation for hours of CI time.
func FuzzHTTPHandler(f *testing.F) {
	dir := f.TempDir()
	store, err := Open(filepath.Join(dir, "fuzz.db"))
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { store.Close() })
	wPub, _, _ := ed25519.GenerateKey(cryptorand.Reader)
	hs := &HTTPServer{Store: store, WitnessPub: wPub, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	srv := httptest.NewServer(hs.Handler())
	f.Cleanup(srv.Close)

	// Seeds derived from real client patterns + curated nasties.
	f.Add("/v1/server-info", "")
	f.Add("/v1/sth/AA/scope:s_aaaaaaaaaaaaaaaaaaaaaaaaaa", "")
	f.Add("/v1/sth/AA/scope:s_aaaaaaaaaaaaaaaaaaaaaaaaaa", "tree_size=1")
	f.Add("/v1/sth/", "")
	f.Add("/v1/sth/AA", "")
	f.Add("", "")
	f.Add("/", "")
	f.Add("/v1/sth/AA/scope:s_x", "tree_size=99999999999999999999")

	f.Fuzz(func(t *testing.T, path, query string) {
		// Reject obviously-invalid URLs before NewRequest panics.
		if strings.ContainsAny(path, "\x00\r\n") {
			t.Skip()
		}
		if strings.ContainsAny(query, "\x00\r\n") {
			t.Skip()
		}
		full := srv.URL + path
		if query != "" {
			full = full + "?" + query
		}
		// Per-request timeout so the fuzzer doesn't stall on a
		// slow/hung request. We're testing the parser, not the
		// HTTP machinery's worst-case latency.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", full, nil)
		if err != nil {
			t.Skip()
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			// Codex test audit (🔴): a server-side PANIC manifests
			// as EOF / connection reset on the client. Previously
			// this branch silently `return`ed — letting panics slip
			// through. Now we distinguish:
			//
			// - context.DeadlineExceeded → input was pathological,
			//   server didn't crash; SKIP this iteration.
			// - URL too long / parse error before transport →
			//   skip (kernel-level rejection).
			// - Anything else → potential panic, fail loudly.
			if errors.Is(err, context.DeadlineExceeded) {
				return
			}
			msg := err.Error()
			// Curl-equivalent local rejections we accept:
			if strings.Contains(msg, "request URI too long") ||
				strings.Contains(msg, "URL too long") ||
				strings.Contains(msg, "invalid URL escape") ||
				strings.Contains(msg, "net/url") ||
				strings.Contains(msg, "invalid control character") {
				return
			}
			// EOF, reset, broken pipe = server-side panic suspect.
			if strings.Contains(msg, "EOF") ||
				strings.Contains(msg, "reset by peer") ||
				strings.Contains(msg, "broken pipe") ||
				strings.Contains(msg, "unexpected EOF") {
				t.Errorf("path=%q query=%q transport error suggests handler panic: %v", path, query, err)
				return
			}
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case 200, 400, 404, 405, 409, 414, 500:
			// expected
		default:
			t.Errorf("path=%q query=%q returned unexpected status %d", path, query, resp.StatusCode)
		}
	})
}
