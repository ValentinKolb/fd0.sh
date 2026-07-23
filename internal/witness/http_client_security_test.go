package witness

import (
	"io"
	"log/slog"
	"testing"
)

func TestWitnessHTTPClientRejectsRedirects(t *testing.T) {
	w := New(nil, Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if w.HTTP.CheckRedirect == nil {
		t.Fatal("witness HTTP client follows redirects")
	}
}
