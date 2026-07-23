package metrics

import (
	"net/http"
	"net/url"
	"testing"
)

func TestOpLabelBoundsUntrustedPathsAndMethods(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: http.MethodGet, path: "/health", want: "GET /health"},
		{method: http.MethodPost, path: "/v1/users/random/events", want: "POST /v1/users/*"},
		{method: http.MethodGet, path: "/attacker/controlled", want: "GET /*"},
		{method: "ARBITRARY", path: "/another/value", want: "OTHER /*"},
	}
	for _, tt := range tests {
		req := &http.Request{Method: tt.method, URL: &url.URL{Path: tt.path}}
		if got := opLabel(req); got != tt.want {
			t.Fatalf("%s %s: got %q want %q", tt.method, tt.path, got, tt.want)
		}
	}
}
