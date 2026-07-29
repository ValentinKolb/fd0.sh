package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/passitem"
)

func TestParseBrowserTargetRequiresHTTPS(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"",
		"example.com",
		"http://example.com",
		"file:///tmp/login",
		"https://user:pass@example.com",
		"https://example.com/login",
		"https://example.com/?next=login",
		"https://example.com/#login",
		"https://example.com:",
		"https://example.com:0",
		"https://example.com:65536",
	} {
		if _, err := parseBrowserTarget(raw); err == nil {
			t.Fatalf("parseBrowserTarget(%q) succeeded", raw)
		}
	}
}

func TestParseBrowserTargetCanonicalizesOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw  string
		want browserTarget
	}{
		{raw: "https://EXAMPLE.com/", want: browserTarget{host: "example.com", port: "443"}},
		{raw: "https://bücher.example:0443", want: browserTarget{host: "xn--bcher-kva.example", port: "443"}},
		{raw: "https://[2001:db8::1]:8443", want: browserTarget{host: "2001:db8::1", port: "8443"}},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parseBrowserTarget(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("parseBrowserTarget(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestBrowserItemMatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		stored string
		target string
		want   bool
	}{
		{name: "exact", stored: "https://accounts.example.com/login", target: "https://accounts.example.com", want: true},
		{name: "scheme less stored", stored: "example.com", target: "https://login.example.com", want: true},
		{name: "parent domain", stored: "https://example.com", target: "https://login.example.com/", want: true},
		{name: "sibling rejected", stored: "https://accounts.example.com", target: "https://mail.example.com/", want: false},
		{name: "suffix confusion rejected", stored: "https://example.com", target: "https://notexample.com/", want: false},
		{name: "public suffix rejected", stored: "https://com", target: "https://example.com/", want: false},
		{name: "different port rejected", stored: "https://example.com:8443", target: "https://example.com/", want: false},
		{name: "http stored rejected", stored: "http://example.com", target: "https://example.com/", want: false},
		{name: "stored credentials rejected", stored: "https://user@example.com", target: "https://example.com/", want: false},
		{name: "idn", stored: "https://bücher.example", target: "https://xn--bcher-kva.example/", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := parseBrowserTarget(tt.target)
			if err != nil {
				t.Fatal(err)
			}
			item := passitem.New("login", []string{tt.stored})
			if got := browserItemMatches(item, target); got != tt.want {
				t.Fatalf("browserItemMatches(%q, %q) = %v, want %v", tt.stored, tt.target, got, tt.want)
			}
		})
	}
}

func TestBrowserFieldsPreferNamedLoginValues(t *testing.T) {
	t.Parallel()
	text := func(name, value string) passitem.Field {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return passitem.Field{Type: passitem.FieldText, Name: name, Value: raw}
	}
	secret := func(name, value string) passitem.Field {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return passitem.Field{Type: passitem.FieldSecret, Name: name, Value: raw}
	}
	item := passitem.New("login", []string{"https://example.com"})
	item.Fields = []passitem.Field{
		text(passitem.NotesFieldName, "not a username"),
		{Type: passitem.FieldSection, Name: "Login", Fields: []passitem.Field{
			text("email address", "user@example.com"),
			secret("password", "correct horse"),
		}},
	}
	if got, ok := browserUsername(item); !ok || got != "user@example.com" {
		t.Fatalf("browserUsername() = %q, %v", got, ok)
	}
	if got, ok := browserPassword(item); !ok || got != "correct horse" {
		t.Fatalf("browserPassword() = %q, %v", got, ok)
	}
}

func TestBrowserCredentialIDRoundTrip(t *testing.T) {
	t.Parallel()
	id := encodeBrowserCredentialID("s_example", "pass:GitHub")
	scope, name, err := decodeBrowserCredentialID(id)
	if err != nil {
		t.Fatal(err)
	}
	if scope != "s_example" || name != "pass:GitHub" {
		t.Fatalf("decodeBrowserCredentialID() = %q, %q", scope, name)
	}
	for _, invalid := range []string{"", "v2.abc", "v1.not-base64", "v1.", "v1." + strings.Repeat("a", 1024)} {
		if _, _, err := decodeBrowserCredentialID(invalid); err == nil {
			t.Fatalf("decodeBrowserCredentialID(%q) succeeded", invalid)
		}
	}
}

func TestBrowserCredentialMetadataJSONIncludesUsernameButNoSecret(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(BrowserCredential{
		ID:       "opaque",
		Title:    "Example",
		Username: "user@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(payload)
	if got != `{"id":"opaque","title":"Example","username":"user@example.com"}` {
		t.Fatalf("BrowserCredential JSON = %s", got)
	}
	if strings.Contains(got, "password") {
		t.Fatalf("BrowserCredential JSON contains secret metadata: %s", got)
	}
}
