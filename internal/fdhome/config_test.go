package fdhome

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetAuthDefaultMethodCreatesConfig(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := SetAuthDefaultMethod(path, "yubikey"); err != nil {
		t.Fatalf("SetAuthDefaultMethod: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Auth.DefaultMethod != "yubikey" {
		t.Fatalf("default_method=%q, want yubikey", cfg.Auth.DefaultMethod)
	}
}

func TestSetAuthDefaultMethodPreservesUnrelatedConfig(t *testing.T) {
	t.Parallel()
	in := `# keep this comment
[sync]
server = "https://example.invalid"

[clipboard]
clear_after_seconds = 7
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetAuthDefaultMethod(path, "passphrase"); err != nil {
		t.Fatalf("SetAuthDefaultMethod: %v", err)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)
	for _, want := range []string{
		"# keep this comment",
		`server = "https://example.invalid"`,
		"clear_after_seconds = 7",
		"[auth]\ndefault_method = \"passphrase\"",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("updated config missing %q:\n%s", want, got)
		}
	}
}

func TestSetAuthDefaultMethodReplacesAndClears(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[auth]\ndefault_method = \"passphrase\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetAuthDefaultMethod(path, "am_01ABC"); err != nil {
		t.Fatalf("replace default: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after replace: %v", err)
	}
	if cfg.Auth.DefaultMethod != "am_01ABC" {
		t.Fatalf("default_method=%q, want am_01ABC", cfg.Auth.DefaultMethod)
	}
	if err := SetAuthDefaultMethod(path, ""); err != nil {
		t.Fatalf("clear default: %v", err)
	}
	cfg, err = LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after clear: %v", err)
	}
	if cfg.Auth.DefaultMethod != "" {
		t.Fatalf("default_method=%q, want empty", cfg.Auth.DefaultMethod)
	}
}
