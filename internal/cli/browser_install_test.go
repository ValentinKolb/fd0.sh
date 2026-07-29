package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrowserManifestPathFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		goos string
		want string
	}{
		{
			goos: "darwin",
			want: filepath.Join("/test-home", "Library", "Application Support", "Google", "Chrome",
				"NativeMessagingHosts", "sh.fd0.browser.json"),
		},
		{
			goos: "linux",
			want: filepath.Join("/test-home", ".config", "google-chrome", "NativeMessagingHosts",
				"sh.fd0.browser.json"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			got, err := browserManifestPathFor(tt.goos, "/test-home")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("browserManifestPathFor() = %q, want %q", got, tt.want)
			}
		})
	}
	if _, err := browserManifestPathFor("windows", "/test-home"); err == nil {
		t.Fatal("unsupported platform succeeded")
	}
}

func TestWriteDevelopmentBrowserManifestPreservesForeignFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "sh.fd0.browser.json")
	foreign := []byte(`{"name":"sh.fd0.browser","description":"production"}`)
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeDevelopmentBrowserManifest(path, []byte(`{"owned":true}`)); err == nil ||
		!strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(foreign) {
		t.Fatalf("foreign manifest changed to %q", got)
	}
}

func TestBrowserEnableDisableLifecycleIsIsolatedAndReversible(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	hostPath := filepath.Join(dir, "fd0-browser-host")
	if err := os.WriteFile(hostPath, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "chrome", "NativeMessagingHosts", "sh.fd0.browser.json")

	var output bytes.Buffer
	if err := runBrowserEnable(hostPath, manifestPath, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), manifestPath) {
		t.Fatalf("enable output = %q", output.String())
	}
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest nativeMessagingManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	absoluteHost, err := filepath.Abs(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if !isDevelopmentBrowserManifest(manifest) || manifest.Path != absoluteHost {
		t.Fatalf("manifest = %+v", manifest)
	}
	info, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("manifest mode = %o, want 600", got)
	}

	output.Reset()
	if err := runBrowserDisable(manifestPath, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "removed") {
		t.Fatalf("disable output = %q", output.String())
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("manifest still exists: %v", err)
	}

	output.Reset()
	if err := runBrowserDisable(manifestPath, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "not registered") {
		t.Fatalf("second disable output = %q", output.String())
	}
}

func TestBrowserDisablePreservesForeignFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "sh.fd0.browser.json")
	foreign := []byte(`{"name":"sh.fd0.browser","description":"production","type":"stdio"}`)
	if err := os.WriteFile(manifestPath, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runBrowserDisable(manifestPath, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "refusing") {
		t.Fatalf("err = %v", err)
	}
	got, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(foreign) {
		t.Fatalf("foreign manifest changed to %q", got)
	}
}
