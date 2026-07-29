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
		want []string
	}{
		{
			goos: "darwin",
			want: []string{
				filepath.Join("/test-home", "Library", "Application Support", "Google", "Chrome",
					"NativeMessagingHosts", "sh.fd0.browser.json"),
				filepath.Join("/test-home", "Library", "Application Support", "Chromium",
					"NativeMessagingHosts", "sh.fd0.browser.json"),
			},
		},
		{
			goos: "linux",
			want: []string{
				filepath.Join("/test-home", ".config", "google-chrome", "NativeMessagingHosts",
					"sh.fd0.browser.json"),
				filepath.Join("/test-home", ".config", "chromium", "NativeMessagingHosts",
					"sh.fd0.browser.json"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			got, err := browserManifestPathsFor(tt.goos, "/test-home")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Fatalf("browserManifestPathsFor() = %q, want %q", got, tt.want)
			}
		})
	}
	if _, err := browserManifestPathsFor("windows", "/test-home"); err == nil {
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

func TestBrowserManifestUpdatesPreflightEveryBrowser(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	oldHost := filepath.Join(dir, "old-fd0-browser-host")
	newHost := filepath.Join(dir, "new-fd0-browser-host")
	for _, path := range []string{oldHost, newHost} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	firstPath := filepath.Join(dir, "chrome", "sh.fd0.browser.json")
	secondPath := filepath.Join(dir, "chromium", "sh.fd0.browser.json")
	owned, err := json.Marshal(nativeMessagingManifest{
		Name:           "sh.fd0.browser",
		Description:    developmentBrowserManifestDescription,
		Path:           oldHost,
		Type:           "stdio",
		AllowedOrigins: []string{"chrome-extension://flkmmllfacmjnhjgdfliahdkhfjmdoec/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(firstPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstPath, owned, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(secondPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte(`{"name":"foreign"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runBrowserEnableAll(newHost, []string{firstPath, secondPath}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "refusing") {
		t.Fatalf("enable err = %v", err)
	}
	got, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(owned) {
		t.Fatalf("first manifest changed before second conflict: %s", got)
	}

	if err := runBrowserDisableAll([]string{firstPath, secondPath}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "refusing") {
		t.Fatalf("disable err = %v", err)
	}
	got, err = os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(owned) {
		t.Fatalf("first manifest removed before second conflict: %s", got)
	}
}

func TestRestoreBrowserManifestSnapshotsRestoresOnlyOwnedState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	existingPath := filepath.Join(dir, "chrome", "sh.fd0.browser.json")
	missingPath := filepath.Join(dir, "chromium", "sh.fd0.browser.json")
	if err := os.MkdirAll(filepath.Dir(existingPath), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"owned":"original"}`)
	if err := os.WriteFile(existingPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	snapshots := []browserManifestSnapshot{
		{path: existingPath, payload: original, mode: 0o640, exists: true},
		{path: missingPath, mode: 0o600, exists: false},
	}
	if err := os.WriteFile(existingPath, []byte(`{"owned":"changed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(missingPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(missingPath, []byte(`{"owned":"created"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreBrowserManifestSnapshots(snapshots); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(existingPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("restored existing manifest = %s", got)
	}
	if _, err := os.Stat(missingPath); !os.IsNotExist(err) {
		t.Fatalf("created manifest survived rollback: %v", err)
	}
}

func TestResolveBrowserHostUsesDesktopManagedPath(t *testing.T) {
	dir := t.TempDir()
	hostPath := filepath.Join(dir, "fd0-browser-host")
	if err := os.WriteFile(hostPath, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FD0_BROWSER_HOST_BIN", hostPath)

	got, err := resolveBrowserHostPath("")
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.Abs(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("resolveBrowserHostPath() = %q, want %q", got, want)
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
