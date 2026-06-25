package simtest

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncRefreshesEnabledKubeConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")
	h.ShareScope(alice, "shared", bob)

	if out, err := bob.run("kube", "enable", "--merge"); err != nil {
		t.Fatalf("bob kube enable: %v\n%s", err, out)
	}
	ca := base64.StdEncoding.EncodeToString([]byte("ca"))
	if out, err := alice.run("kube", "add", "prod", "--server", "https://10.0.0.1:6443", "--ca", ca, "--token", "tok", "--scope", "shared"); err != nil {
		t.Fatalf("alice kube add: %v\n%s", err, out)
	}
	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice sync failed:\n%s", out)
	}
	if out, ok := bob.Sync(); !ok {
		t.Fatalf("bob sync failed:\n%s", out)
	}

	assertFileContains(t, filepath.Join(bob.hostDir, ".kube", "config.fd0"), "prod", "https://10.0.0.1:6443")
	assertFileContains(t, filepath.Join(bob.hostDir, ".kube", "config"), "prod", "https://10.0.0.1:6443")
}

func TestSyncRefreshesEnabledTalosConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")
	h.ShareScope(alice, "shared", bob)

	if out, err := bob.run("talos", "enable", "--merge"); err != nil {
		t.Fatalf("bob talos enable: %v\n%s", err, out)
	}
	cert := base64.StdEncoding.EncodeToString([]byte("cert"))
	if out, err := alice.run("talos", "add", "prod", "--endpoint", "10.0.0.2:50000", "--ca", cert, "--crt", cert, "--key", cert, "--scope", "shared"); err != nil {
		t.Fatalf("alice talos add: %v\n%s", err, out)
	}
	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice sync failed:\n%s", out)
	}
	if out, ok := bob.Sync(); !ok {
		t.Fatalf("bob sync failed:\n%s", out)
	}

	assertFileContains(t, filepath.Join(bob.hostDir, ".talos", "config.fd0"), "prod", "10.0.0.2:50000")
	assertFileContains(t, filepath.Join(bob.hostDir, ".talos", "config"), "prod", "10.0.0.2:50000")
}

func TestKubeEnableAutoMergesLocalChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	h.ShareScope(alice, "shared")

	if out, err := alice.run("kube", "enable", "--merge"); err != nil {
		t.Fatalf("alice kube enable: %v\n%s", err, out)
	}
	ca := base64.StdEncoding.EncodeToString([]byte("ca"))
	if out, err := alice.run("kube", "add", "local", "--server", "https://10.0.0.3:6443", "--ca", ca, "--token", "tok", "--scope", "shared"); err != nil {
		t.Fatalf("alice kube add: %v\n%s", err, out)
	}

	assertFileContains(t, filepath.Join(alice.hostDir, ".kube", "config.fd0"), "local", "https://10.0.0.3:6443")
	assertFileContains(t, filepath.Join(alice.hostDir, ".kube", "config"), "local", "https://10.0.0.3:6443")
}

func TestTalosEnableAutoMergesLocalChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	h.ShareScope(alice, "shared")

	if out, err := alice.run("talos", "enable", "--merge"); err != nil {
		t.Fatalf("alice talos enable: %v\n%s", err, out)
	}
	cert := base64.StdEncoding.EncodeToString([]byte("cert"))
	if out, err := alice.run("talos", "add", "local", "--endpoint", "10.0.0.4:50000", "--ca", cert, "--crt", cert, "--key", cert, "--scope", "shared"); err != nil {
		t.Fatalf("alice talos add: %v\n%s", err, out)
	}

	assertFileContains(t, filepath.Join(alice.hostDir, ".talos", "config.fd0"), "local", "10.0.0.4:50000")
	assertFileContains(t, filepath.Join(alice.hostDir, ".talos", "config"), "local", "10.0.0.4:50000")
}

func assertFileContains(t *testing.T, path string, needles ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := string(data)
	for _, needle := range needles {
		if !strings.Contains(s, needle) {
			t.Fatalf("%s missing %q:\n%s", path, needle, s)
		}
	}
}
