package simtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncRendersSSHConfigWhenEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")
	h.ShareScope(alice, "shared", bob)
	enableSSHInclude(t, bob)

	if out, err := alice.run("key", "add", "deploy", "--scope", "shared"); err != nil {
		t.Fatalf("alice key add: %v\n%s", err, out)
	}
	if out, err := alice.run("ssh", "add", "prod-db", "app@db.internal", "--key", "deploy", "--scope", "shared"); err != nil {
		t.Fatalf("alice ssh add: %v\n%s", err, out)
	}
	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice sync failed:\n%s", out)
	}
	if out, ok := bob.Sync(); !ok {
		t.Fatalf("bob sync failed:\n%s", out)
	}

	out, err := bob.run("ssh", "ls")
	if err != nil {
		t.Fatalf("bob ssh ls: %v\n%s", err, out)
	}
	if !strings.Contains(out, "prod-db") {
		t.Fatalf("bob fd0 inventory missing prod-db after sync:\n%s", out)
	}

	confPath := filepath.Join(bob.hostDir, ".ssh", "fd0.conf")
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read rendered ssh config: %v", err)
	}
	conf := string(data)
	if !strings.Contains(conf, "Host prod-db\n") {
		t.Fatalf("rendered ssh config missing prod-db:\n%s", conf)
	}
	if !strings.Contains(conf, "HostName db.internal\n") {
		t.Fatalf("rendered ssh config missing remote hostname:\n%s", conf)
	}
	pubPath := filepath.Join(bob.hostDir, ".ssh", "fd0.d", "prod-db.pub")
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("expected public-key selector %s: %v", pubPath, err)
	}
}

func enableSSHInclude(t *testing.T, c *Client) {
	t.Helper()
	sshDir := filepath.Join(c.hostDir, ".ssh")
	mustMkdir(t, sshDir)
	confPath := filepath.Join(sshDir, "fd0.conf")
	userCfg := filepath.Join(sshDir, "config")
	mustWrite(t, userCfg, "Include "+confPath+"\n")
}
