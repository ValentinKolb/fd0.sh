package simtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentLifecycleCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")

	out, err := alice.run("agent", "status")
	if err != nil {
		t.Fatalf("agent status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "agent: running, unlocked") ||
		!strings.Contains(out, "agent socket: ok") ||
		!strings.Contains(out, "ssh socket: ok") {
		t.Fatalf("agent status missing expected health:\n%s", out)
	}

	oldPID, err := os.ReadFile(filepath.Join(alice.home, "agent.pid"))
	if err != nil {
		t.Fatalf("read old pid: %v", err)
	}
	out, err = alice.run("agent", "restart")
	if err != nil {
		t.Fatalf("agent restart: %v\n%s", err, out)
	}
	if !strings.Contains(out, "agent restarted") ||
		!strings.Contains(out, "vault is locked") {
		t.Fatalf("non-interactive restart should not prompt and should explain locked state:\n%s", out)
	}
	newPID, err := os.ReadFile(filepath.Join(alice.home, "agent.pid"))
	if err != nil {
		t.Fatalf("read new pid: %v\n%s", err, out)
	}
	if strings.TrimSpace(string(oldPID)) == strings.TrimSpace(string(newPID)) {
		t.Fatalf("agent restart did not replace pid: old=%q new=%q\n%s", oldPID, newPID, out)
	}

	out, err = alice.runStdin(alice.pass+"\n", "unlock")
	if err != nil {
		t.Fatalf("unlock after restart: %v\n%s", err, out)
	}
	if !strings.Contains(out, "vault unlocked") {
		t.Fatalf("unlock after restart did not unlock:\n%s", out)
	}

	out, err = alice.run("agent", "stop")
	if err != nil {
		t.Fatalf("agent stop: %v\n%s", err, out)
	}
	if !strings.Contains(out, "agent stopped") {
		t.Fatalf("agent stop did not report stop:\n%s", out)
	}
	out, err = alice.run("agent", "status")
	if err != nil {
		t.Fatalf("agent status after stop: %v\n%s", err, out)
	}
	if !strings.Contains(out, "agent: not running") ||
		!strings.Contains(out, "agent socket: missing") {
		t.Fatalf("agent status after stop missing expected state:\n%s", out)
	}
}
