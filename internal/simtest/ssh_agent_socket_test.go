package simtest

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDoctorReportsRefusingSSHAgentSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")

	staleSock := filepath.Join(h.dir, "stale-ssh.sock")
	leaveStaleUnixSocket(t, staleSock)
	if _, err := os.Stat(staleSock); err != nil {
		t.Fatalf("stale socket file missing: %v", err)
	}

	cmd := exec.Command(h.fd0Bin, "doctor")
	cmd.Env = replaceEnv(alice.env(), "FD0_SSH_SOCK", staleSock)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("doctor should fail on refusing ssh-agent socket:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "ssh agent socket") ||
		!strings.Contains(text, "fd0 SSH agent socket unavailable") ||
		!strings.Contains(text, staleSock) ||
		!strings.Contains(text, "fd0 agent restart") {
		t.Fatalf("doctor did not report stale ssh-agent socket clearly:\n%s", text)
	}
}

func TestUnlockRepairsRefusingSSHAgentSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")

	staleSock := filepath.Join(h.dir, "repair-ssh.sock")
	leaveStaleUnixSocket(t, staleSock)

	cmd := exec.Command(h.fd0Bin, "unlock")
	cmd.Env = replaceEnv(alice.env(), "FD0_SSH_SOCK", staleSock)
	cmd.Stdin = strings.NewReader(alice.pass + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unlock should repair stale ssh-agent socket: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "repairing fd0 SSH agent socket") ||
		!strings.Contains(text, "vault unlocked") {
		t.Fatalf("unlock did not report repair + unlock:\n%s", text)
	}
	if err := dialUnix(staleSock); err != nil {
		t.Fatalf("repaired ssh-agent socket is not reachable: %v\n%s", err, out)
	}
}

func leaveStaleUnixSocket(t *testing.T, path string) {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		t.Fatalf("bind stale socket: %v", err)
	}
}

func dialUnix(path string) error {
	c, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return err
	}
	return c.Close()
}

func replaceEnv(env []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env)+1)
	replaced := false
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			out = append(out, prefix+value)
			replaced = true
			continue
		}
		out = append(out, item)
	}
	if !replaced {
		out = append(out, prefix+value)
	}
	return out
}
