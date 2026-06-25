package simtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
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
		!strings.Contains(text, staleSock) {
		t.Fatalf("doctor did not report stale ssh-agent socket clearly:\n%s", text)
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
