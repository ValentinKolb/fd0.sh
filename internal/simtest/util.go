package simtest

import (
	"os"
	"testing"
)

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// pathEnv returns the host PATH so the spawned fd0 can find git/etc. if
// it ever needs them; the agent binary is passed explicitly via
// FD0_AGENT_BIN so it does not rely on PATH.
func pathEnv() string {
	return os.Getenv("PATH")
}
