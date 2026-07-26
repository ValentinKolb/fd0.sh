package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRunDesktopManagedAgentCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is POSIX-only")
	}
	root := t.TempDir()
	app := filepath.Join(root, "fd0-desktop")
	output := filepath.Join(root, "args")
	script := "#!/bin/sh\nprintf '%s' \"$1\" > \"$OUT\"\n"
	if err := os.WriteFile(app, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FD0_DESKTOP_MANAGED", "1")
	t.Setenv("FD0_DESKTOP_APP", app)
	t.Setenv("OUT", output)

	handled, err := runDesktopManagedAgentCommand(context.Background(), "restart")
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("desktop-managed command was not handled")
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "--fd0-agent-service-restart" {
		t.Fatalf("arg=%q", got)
	}
}

func TestRunDesktopManagedAgentCommandLeavesCustomHomeAlone(t *testing.T) {
	t.Setenv("FD0_DESKTOP_MANAGED", "1")
	t.Setenv("FD0_DESKTOP_APP", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("FD0_HOME", t.TempDir())

	handled, err := runDesktopManagedAgentCommand(context.Background(), "stop")
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("custom FD0_HOME must keep the regular isolated lifecycle")
	}
}
