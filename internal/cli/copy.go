package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/atotto/clipboard"

	"github.com/valentinkolb/fd0.sh/internal/tui"
)

// RunCopy implements `fd0 copy [NAME]`.
//
// NAME present  → copy that secret's value, spawn detached clearer, exit.
// NAME absent + TTY → interactive searcher; selection copies + clears.
// NAME absent + non-TTY → error.
func RunCopy(ctx context.Context, scopeID, name string, clearAfter time.Duration) error {
	if name != "" {
		val, err := RunSecretGet(ctx, scopeID, name)
		if err != nil {
			return err
		}
		return doCopy(name, val, clearAfter)
	}
	if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return fmt.Errorf("interactive copy requires a TTY (or pass NAME explicitly)")
	}
	entries, s, err := CollectAllSecrets(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "(no secrets)")
		return nil
	}
	tuiEntries := make([]tui.Entry, len(entries))
	for i, e := range entries {
		tuiEntries[i] = tui.Entry{ScopeID: e.ScopeID, ScopeLabel: e.ScopeLabel, ID: e.ID, Name: e.Name, Type: e.Type}
	}
	sel, err := tui.Run(tuiEntries)
	if err != nil {
		return err
	}
	if sel.Entry.Name == "" {
		return nil
	}
	val, err := s.GetSecretByName(sel.Entry.ScopeID, sel.Entry.Name)
	if err != nil {
		return err
	}
	return doCopy(sel.Entry.Name, val, clearAfter)
}

// doCopy writes val to the clipboard and (if clearAfter > 0) launches a
// detached child process that will clear the clipboard later.
func doCopy(name, val string, clearAfter time.Duration) error {
	if err := clipboard.WriteAll(val); err != nil {
		return fmt.Errorf("clipboard: %w", err)
	}
	if clearAfter > 0 {
		if err := spawnClearer(val, clearAfter); err != nil {
			fmt.Fprintf(os.Stderr, "warn: could not spawn clipboard clearer: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "✓ %s copied (auto-clear in %s)\n", name, clearAfter)
	} else {
		fmt.Fprintf(os.Stderr, "✓ %s copied\n", name)
	}
	return nil
}

// ClipboardClearHelperArgv is the argv[1] sentinel that turns fd0 into a
// detached "clear the clipboard after N seconds" helper. The secret value is
// fed via stdin to keep it out of the process listing.
const ClipboardClearHelperArgv = "_clipboard-clear-helper"

// RunClipboardClearHelper is the main loop of the helper subcommand. It
// reads the value from stdin, sleeps, then clears the clipboard if it still
// holds the same value.
func RunClipboardClearHelper(seconds int) {
	defer os.Exit(0)
	val, err := io.ReadAll(os.Stdin)
	if err != nil || len(val) == 0 {
		return
	}
	time.Sleep(time.Duration(seconds) * time.Second)
	cur, err := clipboard.ReadAll()
	if err != nil {
		return
	}
	if cur == string(val) {
		_ = clipboard.WriteAll("")
	}
}

func spawnClearer(val string, d time.Duration) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	secs := int(d.Seconds())
	if secs <= 0 {
		secs = 1
	}
	cmd := exec.Command(self, ClipboardClearHelperArgv, strconv.Itoa(secs))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_, _ = stdin.Write([]byte(val))
		_ = stdin.Close()
	}()
	// Detach: don't wait.
	go func() { _ = cmd.Wait() }()
	return nil
}

