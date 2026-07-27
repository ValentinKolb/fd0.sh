package simtest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestInteractiveVaultCommandAutoUnlocks(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}
	h := New(t, 1)
	alice := h.AddClient("alice")
	if out, err := alice.run("lock"); err != nil {
		t.Fatalf("lock: %v\n%s", err, out)
	}

	out, err := runTTY(alice, alice.pass+"\n", "ls")
	if err != nil {
		t.Fatalf("interactive ls should prompt, unlock, and run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Passphrase:") {
		t.Fatalf("interactive ls did not prompt for unlock:\n%s", out)
	}
	if strings.Contains(out, "agent is locked") || strings.Contains(out, "agent is not running") {
		t.Fatalf("interactive ls returned the old locked-agent error:\n%s", out)
	}
	status, err := alice.run("status")
	if err != nil {
		t.Fatalf("status after auto-unlock: %v\n%s", err, status)
	}
	if !strings.Contains(status, "unlocked") {
		t.Fatalf("auto-unlock did not leave the agent unlocked:\n%s", status)
	}
}

func TestUnlockAlreadyUnlockedDoesNotPrompt(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}
	h := New(t, 1)
	alice := h.AddClient("alice")
	status, err := alice.run("status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, status)
	}
	if !strings.Contains(status, "unlocked") {
		t.Fatalf("fixture should start unlocked:\n%s", status)
	}
	out, err := runTTYNoInput(alice, "unlock")
	if err != nil {
		t.Fatalf("unlock while already unlocked should be a no-op: %v\n%s", err, out)
	}
	if strings.Contains(out, "Passphrase:") {
		t.Fatalf("already-unlocked fd0 unlock prompted:\n%s", out)
	}
	if !strings.Contains(out, "already unlocked") {
		t.Fatalf("already-unlocked fd0 unlock should explain no-op:\n%s", out)
	}
}

func TestNonInteractiveVaultCommandDoesNotAutoUnlock(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}
	h := New(t, 1)
	alice := h.AddClient("alice")
	if out, err := alice.run("lock"); err != nil {
		t.Fatalf("lock: %v\n%s", err, out)
	}

	out, err := alice.run("ls")
	if err == nil {
		t.Fatalf("non-interactive ls should still fail while locked:\n%s", out)
	}
	if strings.Contains(out, "Passphrase:") {
		t.Fatalf("non-interactive ls unexpectedly prompted:\n%s", out)
	}
	if !strings.Contains(out, "fd0 agent is locked") && !strings.Contains(out, "fd0 agent is not running") {
		t.Fatalf("non-interactive ls returned an unexpected error:\n%s", out)
	}
}

func TestInteractiveDoctorDoesNotAutoUnlock(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}
	h := New(t, 1)
	alice := h.AddClient("alice")
	if out, err := alice.run("lock"); err != nil {
		t.Fatalf("lock: %v\n%s", err, out)
	}

	out, err := runTTYNoInput(alice, "doctor")
	if err == nil {
		t.Fatalf("doctor should require an explicit unlock while locked:\n%s", out)
	}
	if strings.Contains(out, "Passphrase:") {
		t.Fatalf("doctor unexpectedly prompted for credentials:\n%s", out)
	}
	if !strings.Contains(out, "fd0 agent is locked") {
		t.Fatalf("doctor returned an unexpected locked-agent error:\n%s", out)
	}
}

func TestEmptyHomePointsToInit(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}
	h := New(t, 1)
	home := filepath.Join(h.dir, "fresh")
	hostHome := filepath.Join(h.dir, "freshh")
	mustMkdir(t, home)
	mustMkdir(t, hostHome)

	cmd := exec.Command(h.fd0Bin, "ls")
	cmd.Env = []string{
		"FD0_HOME=" + home,
		"HOME=" + hostHome,
		"FD0_SSH_SOCK=" + filepath.Join(h.dir, "fresh.s"),
		"FD0_AGENT_BIN=" + h.agentBin,
		"FD0_AUTO_PIN=1",
		"PATH=" + pathEnv(),
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("fresh home ls should fail:\n%s", out)
	}
	if !strings.Contains(string(out), "fd0 init") {
		t.Fatalf("fresh home error should point to fd0 init:\n%s", out)
	}
}

func TestInteractiveRemovePromptsAndCanAbort(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}
	h := New(t, 1)
	alice := h.AddClient("alice")
	if out, err := alice.run("scope", "create", "--label", "shared"); err != nil {
		t.Fatalf("scope create: %v\n%s", err, out)
	}
	if out, err := alice.run("set", "TOKEN", "secret", "--scope", "shared"); err != nil {
		t.Fatalf("set: %v\n%s", err, out)
	}

	out, err := runTTYAfter(alice, "Remove secret", "n\n", "rm", "TOKEN", "--scope", "shared")
	if err == nil {
		t.Fatalf("interactive rm should abort when declined:\n%s", out)
	}
	if !strings.Contains(out, "aborted") {
		t.Fatalf("interactive rm did not report abort:\n%s", out)
	}
	if got, ok := alice.Get("shared", "TOKEN"); !ok || got != "secret" {
		t.Fatalf("declined rm removed secret, got ok=%v value=%q", ok, got)
	}
}

func runTTY(c *Client, stdin string, args ...string) (string, error) {
	return runTTYAfter(c, "Passphrase:", stdin, args...)
}

func runTTYNoInput(c *Client, args ...string) (string, error) {
	c.h.t.Helper()
	c.h.mu.Lock()
	defer c.h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.h.fd0Bin, args...)
	cmd.Env = c.env()
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, ptmx)
		close(done)
	}()
	err = cmd.Wait()
	_ = ptmx.Close()
	<-done
	if ctx.Err() != nil {
		return buf.String(), ctx.Err()
	}
	return buf.String(), err
}

func runTTYAfter(c *Client, prompt, stdin string, args ...string) (string, error) {
	c.h.t.Helper()
	c.h.mu.Lock()
	defer c.h.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.h.fd0Bin, args...)
	cmd.Env = c.env()
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return "", err
	}
	out := newTTYOutput(prompt)
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(out, ptmx)
		close(done)
	}()
	if stdin != "" {
		select {
		case <-out.seen:
			_, _ = ptmx.Write([]byte(stdin))
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			_ = ptmx.Close()
			<-done
			return out.String(), errors.New("timed out waiting for prompt")
		}
	}
	err = cmd.Wait()
	_ = ptmx.Close()
	<-done
	if ctx.Err() != nil {
		return out.String(), ctx.Err()
	}
	return out.String(), err
}

type ttyOutput struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	prompt string
	seen   chan struct{}
	once   sync.Once
}

func newTTYOutput(prompt string) *ttyOutput {
	return &ttyOutput{prompt: prompt, seen: make(chan struct{})}
}

func (o *ttyOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	n, err := o.buf.Write(p)
	sawPrompt := strings.Contains(o.buf.String(), o.prompt)
	o.mu.Unlock()
	if sawPrompt {
		o.once.Do(func() { close(o.seen) })
	}
	return n, err
}

func (o *ttyOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}
