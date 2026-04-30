package agent

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Spawn launches fd0-agent as a detached child process. logPath, when set,
// receives the agent's stdout+stderr so the user's terminal stays clean.
//
// We deliberately do NOT auto-spawn on every CLI call: per the design, an
// inactive agent yields an error "run fd0 unlock first".
func Spawn(binPath, logPath string) error {
	if binPath == "" {
		p, err := exec.LookPath("fd0-agent")
		if err != nil {
			return fmt.Errorf("agent: fd0-agent not in PATH: %w", err)
		}
		binPath = p
	}
	cmd := exec.Command(binPath)
	cmd.Stdin = nil
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("agent: open log: %w", err)
		}
		cmd.Stdout = f
		cmd.Stderr = f
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("agent: spawn: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// WaitReady polls the agent socket until it answers Status or timeout elapses.
func WaitReady(sockPath string, timeout time.Duration) error {
	c := NewClient(sockPath)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.IsRunning() {
			if _, err := c.Status(); err == nil {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("agent: not ready after %s", timeout)
}
