package agent

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Spawn launches fd0-agent as a detached child process. logPath, when set,
// receives the agent's stdout+stderr so the user's terminal stays clean.
//
// We deliberately do NOT auto-spawn on every CLI call: per the design, an
// inactive agent yields an error "run fd0 unlock first".
func Spawn(binPath, logPath string) error {
	return SpawnAs(binPath, logPath, "")
}

// SpawnAs is Spawn plus an ownership marker: startedBy (StartedByDesktop, or
// empty) is placed in the child's environment and echoed back in its status, so
// a supervisor can later recognise the agent it started and — just as
// important — recognise one it did not.
func SpawnAs(binPath, logPath, startedBy string) error {
	if binPath == "" {
		p, err := exec.LookPath("fd0-agent")
		if err != nil {
			return fmt.Errorf("agent: fd0-agent not in PATH: %w", err)
		}
		binPath = p
	}
	cmd := exec.Command(binPath)
	cmd.Stdin = nil
	cmd.Env = agentEnv(startedBy)
	// SECURITY (codex audit 🟡 spawn.go:26): close the log file in
	// the parent after Start() so the parent's FD count stays
	// clean. The child inherits via Stdout/Stderr; the parent's
	// dup is no longer needed.
	var logFile *os.File
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("agent: open log: %w", err)
		}
		cmd.Stdout = f
		cmd.Stderr = f
		logFile = f
	}
	if err := cmd.Start(); err != nil {
		if logFile != nil {
			logFile.Close()
		}
		return fmt.Errorf("agent: spawn: %w", err)
	}
	if logFile != nil {
		_ = logFile.Close() // child still has it via fork
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// agentEnv gives the child the caller's ownership marker — and only that one.
// An inherited marker is dropped first, so an unmarked spawn always produces an
// agent that describes itself as unowned rather than borrowing our ancestry.
func agentEnv(startedBy string) []string {
	current := os.Environ()
	env := make([]string, 0, len(current)+1)
	for _, entry := range current {
		if strings.HasPrefix(entry, StartedByEnv+"=") {
			continue
		}
		env = append(env, entry)
	}
	if startedBy != "" {
		env = append(env, StartedByEnv+"="+startedBy)
	}
	return env
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

// StopByPIDFile terminates the fd0-agent process recorded in pidPath.
func StopByPIDFile(pidPath string, timeout time.Duration) error {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return fmt.Errorf("agent: read PID file %s: %w", pidPath, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("agent: invalid PID file %s", pidPath)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("agent: find pid %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("agent: stop pid %d: %w", pid, err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("agent: kill pid %d after timeout: %w", pid, err)
	}
	return nil
}
