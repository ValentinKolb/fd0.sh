package agent

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"
)

// SchedulerConfig controls the agent's auto-sync behaviour.
type SchedulerConfig struct {
	// Interval between automatic syncs. Zero disables.
	Interval time.Duration
	// OnUnlock triggers a sync immediately after every successful unlock.
	OnUnlock bool
	// FD0Bin is the absolute path to the `fd0` CLI binary the scheduler
	// shells out to. Empty falls back to PATH lookup at first use.
	FD0Bin string
	// Server is exported as FD0_SERVER for the spawned sync subprocess.
	Server string
	// Home is exported as FD0_HOME so the spawned subprocess targets the
	// agent's identity (not whatever HOME the user happens to have set).
	Home string
}

// Scheduler runs the periodic sync goroutine.
type Scheduler struct {
	cfg SchedulerConfig
	log *slog.Logger

	mu      sync.Mutex
	running bool // a sync is currently in flight; suppresses overlap
}

// NewScheduler returns a non-running scheduler. Call Run to start.
func NewScheduler(cfg SchedulerConfig, log *slog.Logger) *Scheduler {
	if log == nil {
		log = slog.Default()
	}
	return &Scheduler{cfg: cfg, log: log}
}

// Run blocks until ctx is done. Triggers a sync every Interval. Safe to call
// when Interval == 0 (becomes a no-op until ctx done).
func (s *Scheduler) Run(ctx context.Context) {
	if s.cfg.Interval <= 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.TriggerSync("scheduled")
		}
	}
}

// TriggerSync fires a sync subprocess fire-and-forget. reason is logged so
// the user can later tell from agent.log whether it was scheduled or
// triggered by an unlock. Suppresses overlapping triggers.
func (s *Scheduler) TriggerSync(reason string) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		s.log.Debug("agent: sync already running, skip", "reason", reason)
		return
	}
	s.running = true
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}()
		s.runOnce(reason)
	}()
}

func (s *Scheduler) runOnce(reason string) {
	bin := s.cfg.FD0Bin
	if bin == "" {
		p, err := exec.LookPath("fd0")
		if err != nil {
			s.log.Warn("agent: fd0 binary not in PATH; skipping auto-sync", "reason", reason)
			return
		}
		bin = p
	}
	cmd := exec.Command(bin, "sync", "--wait-lock=60s")
	cmd.Env = append(os.Environ(),
		"FD0_HOME="+s.cfg.Home,
		"FD0_SERVER="+s.cfg.Server,
	)
	cmd.Stdin = nil
	cmd.Stdout = nil // captured into the agent log via stderr anyway
	cmd.Stderr = nil
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.log.Warn("agent: auto-sync failed", "reason", reason, "err", err, "out", string(out))
		return
	}
	s.log.Info("agent: auto-sync ok", "reason", reason)
}
