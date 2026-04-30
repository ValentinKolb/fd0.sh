// fd0-agent is the local key-holding daemon. It listens on
// $FD0_HOME/agent.sock (default ~/.fd0/agent.sock) and serves five operations
// to same-UID clients: status, unlock, lock, sign, open_seal, re_seal.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/awnumar/memguard"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

// version is overwritten by goreleaser via `-ldflags="-X main.version=..."`.
var version = "dev"

type cli struct {
	IdleTimeout string `name:"idle-timeout" help:"Lock after idle." default:"5m" env:"FD0_AGENT_IDLE"`
	MaxLifetime string `name:"max-lifetime" help:"Lock after max lifetime." default:"8h" env:"FD0_AGENT_MAX_LIFETIME"`
	Verbose     bool   `name:"verbose" short:"v" help:"Verbose logging." env:"FD0_AGENT_VERBOSE"`
	Version     bool   `name:"version" help:"Print version and exit."`
}

func main() {
	memguard.CatchInterrupt() // Wipe on SIGINT/SIGTERM.
	defer memguard.Purge()
	var c cli
	kong.Parse(&c, kong.Name("fd0-agent"))
	if c.Version {
		fmt.Printf("fd0-agent %s\n", version)
		return
	}
	level := slog.LevelInfo
	if c.Verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	idle, err := time.ParseDuration(c.IdleTimeout)
	if err != nil {
		log.Error("bad idle-timeout", "err", err)
		os.Exit(2)
	}
	maxLife, err := time.ParseDuration(c.MaxLifetime)
	if err != nil {
		log.Error("bad max-lifetime", "err", err)
		os.Exit(2)
	}

	paths, err := fdhome.Resolve()
	if err != nil {
		log.Error("resolve home", "err", err)
		os.Exit(1)
	}
	if err := paths.EnsureDirs(); err != nil {
		log.Error("ensure dirs", "err", err)
		os.Exit(1)
	}
	// Load ~/.fd0/config.toml so the agent can run periodic auto-sync.
	cfg, err := fdhome.LoadConfig(paths.Config)
	if err != nil {
		log.Warn("config: load failed, continuing with defaults", "err", err)
	}
	server := cfg.Sync.Server
	if server == "" {
		server = os.Getenv("FD0_SERVER")
	}
	var sched *agent.Scheduler
	onUnlock := cfg.Sync.OnUnlockEnabled()
	if interval := cfg.SyncIntervalDuration(); interval > 0 || onUnlock {
		sched = agent.NewScheduler(agent.SchedulerConfig{
			Interval: interval,
			OnUnlock: onUnlock,
			FD0Bin:   os.Getenv("FD0_BIN"),
			Server:   server,
			Home:     paths.Home,
		}, log)
		if interval > 0 {
			log.Info("agent: auto-sync enabled", "interval", interval, "server", server)
		}
		if onUnlock {
			log.Info("agent: on-unlock sync enabled")
		}
	}
	srv, err := agent.Listen(paths, agent.Config{
		IdleTimeout: idle, MaxLifetime: maxLife, Logger: log, Scheduler: sched,
	})
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("agent: shutdown")
		cancel()
		srv.Close()
		_ = memguard.Purge
	}()

	log.Info("fd0-agent listening", "sock", paths.AgentSock)
	if err := srv.Serve(ctx); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
