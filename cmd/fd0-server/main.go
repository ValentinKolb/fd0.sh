// fd0-server is the HTTP backend for fd0. It serves the API in API.md backed
// by a single SQLite file. Configuration is via flags or env vars (FD0_*).
package main

import (
	"log/slog"
	"os"

	"github.com/alecthomas/kong"

	"github.com/valentinkolb/fd0.sh/internal/server"
	"github.com/valentinkolb/fd0.sh/internal/server/ratelimit"
)

// Default port is 0xFD0 = 4048.
type cli struct {
	Bind    string `name:"bind" help:"Listen address." default:":4048" env:"FD0_BIND"`
	DB      string `name:"db" help:"SQLite path." default:"fd0.db" env:"FD0_DB"`
	MaxBody int64  `name:"max-body" help:"Max request body bytes." default:"8388608" env:"FD0_MAX_BODY"`
	Verbose bool   `name:"verbose" short:"v" help:"Verbose logging." env:"FD0_VERBOSE"`

	// Rate limiting. Single-instance only. Negative values disable that
	// specific class; --no-ratelimit (FD0_RATELIMIT=off) disables all.
	NoRateLimit          bool `name:"no-ratelimit" help:"Disable rate limiting entirely." env:"FD0_RATELIMIT_OFF"`
	WritesPerMin         int  `name:"writes-per-min" help:"Authenticated writes/min per identity." default:"60" env:"FD0_RATELIMIT_WRITES_PER_MIN"`
	BytesPerMin          int  `name:"bytes-per-min" help:"Aggregate request body bytes/min per identity." default:"33554432" env:"FD0_RATELIMIT_BYTES_PER_MIN"`
	RegisterPerHour      int  `name:"register-per-hour" help:"POST /users registrations/hour per IP." default:"5" env:"FD0_RATELIMIT_REGISTER_PER_HOUR"`
}

// version is overwritten by goreleaser via `-ldflags="-X main.version=..."`.
var version = "dev"

func main() {
	var c cli
	kong.Parse(&c,
		kong.Name("fd0-server"),
		kong.Description("fd0 sync server (port 0xFD0 = 4048)"),
		kong.UsageOnError(),
	)
	level := slog.LevelInfo
	if c.Verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	srv, err := server.New(server.Config{
		Bind:     c.Bind,
		DBPath:   c.DB,
		Version:  version,
		MaxBytes: c.MaxBody,
		Logger:   log,

		RateLimitDisabled: c.NoRateLimit,
		RateLimit: ratelimit.Config{
			IdentityWritesPerMin: c.WritesPerMin,
			IdentityBytesPerMin:  c.BytesPerMin,
			RegisterPerHour:      c.RegisterPerHour,
		},
	})
	if err != nil {
		log.Error("init", "err", err)
		os.Exit(1)
	}
	defer srv.Close()
	if err := server.Run(srv); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}
