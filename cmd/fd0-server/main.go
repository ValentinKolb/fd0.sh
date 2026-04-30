// fd0-server is the HTTP backend for fd0. It serves the API in API.md backed
// by a single SQLite file. Configuration is via flags or env vars (FD0_*).
package main

import (
	"log/slog"
	"os"

	"github.com/alecthomas/kong"

	"github.com/valentinkolb/fd0.sh/internal/server"
)

// Default port is 0xFD0 = 4048.
type cli struct {
	Bind    string `name:"bind" help:"Listen address." default:":4048" env:"FD0_BIND"`
	DB      string `name:"db" help:"SQLite path." default:"fd0.db" env:"FD0_DB"`
	MaxBody int64  `name:"max-body" help:"Max request body bytes." default:"8388608" env:"FD0_MAX_BODY"`
	Verbose bool   `name:"verbose" short:"v" help:"Verbose logging." env:"FD0_VERBOSE"`
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
