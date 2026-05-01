// fd0-witness is a passive transparency-log archiver per TRANSLOG.md
// §8. It polls one or more fd0-server instances for current STHs,
// verifies them against operator-pinned pubkeys, archives every STH
// in a local SQLite, and flags equivocation when the same
// (server, chain, tree_size) shows up with two distinct root_hash
// values.
//
// Designed to run as a long-lived daemon. Operators are expected to
// publish their archive (or a derived alert feed) so other clients
// of the same servers can cross-correlate. v1.0 is observation only;
// future versions add a witness-cosign endpoint clients can require.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/alecthomas/kong"

	"github.com/valentinkolb/fd0.sh/internal/witness"
)

type cli struct {
	Config  string `name:"config" short:"c" help:"Witness config TOML." default:"/etc/fd0-witness.toml" env:"FD0_WITNESS_CONFIG"`
	DB      string `name:"db" help:"Witness archive SQLite path." default:"/var/lib/fd0-witness/witness.db" env:"FD0_WITNESS_DB"`
	Verbose bool   `name:"verbose" short:"v" help:"Verbose logging."`

	Run    runCmd    `cmd:"" default:"1" help:"Start the polling daemon (default)."`
	Status statusCmd `cmd:"" help:"Print archive summary (per-chain max tree_size, equivocation flags)."`
	Verify verifyCmd `cmd:"" help:"Re-verify every archived STH signature + scan for equivocations."`
}

type runCmd struct{}
type statusCmd struct{}
type verifyCmd struct{}

// version is overwritten by goreleaser via `-ldflags="-X main.version=..."`.
var version = "dev"

func main() {
	var c cli
	kctx := kong.Parse(&c,
		kong.Name("fd0-witness"),
		kong.Description("fd0 transparency-log witness (TRANSLOG.md §8)"),
		kong.UsageOnError(),
		kong.Vars{"version": version},
	)
	level := slog.LevelInfo
	if c.Verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := witness.LoadConfig(c.Config)
	if err != nil {
		log.Error("load config", "path", c.Config, "err", err)
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(c.DB), 0o700); err != nil {
		log.Error("mkdir db dir", "err", err)
		os.Exit(2)
	}
	store, err := witness.Open(c.DB)
	if err != nil {
		log.Error("open db", "path", c.DB, "err", err)
		os.Exit(2)
	}
	defer store.Close()

	w := witness.New(store, cfg, log)

	switch kctx.Command() {
	case "run":
		runDaemon(w, log)
	case "status":
		runStatus(w)
	case "verify":
		runVerify(w, log)
	default:
		runDaemon(w, log)
	}
}

func runDaemon(w *witness.Witness, log *slog.Logger) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := w.Run(ctx); err != nil && err != context.Canceled {
		log.Error("witness run", "err", err)
		os.Exit(1)
	}
}

func runStatus(w *witness.Witness) {
	ctx := context.Background()
	total, err := w.Store.CountAll(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "status:", err)
		os.Exit(1)
	}
	rows, err := w.Store.Summary(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "status:", err)
		os.Exit(1)
	}
	fmt.Printf("Witness archive: %d STHs across %d (server, chain) pairs\n\n", total, len(rows))
	if len(rows) == 0 {
		fmt.Println("(no STHs archived yet — daemon hasn't polled)")
		return
	}
	fmt.Printf("%-40s %-40s %12s %8s  EQUIV\n", "SERVER", "CHAIN", "MAX_SIZE", "ROWS")
	for _, r := range rows {
		mark := ""
		if r.HasEquivAt {
			mark = "⚠ EQUIVOCATION"
		}
		fmt.Printf("%-40s %-40s %12d %8d  %s\n",
			truncate(r.ServerURL, 40), truncate(r.ChainID, 40),
			r.MaxTreeSize, r.RowCount, mark)
	}
}

func runVerify(w *witness.Witness, log *slog.Logger) {
	ctx := context.Background()
	errs, equivs, err := w.VerifyArchive(ctx)
	if err != nil {
		log.Error("verify", "err", err)
		os.Exit(1)
	}
	fmt.Printf("verify: %d signature error(s), %d (server, chain) pair(s) with equivocation\n", errs, equivs)
	if errs > 0 || equivs > 0 {
		os.Exit(2)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

