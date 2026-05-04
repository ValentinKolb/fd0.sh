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
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"net/http"
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
	Key     string `name:"key" help:"Witness cosign key path (ed25519 64-byte seed||pub). Empty = legacy passive-archiver mode (no cosign, no HTTP)." default:"" env:"FD0_WITNESS_KEY"`
	Bind    string `name:"bind" help:"HTTP server bind address for client cross-check (empty = no HTTP server). Requires --key." default:"" env:"FD0_WITNESS_BIND"`
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
	defer func() { _ = store.Close() }()

	// Provision the witness's own cosign keypair only when --key
	// is given. Without a key the witness runs in legacy
	// passive-archiver mode (no cosign, no HTTP server) — exactly
	// the v1.0 OPTIONAL profile from TRANSLOG.md §10.
	var (
		cosignPriv ed25519.PrivateKey
		cosignPub  ed25519.PublicKey
	)
	if c.Key != "" {
		bgCtx := context.Background()
		cosignPriv, cosignPub, err = witness.LoadOrCreateWitnessKey(bgCtx, store, c.Key, func(msg string) {
			fmt.Fprintln(os.Stderr, msg)
		})
		if err != nil {
			log.Error("witness keypair", "err", err)
			os.Exit(2)
		}
		log.Info("witness cosign key loaded", "pub_hex", fmt.Sprintf("%x", cosignPub))
	} else if c.Bind != "" {
		log.Error("--bind requires --key (HTTP server has no cosign key to expose)")
		os.Exit(2)
	}

	w := witness.New(store, cfg, log)
	w.CosignPriv = cosignPriv

	switch kctx.Command() {
	case "run":
		runDaemon(w, cosignPub, c.Bind, log)
	case "status":
		runStatus(w)
	case "verify":
		runVerify(w, log)
	default:
		runDaemon(w, cosignPub, c.Bind, log)
	}
}

func runDaemon(w *witness.Witness, cosignPub ed25519.PublicKey, bind string, log *slog.Logger) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Optional HTTP server for client cross-check (TRANSLOG.md §8.3).
	// Requires --key (validated above). Absent --bind the witness
	// runs in legacy "passive archiver" mode.
	if bind != "" {
		hs := &witness.HTTPServer{
			Store:      w.Store,
			WitnessPub: cosignPub,
			Log:        log,
		}
		go func() {
			log.Info("witness http server up", "bind", bind)
			if err := hs.ListenAndServe(bind); err != nil && err != http.ErrServerClosed {
				log.Error("witness http server", "err", err)
				cancel()
			}
		}()
	}

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

