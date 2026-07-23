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
	"sync"
	"syscall"

	"encoding/json"
	"time"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/valentinkolb/fd0.sh/internal/metrics"
	"github.com/valentinkolb/fd0.sh/internal/witness"
)

// promObserver implements witness.Observer using Prometheus collectors
// registered on the same registry that powers /metrics. Chain-level details
// stay in the witness API so server-controlled IDs cannot create unbounded
// Prometheus series.
type promObserver struct {
	polls               *prometheus.CounterVec
	cosigns             *prometheus.CounterVec
	equivocations       *prometheus.CounterVec
	consistencyFailures *prometheus.CounterVec
	treeSize            *prometheus.GaugeVec
	lastPollSeconds     *prometheus.GaugeVec
	now                 func() time.Time
	mu                  sync.Mutex
	maxTreeSize         map[string]uint64
}

func newPromObserver(reg *prometheus.Registry) *promObserver {
	o := &promObserver{
		polls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fd0_witness_polls_total",
			Help: "Witness polls grouped by upstream server and outcome.",
		}, []string{"server", "result"}),
		cosigns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fd0_witness_cosigns_total",
			Help: "Witness cosigns successfully issued.",
		}, []string{"server"}),
		equivocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fd0_witness_equivocations_total",
			Help: "Detected equivocations (multi-root archives at the same tree_size).",
		}, []string{"server"}),
		consistencyFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fd0_witness_consistency_failures_total",
			Help: "Consistency-proof failures between successive STHs.",
		}, []string{"server"}),
		treeSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fd0_witness_tree_size",
			Help: "Largest tree_size observed across chains for an upstream server.",
		}, []string{"server"}),
		lastPollSeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "fd0_witness_last_poll_timestamp_seconds",
			Help: "Unix timestamp of the most recent successful poll for an upstream server.",
		}, []string{"server"}),
		now:         time.Now,
		maxTreeSize: map[string]uint64{},
	}
	reg.MustRegister(o.polls, o.cosigns, o.equivocations, o.consistencyFailures, o.treeSize, o.lastPollSeconds)
	return o
}

func (o *promObserver) OnPoll(server, chain, result string) {
	o.polls.WithLabelValues(server, result).Inc()
	if result == "ok" {
		o.lastPollSeconds.WithLabelValues(server).Set(float64(o.now().Unix()))
	}
}

func (o *promObserver) OnCosign(server, chain string) {
	o.cosigns.WithLabelValues(server).Inc()
}

func (o *promObserver) OnEquivocation(server, chain string) {
	o.equivocations.WithLabelValues(server).Inc()
}

func (o *promObserver) OnConsistencyFailure(server, chain string) {
	o.consistencyFailures.WithLabelValues(server).Inc()
}

func (o *promObserver) OnTreeSize(server, chain string, size uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if size <= o.maxTreeSize[server] {
		return
	}
	o.maxTreeSize[server] = size
	o.treeSize.WithLabelValues(server).Set(float64(size))
}

type cli struct {
	// Storage / runtime
	DB           string `name:"db" help:"Witness archive SQLite path." default:"/data/witness.db" env:"FD0_WITNESS_DB"`
	Key          string `name:"key" help:"Witness cosign key path (ed25519 64-byte seed||pub). Auto-generated on first run if missing. Set empty to opt into v1.0 OPTIONAL passive-archiver mode (no cosign, no HTTP)." default:"/data/cosign.key" env:"FD0_WITNESS_KEY"`
	Bind         string `name:"bind" help:"HTTP server bind address. Set empty to disable the HTTP layer (passive-archiver mode)." default:":4049" env:"FD0_WITNESS_BIND"`
	MetricsToken string `name:"metrics-token" help:"Bearer token guarding /metrics." default:"" env:"FD0_WITNESS_METRICS_TOKEN"`
	Verbose      bool   `name:"verbose" short:"v" help:"Verbose logging." env:"FD0_WITNESS_VERBOSE"`

	// Target — env-only single-target config. Multi-target = run
	// multiple containers; each gets process / storage / metrics
	// isolation and a smaller failure domain than one mega-witness.
	ServerURL     string        `name:"server-url" help:"fd0-server to watch (e.g. https://api.fd0.sh or http://fd0-server:4048)." env:"FD0_WITNESS_SERVER_URL"`
	ServerPub     string        `name:"server-pub" help:"Server cosign pubkey obtained out of band (hex, 32 bytes). Required for a fresh production witness." default:"" env:"FD0_WITNESS_SERVER_PUB"`
	PollInterval  time.Duration `name:"poll-interval" help:"Time between poll rounds." default:"30s" env:"FD0_WITNESS_POLL_INTERVAL"`
	AutoDiscover  bool          `name:"auto-discover" help:"Fetch chain list from GET /v1/chains every round." default:"true" env:"FD0_WITNESS_AUTO_DISCOVER"`
	PinOnFirstUse bool          `name:"pin-on-first-use" help:"UNSAFE development-only TOFU from /v1/server-info. Never use for independent production witness trust." default:"false" env:"FD0_WITNESS_PIN_ON_FIRST_USE"`
	Chains        []string      `name:"chain" help:"Explicit chain ID to poll. Combine with --auto-discover or use as an allow-list when auto-discover is off." env:"FD0_WITNESS_CHAINS"`

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

	cfg := witness.Config{
		ServerURL:     c.ServerURL,
		ServerPubHex:  c.ServerPub,
		PollInterval:  c.PollInterval,
		AutoDiscover:  c.AutoDiscover,
		PinOnFirstUse: c.PinOnFirstUse,
		Chains:        c.Chains,
	}
	if err := cfg.Validate(); err != nil {
		log.Error("invalid witness config", "err", err)
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
		runDaemon(w, cosignPub, c.Bind, c.MetricsToken, log)
	case "status":
		runStatus(w)
	case "verify":
		runVerify(w, log)
	default:
		runDaemon(w, cosignPub, c.Bind, c.MetricsToken, log)
	}
}

func runDaemon(w *witness.Witness, cosignPub ed25519.PublicKey, bind, metricsToken string, log *slog.Logger) {
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
		reg := metrics.New(metrics.BuildInfo{Service: "fd0-witness", Version: version})
		// Domain-specific metrics: poll counter, cosign counter,
		// equivocation counter, tree_size gauge, last-poll gauge.
		// The observer is wired into w directly so pollOne fires the
		// hooks without further plumbing.
		w.Observer = newPromObserver(reg.Reg())

		top := http.NewServeMux()
		top.Handle("GET /metrics", reg.Handler(metricsToken, ""))
		top.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":  "ok",
				"service": "fd0-witness",
				"version": version,
			})
		})
		top.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"service":        "fd0-witness",
				"server_version": version,
				"api_version":    "v1",
			})
		})
		top.Handle("/", reg.Middleware("fd0-witness")(hs.Handler()))

		httpSrv := &http.Server{
			Addr:              bind,
			Handler:           top,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		go func() {
			log.Info("witness http server up", "bind", bind,
				"metrics_auth", boolWord(metricsToken != ""))
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("witness http server", "err", err)
				cancel()
			}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()
			_ = httpSrv.Shutdown(shutdownCtx)
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
	pairs, err := w.Store.CountSummary(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "status:", err)
		os.Exit(1)
	}
	fmt.Printf("Witness archive: %d STHs across %d (server, chain) pairs\n\n", total, pairs)
	if pairs == 0 {
		fmt.Println("(no STHs archived yet — daemon hasn't polled)")
		return
	}
	fmt.Printf("%-40s %-40s %12s %8s  EQUIV\n", "SERVER", "CHAIN", "MAX_SIZE", "ROWS")
	afterServer := ""
	afterChain := ""
	for {
		rows, nextServer, nextChain, pageErr := w.Store.SummaryPage(ctx, afterServer, afterChain, 256)
		if pageErr != nil {
			fmt.Fprintln(os.Stderr, "status:", pageErr)
			os.Exit(1)
		}
		for _, r := range rows {
			mark := ""
			if r.HasEquivAt {
				mark = "⚠ EQUIVOCATION"
			}
			fmt.Printf("%-40s %-40s %12d %8d  %s\n",
				truncate(r.ServerURL, 40), truncate(r.ChainID, 40),
				r.MaxTreeSize, r.RowCount, mark)
		}
		if nextServer == "" {
			return
		}
		if nextServer < afterServer || (nextServer == afterServer && nextChain <= afterChain) {
			fmt.Fprintln(os.Stderr, "status: summary pagination did not advance")
			os.Exit(1)
		}
		afterServer = nextServer
		afterChain = nextChain
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

func boolWord(b bool) string {
	if b {
		return "enabled"
	}
	return "open"
}
