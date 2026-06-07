// fd0-server is the HTTP backend for fd0. It serves the API in API.md backed
// by a single SQLite file. Configuration is via flags or env vars (FD0_*).
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/valentinkolb/fd0.sh/internal/metrics"
	"github.com/valentinkolb/fd0.sh/internal/server"
	"github.com/valentinkolb/fd0.sh/internal/server/ratelimit"
	"github.com/valentinkolb/fd0.sh/internal/server/store"
)

// promObserver implements server.Observer using Prometheus collectors
// registered on the same registry that powers /metrics. Counters track
// per-operation outcomes; the gauges below them are wired separately
// via NewGaugeFunc so they reflect current state at scrape time.
type promObserver struct {
	registrations   *prometheus.CounterVec
	eventsPushed    *prometheus.CounterVec
	eventsPulled    *prometheus.CounterVec
	eventsPulledSum *prometheus.CounterVec
}

func newPromObserver(reg *prometheus.Registry) *promObserver {
	o := &promObserver{
		registrations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fd0_server_registrations_total",
			Help: "POST /v1/users attempts grouped by outcome (ok, taken, bad_input, ratelimit, dup, internal).",
		}, []string{"result"}),
		eventsPushed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fd0_server_events_pushed_total",
			Help: "Events pushed in /v1/sync grouped by chain kind (user/scope) and outcome.",
		}, []string{"chain_kind", "result"}),
		eventsPulled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fd0_server_pulls_total",
			Help: "Pull responses grouped by chain kind.",
		}, []string{"chain_kind"}),
		eventsPulledSum: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "fd0_server_events_pulled_total",
			Help: "Events delivered to clients via pull grouped by chain kind.",
		}, []string{"chain_kind"}),
	}
	reg.MustRegister(o.registrations, o.eventsPushed, o.eventsPulled, o.eventsPulledSum)
	return o
}

func (o *promObserver) OnRegister(result string) {
	o.registrations.WithLabelValues(result).Inc()
}

func (o *promObserver) OnEventPushed(chainKind, result string) {
	o.eventsPushed.WithLabelValues(chainKind, result).Inc()
}

func (o *promObserver) OnEventsPulled(chainKind string, count int) {
	o.eventsPulled.WithLabelValues(chainKind).Inc()
	o.eventsPulledSum.WithLabelValues(chainKind).Add(float64(count))
}

// registerStateGauges wires the scrape-time gauges. Each one runs a
// quick query at scrape time. Total cost: 2 trivial COUNT queries + an
// os.Stat per /metrics scrape, well below the cost of the response.
func registerStateGauges(reg *prometheus.Registry, st *store.Store, dbPath string) {
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "fd0_server_users_total",
		Help: "Number of registered users (SELECT COUNT FROM users at scrape time).",
	}, func() float64 {
		n, err := st.CountUsers(context.Background())
		if err != nil {
			return 0
		}
		return float64(n)
	}))
	// Per-kind chain count via a dedicated collector so kinds can be
	// emitted dynamically — a static GaugeVec would require knowing
	// every kind label at registration time.
	reg.MustRegister(&chainCountCollector{store: st})
	// DB file size at scrape time. Useful for capacity dashboards.
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "fd0_server_db_size_bytes",
		Help: "Size of the SQLite file in bytes at scrape time.",
	}, func() float64 {
		fi, err := os.Stat(dbPath)
		if err != nil {
			return 0
		}
		return float64(fi.Size())
	}))
}

// chainCountCollector publishes per-kind chain counts at scrape time.
// A dedicated collector is needed (vs NewGaugeFunc on a GaugeVec) so we
// can emit a row per kind discovered in the DB without pre-registering
// labels.
type chainCountCollector struct {
	store *store.Store
}

var chainCountDesc = prometheus.NewDesc(
	"fd0_server_chains_total",
	"Chains grouped by kind (user/scope), discovered at scrape time.",
	[]string{"kind"}, nil,
)

func (c *chainCountCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- chainCountDesc
}

func (c *chainCountCollector) Collect(ch chan<- prometheus.Metric) {
	counts, err := c.store.CountChainsByKind(context.Background())
	if err != nil {
		return
	}
	for kind, n := range counts {
		ch <- prometheus.MustNewConstMetric(chainCountDesc, prometheus.GaugeValue, float64(n), kind)
	}
}

// Default port is 0xFD0 = 4048.
type cli struct {
	Bind    string `name:"bind" help:"Listen address." default:":4048" env:"FD0_BIND"`
	DB      string `name:"db" help:"SQLite path." default:"/data/fd0.db" env:"FD0_DB"`
	MaxBody int64  `name:"max-body" help:"Max request body bytes." default:"8388608" env:"FD0_MAX_BODY"`
	Verbose bool   `name:"verbose" short:"v" help:"Verbose logging." env:"FD0_VERBOSE"`

	// MetricsToken protects the /metrics endpoint. If empty, /metrics
	// is served openly (suitable for a trusted internal network or
	// behind a scrape-only reverse proxy). If set, scrapers must send
	// `Authorization: Bearer <token>` — anything else 404s.
	MetricsToken string `name:"metrics-token" help:"Bearer token guarding /metrics." default:"" env:"FD0_METRICS_TOKEN"`

	// Rate limiting. Single-instance only. Negative values disable that
	// specific class; --no-ratelimit (FD0_RATELIMIT=off) disables all.
	NoRateLimit     bool `name:"no-ratelimit" help:"Disable rate limiting entirely." env:"FD0_RATELIMIT_OFF"`
	WritesPerMin    int  `name:"writes-per-min" help:"Authenticated writes/min per identity." default:"60" env:"FD0_RATELIMIT_WRITES_PER_MIN"`
	BytesPerMin     int  `name:"bytes-per-min" help:"Aggregate request body bytes/min per identity." default:"33554432" env:"FD0_RATELIMIT_BYTES_PER_MIN"`
	RegisterPerHour int  `name:"register-per-hour" help:"POST /v1/users registrations/hour per IP." default:"5" env:"FD0_RATELIMIT_REGISTER_PER_HOUR"`
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
	// Build the metrics registry FIRST so the observer can be passed
	// into the server constructor and gauges can reference srv.Store().
	reg := metrics.New(metrics.BuildInfo{Service: "fd0-server", Version: version})
	obs := newPromObserver(reg.Reg())

	srv, err := server.New(server.Config{
		Bind:     c.Bind,
		DBPath:   c.DB,
		Version:  version,
		MaxBytes: c.MaxBody,
		Logger:   log,
		Observer: obs,

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
	defer func() { _ = srv.Close() }()

	// State gauges (users, chains by kind, db file size) — scrape-time
	// queries on the store, so they need srv to exist first.
	registerStateGauges(reg.Reg(), srv.Store(), c.DB)

	// Wrap the server in RED metrics middleware and mount /metrics
	// separately on a top-level mux so the metrics endpoint never
	// hits the data API's routing.
	top := http.NewServeMux()
	top.Handle("GET /metrics", reg.Handler(c.MetricsToken, ""))
	top.Handle("/", reg.Middleware("fd0-server")(srv))

	httpSrv := &http.Server{
		Addr:              c.Bind,
		Handler:           top,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		log.Info("fd0-server listening", "bind", c.Bind, "version", version,
			"metrics_auth", boolWord(c.MetricsToken != ""))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		if err != nil {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}
}

func boolWord(b bool) string {
	if b {
		return "enabled"
	}
	return "open"
}
