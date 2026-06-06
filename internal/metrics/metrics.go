// Package metrics provides a Prometheus registry, HTTP RED middleware
// (requests / errors / duration), and a layered-auth /metrics handler
// shared by fd0-server, fd0-witness, and any future fd0 daemon.
//
// The design mirrors filegate's metrics package — same RED labels
// (service, op, status_class), same handler shape, same auth rule
// (metricsToken if set, else bearerToken if set, else open). Keeping
// the two projects in lockstep means scrape configs and dashboards
// stay portable.
package metrics

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry holds the per-process collectors. One Registry per binary;
// pass it to Middleware to wrap an http.Handler and to Handler() to
// build the /metrics endpoint.
type Registry struct {
	reg *prometheus.Registry

	httpRequests  *prometheus.CounterVec
	httpDuration  *prometheus.HistogramVec
	httpInFlight  *prometheus.GaugeVec
	httpRespBytes *prometheus.HistogramVec
	httpReqBytes  *prometheus.HistogramVec

	buildInfo *prometheus.GaugeVec
}

// BuildInfo is recorded as a constant gauge so dashboards can pivot by
// service+version without scraping a separate /version endpoint.
type BuildInfo struct {
	Service string // "fd0-server" / "fd0-witness" / "fd0-website"
	Version string
}

// New returns a Registry pre-loaded with HTTP RED collectors and a
// build_info gauge. Domain-specific collectors are added separately by
// the caller via reg.Reg().MustRegister(...).
func New(info BuildInfo) *Registry {
	r := &Registry{reg: prometheus.NewRegistry()}

	r.httpRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fd0_http_requests_total",
		Help: "HTTP requests processed, partitioned by service, operation and status class.",
	}, []string{"service", "op", "status_class"})

	r.httpDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "fd0_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"service", "op"})

	r.httpInFlight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fd0_http_in_flight",
		Help: "In-flight HTTP requests at scrape time.",
	}, []string{"service"})

	r.httpRespBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "fd0_http_response_bytes",
		Help:    "HTTP response body size in bytes.",
		Buckets: prometheus.ExponentialBuckets(64, 4, 8),
	}, []string{"service", "op"})

	r.httpReqBytes = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "fd0_http_request_bytes",
		Help:    "HTTP request body size in bytes (only when Content-Length is set).",
		Buckets: prometheus.ExponentialBuckets(64, 4, 8),
	}, []string{"service", "op"})

	r.buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fd0_build_info",
		Help: "Build identifier (always 1). Use the labels to pivot.",
	}, []string{"service", "version"})

	r.reg.MustRegister(r.httpRequests, r.httpDuration, r.httpInFlight, r.httpRespBytes, r.httpReqBytes, r.buildInfo)
	r.buildInfo.WithLabelValues(info.Service, info.Version).Set(1)

	// Register the standard process + Go runtime collectors so the
	// scrape includes RSS, FDs, GC stats — invaluable for operators.
	r.reg.MustRegister(
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
		prometheus.NewGoCollector(),
	)

	return r
}

// Reg exposes the underlying *prometheus.Registry so callers can add
// service-specific collectors (counter for fd0_sync_events_total,
// gauge for fd0_db_size_bytes, etc.).
func (r *Registry) Reg() *prometheus.Registry { return r.reg }

// Middleware returns an http middleware that records RED metrics for
// the wrapped handler. `service` is the constant label written on
// every observation ("fd0-server", "fd0-witness", "fd0-website").
func (r *Registry) Middleware(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			start := time.Now()
			r.httpInFlight.WithLabelValues(service).Inc()
			defer r.httpInFlight.WithLabelValues(service).Dec()

			sw := &sizeStatusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, req)

			op := opLabel(req)
			class := statusClass(sw.status)
			r.httpRequests.WithLabelValues(service, op, class).Inc()
			r.httpDuration.WithLabelValues(service, op).Observe(time.Since(start).Seconds())
			r.httpRespBytes.WithLabelValues(service, op).Observe(float64(sw.written))
			if size := requestBodySize(req); size >= 0 {
				r.httpReqBytes.WithLabelValues(service, op).Observe(float64(size))
			}
		})
	}
}

// Handler builds the /metrics endpoint with the layered token-auth
// rule: require metricsToken if set, else require bearerToken if set,
// else serve openly (trusted network). Comparison is constant-time.
//
// Returns nothing useful (404 plus body) to anonymous callers when
// auth is required — no probing for token presence.
func (r *Registry) Handler(metricsToken, bearerToken string) http.Handler {
	prom := promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{Registry: r.reg})
	effective := strings.TrimSpace(metricsToken)
	if effective == "" {
		effective = strings.TrimSpace(bearerToken)
	}
	if effective == "" {
		return prom // open access on trusted network
	}
	expected := []byte("Bearer " + effective)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got := req.Header.Get("Authorization")
		// Constant-time prevents leaking the token via timing.
		if subtle.ConstantTimeCompare([]byte(got), expected) != 1 {
			http.NotFound(w, req)
			return
		}
		prom.ServeHTTP(w, req)
	})
}

// statusClass buckets HTTP statuses into RED-suitable labels. Keeping
// status-class cardinality at most six series per (service, op) is
// the whole point — exact codes would explode the histogram count.
func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	case code >= 100:
		return "1xx"
	default:
		return "other"
	}
}

// opLabel collapses HTTP requests onto a stable, low-cardinality
// label. We use the path with dynamic segments masked: /v1/sth/{...}
// rather than the raw URL. For now keep it cheap — bucket on first
// two path segments, and use a single bucket for everything else.
//
// Examples:
//   GET  /v1/sync                          → "GET /v1/sync"
//   GET  /v1/sth/aGVsbG8/scope:s_x         → "GET /v1/sth/*"
//   GET  /v1/users/upXxx/events            → "GET /v1/users/*"
//   GET  /health                           → "GET /health"
func opLabel(req *http.Request) string {
	parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/"), "/")
	switch {
	case len(parts) == 0 || parts[0] == "":
		return req.Method + " /"
	case len(parts) == 1:
		return req.Method + " /" + parts[0]
	case len(parts) >= 3:
		// version + collection + variable → /v1/users/*, /v1/sth/*
		return req.Method + " /" + parts[0] + "/" + parts[1] + "/*"
	default:
		return req.Method + " /" + parts[0] + "/" + parts[1]
	}
}

// sizeStatusWriter records the response status and total bytes
// written so the middleware can observe both without buffering.
type sizeStatusWriter struct {
	http.ResponseWriter
	status  int
	written int
}

func (w *sizeStatusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *sizeStatusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.written += n
	return n, err
}

// requestBodySize returns the Content-Length when the client declared
// one, or -1 to skip the observation. We do not consume the body just
// to measure it — that would compete with the handler.
func requestBodySize(req *http.Request) int64 {
	cl := req.Header.Get("Content-Length")
	if cl == "" {
		return -1
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}
