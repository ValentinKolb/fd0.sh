package witness

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// HTTPServer exposes the witness's archive over a small read-only
// HTTP API so clients can cross-check server-provided STHs against
// what the witness independently observed (TRANSLOG.md §8.3 / §10).
//
// Endpoints:
//
//	GET /v1/witness/server-info
//	    → CBOR { witness_pub: bytes(32) }
//
//	GET /v1/witness/sth/<server_url_b64>/<chain_id>[?tree_size=N]
//	    → CBOR translog.WitnessedSTH (latest, or at exact size when given)
//	    → 404 if the witness has not observed that (server, chain, size)
//
// `<server_url_b64>` is a base64url (no padding) encoding of the
// upstream server URL — keeps slashes and colons out of the path
// without forcing the witness to do per-request URL parsing on
// untrusted input.
//
// Healthz is intentionally omitted; clients use the server-info
// endpoint as a liveness probe (any 200 implies the witness is up
// AND has its keypair loaded).
type HTTPServer struct {
	Store      *Store
	WitnessPub ed25519.PublicKey
	Log        *slog.Logger
}

// Handler returns the http.Handler tree. Hosting the mux outside the
// struct lets callers compose the witness API into a larger router
// (e.g., behind a reverse proxy with TLS termination).
func (s *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/witness/server-info", s.handleServerInfo)
	mux.HandleFunc("/v1/witness/sth/", s.handleWitnessSTH)
	// C4: T41 freshness probe — highest tree_size archived per chain.
	mux.HandleFunc("/v1/witness/highest/", s.handleHighest)
	// C5: T35 chain-level equivocation probe — has the witness ever
	// archived multi-roots at any tree_size for this chain?
	mux.HandleFunc("/v1/witness/equivocation/", s.handleEquivocation)
	return mux
}

// ListenAndServe starts a basic http.Server bound to addr. Returns
// the underlying error from Server.ListenAndServe so the caller can
// distinguish "shutdown requested" from "port collision". Handler-
// level panics are recovered into 500 responses by net/http.
func (s *HTTPServer) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	return srv.ListenAndServe()
}

// EncodeServerURL returns the base64url(no-padding) encoding of a
// raw server URL string. Exposed so clients can build request URLs
// with the same encoder the server uses to decode.
func EncodeServerURL(raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeServerURL is EncodeServerURL's inverse. Returns the raw URL
// string or an error if the input is not valid base64url.
func DecodeServerURL(enc string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ---- handlers ----

// handleServerInfo serves GET /v1/witness/server-info.
func (s *HTTPServer) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := serverInfoResponse{
		WitnessPub: append([]byte(nil), s.WitnessPub...),
		PubHex:     hex.EncodeToString(s.WitnessPub),
	}
	writeCBOR(w, http.StatusOK, body)
}

type serverInfoResponse struct {
	WitnessPub []byte `cbor:"witness_pub"`
	PubHex     string `cbor:"witness_pub_hex"` // operator convenience for log diffs
}

// Length caps for path segments — small constants are enough for
// any legitimate (server URL, chain ID) and bound the work the
// handler does on adversarial input (codex fix #6). A real chain ID
// is ~50 chars; a server URL has no protocol-defined limit but
// 4 KiB covers anything reasonable.
const (
	maxServerB64Len = 4096
	maxChainIDLen   = 256
)

// handleWitnessSTH serves GET /v1/witness/sth/<server_b64>/<chain>[?tree_size=N].
//
// The handler is deliberately strict on the request shape — the
// route is small enough that surprising URLs almost certainly
// indicate a misconfigured client.
func (s *HTTPServer) handleWitnessSTH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/witness/sth/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "expected /v1/witness/sth/<server_b64>/<chain_id>", http.StatusBadRequest)
		return
	}
	if len(parts[0]) > maxServerB64Len {
		http.Error(w, "server segment too long", http.StatusRequestURITooLong)
		return
	}
	if len(parts[1]) > maxChainIDLen {
		http.Error(w, "chain_id too long", http.StatusRequestURITooLong)
		return
	}
	serverURL, err := DecodeServerURL(parts[0])
	if err != nil {
		http.Error(w, "server segment is not valid base64url", http.StatusBadRequest)
		return
	}
	chainID := parts[1]
	if !strings.HasPrefix(chainID, "user:") && !strings.HasPrefix(chainID, "scope:") {
		http.Error(w, "chain_id must start with user: or scope:", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	var (
		sth     translog.STH
		cosign  []byte
		lookErr error
	)
	if sizeStr := r.URL.Query().Get("tree_size"); sizeStr != "" {
		n, perr := strconv.ParseUint(sizeStr, 10, 64)
		if perr != nil {
			http.Error(w, "tree_size must be an unsigned integer", http.StatusBadRequest)
			return
		}
		sth, cosign, lookErr = s.Store.LookupAt(ctx, serverURL, chainID, n)
	} else {
		sth, cosign, lookErr = s.Store.LatestSTHWithCosign(ctx, serverURL, chainID)
	}
	switch {
	case errors.Is(lookErr, ErrNoSTH):
		http.Error(w, fmt.Sprintf("witness has not observed %s @ %s yet", chainID, serverURL), http.StatusNotFound)
		return
	case errors.Is(lookErr, ErrEquivocationAtSize):
		// Codex fix #2: surface multi-root archive state as 409
		// instead of silently picking one branch. Cooperating
		// clients treat 409 as hard equivocation evidence.
		s.Log.Error("witness http: equivocation at requested size", "server", serverURL, "chain", chainID)
		http.Error(w, "witness archive holds multiple distinct roots at this tree_size — equivocation evidence", http.StatusConflict)
		return
	case lookErr != nil:
		s.Log.Error("witness http: store lookup failed", "err", lookErr)
		http.Error(w, "internal lookup error", http.StatusInternalServerError)
		return
	}
	// A row that pre-dates the cosign deployment (witness_signature
	// IS NULL) — or one withheld for consistency-failure (codex
	// fix #1) — is honest data but cannot satisfy a client doing
	// cosign verification. Surface as 404 rather than handing back
	// a structurally-incomplete WitnessedSTH.
	if cosign == nil {
		http.Error(w, "STH archived without witness cosign (legacy or consistency-failed); retry after witness rearchives", http.StatusNotFound)
		return
	}

	wsth := translog.WitnessedSTH{
		STH:        sth,
		ServerURL:  serverURL,
		WitnessPub: append([]byte(nil), s.WitnessPub...),
		WitnessSig: cosign,
	}
	writeCBOR(w, http.StatusOK, wsth)
}

// HighestResponse is the body of GET
// /v1/witness/highest/<server_b64>/<chain_id>. `Observed` is true
// iff the witness has archived at least one STH for the
// (server_url, chain_id) pair; `TreeSize` is the maximum observed.
//
// Clients call this BEFORE accepting a server-supplied STH at
// tree_size N. If `Observed && N < TreeSize`, the server is
// rolling the client back — refuse.
type HighestResponse struct {
	Observed bool   `cbor:"observed"`
	TreeSize uint64 `cbor:"tree_size"`
}

// EquivocationResponse is the body of GET
// /v1/witness/equivocation/<server_b64>/<chain_id>. `Equivocated`
// is true iff the witness has ever archived multi-root STHs at
// the SAME tree_size for the (server_url, chain_id) pair.
//
// Clients call this BEFORE accepting any cosign on a chain.
// `Equivocated == true` means the witness saw the server publish
// two divergent histories — refuse all cosigns from this server
// for this chain regardless of tree_size.
type EquivocationResponse struct {
	Equivocated bool `cbor:"equivocated"`
}

// handleHighest serves
// GET /v1/witness/highest/<server_b64>/<chain_id> for the C4
// T41 freshness probe.
func (s *HTTPServer) handleHighest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	serverURL, chainID, ok := parseHighestEquivocPath(w, r, "/v1/witness/highest/")
	if !ok {
		return
	}
	size, observed, err := s.Store.HighestTreeSize(r.Context(), serverURL, chainID)
	if err != nil {
		s.Log.Error("witness http: HighestTreeSize lookup failed", "err", err)
		http.Error(w, "internal lookup error", http.StatusInternalServerError)
		return
	}
	writeCBOR(w, http.StatusOK, HighestResponse{Observed: observed, TreeSize: size})
}

// handleEquivocation serves
// GET /v1/witness/equivocation/<server_b64>/<chain_id> for the
// C5 T35 chain-level equivocation probe.
func (s *HTTPServer) handleEquivocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	serverURL, chainID, ok := parseHighestEquivocPath(w, r, "/v1/witness/equivocation/")
	if !ok {
		return
	}
	equiv, err := s.Store.DetectChainEquivocation(r.Context(), serverURL, chainID)
	if err != nil {
		s.Log.Error("witness http: DetectChainEquivocation lookup failed", "err", err)
		http.Error(w, "internal lookup error", http.StatusInternalServerError)
		return
	}
	writeCBOR(w, http.StatusOK, EquivocationResponse{Equivocated: equiv})
}

// parseHighestEquivocPath shares URL-shape validation between
// handleHighest and handleEquivocation. Both routes use the same
// `<server_b64>/<chain_id>` shape as handleWitnessSTH (without the
// optional ?tree_size). Returns (server_url, chain_id, ok); writes
// the response on the http.ResponseWriter on parse error.
func parseHighestEquivocPath(w http.ResponseWriter, r *http.Request, prefix string) (string, string, bool) {
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "expected "+prefix+"<server_b64>/<chain_id>", http.StatusBadRequest)
		return "", "", false
	}
	if len(parts[0]) > maxServerB64Len {
		http.Error(w, "server segment too long", http.StatusRequestURITooLong)
		return "", "", false
	}
	if len(parts[1]) > maxChainIDLen {
		http.Error(w, "chain_id too long", http.StatusRequestURITooLong)
		return "", "", false
	}
	serverURL, err := DecodeServerURL(parts[0])
	if err != nil {
		http.Error(w, "server segment is not valid base64url", http.StatusBadRequest)
		return "", "", false
	}
	chainID := parts[1]
	if !strings.HasPrefix(chainID, "user:") && !strings.HasPrefix(chainID, "scope:") {
		http.Error(w, "chain_id must start with user: or scope:", http.StatusBadRequest)
		return "", "", false
	}
	return serverURL, chainID, true
}

// writeCBOR serializes v as CBOR and writes it. Mirror of the
// server's writer so we don't pull in the whole server package.
func writeCBOR(w http.ResponseWriter, code int, v any) {
	b, err := proto.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

// Compile-time guard: ensure context is wired through to handler.
var _ = context.Background
