package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Auth header parsing per API.md §1.
//
//	Authorization: fd0-sig v1
//	    pk=<base64>, nonce=<base64>, ts=<unix_seconds>, sig=<base64>

const (
	maxClockSkew = 300 * time.Second
	nonceTTLSecs = 600
)

// AuthResult is what verifyHTTPSig returns on success.
type AuthResult struct {
	Pub  []byte // signer public key
	Body []byte // body bytes (already read; pass through to handler)
}

// verifyHTTPSig validates the Authorization header against the request.
//
// Side-effect: insertion of (pk, nonce) into auth_nonces. If the same triple
// is seen twice within nonceTTLSecs the request is rejected.
//
// The handler MUST NOT use r.Body after this call: the body has already been
// consumed. Use the returned Body bytes.
func (s *Server) verifyHTTPSig(ctx context.Context, r *http.Request) (*AuthResult, int, error) {
	// SECURITY (codex security audit 🔴 auth.go:70/98/115): per-IP
	// pre-auth rate limit. Without this, a key-rotating attacker
	// hits body-read + sig-verify + IsUserRegistered DB lookup for
	// each request and only rate-limits at the per-pk layer —
	// which they bypass by definition of key rotation. The cheap
	// per-IP token bucket fires BEFORE any expensive work.
	if s.rl != nil {
		if d := s.rl.AcquireAuthAttempt(clientIP(r)); !d.Allow {
			return nil, http.StatusTooManyRequests, rateLimitedError{retry: d.Retry}
		}
	}
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, http.StatusUnauthorized, errors.New("missing authorization")
	}
	if !strings.HasPrefix(hdr, "fd0-sig v1") {
		return nil, http.StatusUnauthorized, errors.New("bad scheme")
	}
	params := parseSigParams(strings.TrimSpace(strings.TrimPrefix(hdr, "fd0-sig v1")))
	pk, err := b64dec(params["pk"])
	if err != nil || len(pk) != 32 {
		return nil, http.StatusUnauthorized, errors.New("bad pk")
	}
	nonce, err := b64dec(params["nonce"])
	if err != nil || len(nonce) != 16 {
		return nil, http.StatusUnauthorized, errors.New("bad nonce")
	}
	ts, err := strconv.ParseInt(params["ts"], 10, 64)
	if err != nil {
		return nil, http.StatusUnauthorized, errors.New("bad ts")
	}
	sig, err := b64dec(params["sig"])
	if err != nil || len(sig) != 64 {
		return nil, http.StatusUnauthorized, errors.New("bad sig")
	}
	now := time.Now().Unix()
	if absDelta(now, ts) > int64(maxClockSkew.Seconds()) {
		return nil, http.StatusUnauthorized, errors.New("stale_ts")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	r.Body.Close()
	// Build query map. v1 forbids multi-value keys.
	qmap := map[string]string{}
	for k, vs := range r.URL.Query() {
		if len(vs) > 1 {
			return nil, http.StatusBadRequest, fmt.Errorf("multi-value query key %q", k)
		}
		qmap[k] = vs[0]
	}
	// SECURITY (signature subagent audit 🔴): bind the signature to
	// THIS server's pubkey. A request signed for server-A cannot
	// be replayed against server-B because the signed input
	// includes server-A's pub which doesn't match server-B's.
	si, err := proto.HTTPSignedInput(r.Method, r.URL.Path, qmap, uint64(ts), nonce, body, []byte(s.store.TranslogPub()))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if !crypto.Verify(pk, si, sig) {
		return nil, http.StatusUnauthorized, errors.New("bad_sig")
	}
	// SECURITY (codex audit 🔴 auth.go:87): authenticated endpoints
	// MUST verify pk corresponds to a registered user. Without this
	// check, anyone could self-sign a key, call /sync, and create
	// scopes on the server. Registration happens via POST /users.
	registered, err := s.store.IsUserRegistered(ctx, pk)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !registered {
		return nil, http.StatusUnauthorized, errors.New("unregistered_pk")
	}
	// Replay window via auth_nonces.
	ok, err := s.store.CheckAndInsertNonce(ctx, pk, nonce, ts)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !ok {
		return nil, http.StatusUnauthorized, errors.New("replay")
	}
	// Rate limit applies AFTER signature + replay verification so an attacker
	// can't burn somebody else's bucket with a forged Authorization header.
	if s.rl != nil {
		ident := base64.StdEncoding.EncodeToString(pk)
		if d := s.rl.AcquireWrite(ident); !d.Allow {
			return nil, http.StatusTooManyRequests, rateLimitedError{retry: d.Retry}
		}
		if d := s.rl.AcquireBytes(ident, len(body)); !d.Allow {
			return nil, http.StatusTooManyRequests, rateLimitedError{retry: d.Retry}
		}
	}
	return &AuthResult{Pub: pk, Body: body}, 0, nil
}

// rateLimitedError lets handlers detect rate-limit-driven 429s and emit the
// Retry-After header without sniffing the message string.
type rateLimitedError struct{ retry time.Duration }

func (e rateLimitedError) Error() string { return "rate_limited" }
func (e rateLimitedError) RetryAfter() time.Duration { return e.retry }

// readBody reads the request body without verifying a signature. Used by the
// two unauthenticated endpoints (POST /users, GET /users/<shortId>/events).
func readBody(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

// parseSigParams parses comma-separated `key=value` pairs from the auth header
// payload. Values do not contain commas in v1.
func parseSigParams(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if eq := strings.IndexByte(part, '='); eq > 0 {
			out[strings.TrimSpace(part[:eq])] = strings.TrimSpace(part[eq+1:])
		}
	}
	return out
}

func b64dec(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func absDelta(a, b int64) int64 {
	d := a - b
	if d < 0 {
		return -d
	}
	return d
}

