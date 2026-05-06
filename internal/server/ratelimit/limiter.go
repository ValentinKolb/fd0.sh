// Package ratelimit implements a small in-memory token-bucket rate limiter
// scoped to fd0-server's needs.
//
// Single-process, single-instance: counters live in process memory only and
// reset on restart. That's deliberate — fd0-server is meant to be run as a
// single binary, and persistent ban tracking is out of scope. If you ever
// horizontally scale, replace this layer with a shared store.
//
// Three classes of limit are defined:
//
//   - per-identity write rate     ("ident:<base64(pk)>")  — POST /sync, POST /users/.../events
//   - per-IP register rate        ("regip:<ip>")          — POST /users (genesis)
//   - per-identity bytes-in       ("identbytes:<pk>")     — request body size aggregation
//
// Each entry uses an independent token-bucket with its own refill rate and
// capacity, all driven by a single Limiter.
//
// Limits are evaluated AFTER signature verification for ident-keyed buckets
// (otherwise an attacker could exhaust the limit by stuffing a spoofed pk
// header). Per-IP buckets check earlier because the unauthenticated register
// endpoint has no pk yet.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Config tunes the limiter. A zero or negative limit means "no bucket of
// this class; always allow".
type Config struct {
	// IdentityWritesPerMin: token bucket capacity for authenticated writes
	// keyed by signing pubkey. Refills at rate/min linearly. Default 60.
	IdentityWritesPerMin int

	// IdentityBytesPerMin: cap on aggregate request-body bytes per pubkey.
	// Defaults to 32 MiB (== 4 × default MaxBody × 1 minute window).
	IdentityBytesPerMin int

	// RegisterPerHour: limit on POST /users genesis registrations per IP.
	// Defaults to 5/h. Use a low value: registration is irreversible.
	RegisterPerHour int

	// AuthAttemptsPerMin: per-IP cap on authenticated-endpoint attempts
	// BEFORE signature verification. Closes the codex-found DoS where
	// an unauthenticated attacker rotates self-signed keys and forces
	// the server to body-read + sig-verify + DB lookup for each. The
	// per-pk rate limit only fires AFTER auth, so without this an
	// attacker bypasses it by changing pk every request.
	// Default 600/min (10/sec) — generous enough that a legitimate
	// behind-NAT cluster of clients works, tight enough to bound
	// crypto cost. Set to -1 to disable.
	AuthAttemptsPerMin int

	// ProofRequestsPerMin: per-IP cap on the unauthenticated translog
	// proof endpoints (handleSTH, handleInclusionProof,
	// handleConsistencyProof). Closes the T48 residual-exposure
	// flagged by codex threat-model review: those handlers walk
	// SQL per request and are NOT cached, so an attacker with a
	// high-fanout client could drive non-trivial CPU + IO without
	// authenticating. Default 120/min (2/sec) per IP — generous
	// enough for legitimate clients verifying many proofs in a
	// pull, tight enough that a single hostile IP can't saturate
	// the proof query path. Set to -1 to disable.
	ProofRequestsPerMin int

	// IdleEvict drops buckets unused for at least this long. Default 10 min.
	IdleEvict time.Duration

	// GCInterval is how often the eviction goroutine wakes. Default 5 min.
	GCInterval time.Duration

	// Now lets tests drive time. Defaults to time.Now.
	Now func() time.Time
}

// Limiter holds the bucket map. Safe for concurrent use.
type Limiter struct {
	cfg Config
	mu  sync.Mutex
	// Buckets indexed by composite key. We split by class (writes/bytes/reg)
	// so a pubkey that exhausts its write bucket doesn't disable other
	// classes for the same identity.
	buckets map[string]*bucket
}

// bucket is one token bucket. Token count is float because refill at less
// than once per second is otherwise impossible without lossy quantisation.
type bucket struct {
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	lastUsed   time.Time
}

// New constructs a Limiter and starts a GC goroutine bound to ctx.
//
// All zero / negative cfg values fall back to documented defaults. A
// non-positive specific limit (e.g. IdentityWritesPerMin: -1) disables that
// class — Acquire always returns Allow=true.
//
// THREAT: T48 (per-IP brute-force / DoS).
func New(ctx context.Context, cfg Config) *Limiter {
	if cfg.IdentityWritesPerMin == 0 {
		cfg.IdentityWritesPerMin = 60
	}
	if cfg.IdentityBytesPerMin == 0 {
		cfg.IdentityBytesPerMin = 32 * 1024 * 1024
	}
	if cfg.RegisterPerHour == 0 {
		cfg.RegisterPerHour = 5
	}
	if cfg.AuthAttemptsPerMin == 0 {
		cfg.AuthAttemptsPerMin = 600
	}
	if cfg.ProofRequestsPerMin == 0 {
		cfg.ProofRequestsPerMin = 120
	}
	if cfg.IdleEvict <= 0 {
		cfg.IdleEvict = 10 * time.Minute
	}
	if cfg.GCInterval <= 0 {
		cfg.GCInterval = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	l := &Limiter{cfg: cfg, buckets: map[string]*bucket{}}
	if ctx != nil {
		go l.gcLoop(ctx)
	}
	return l
}

// Class names keys for the bucket map. Public so tests can poke specific
// classes; do not call directly from handlers — use the helpers below.
const (
	classWrites      = "w:"
	classBytes       = "b:"
	classRegister    = "r:"
	classAuthAttempt = "a:"
	classProof       = "p:"
)

// Decision is the result of an Acquire. Retry is non-zero only when Allow is
// false; it's an estimate of when the next token would be available.
type Decision struct {
	Allow bool
	Retry time.Duration
}

// AcquireWrite checks whether identity ident may issue one more write right
// now. Cost is 1 token.
func (l *Limiter) AcquireWrite(ident string) Decision {
	if l.cfg.IdentityWritesPerMin < 0 {
		return Decision{Allow: true}
	}
	cap := float64(l.cfg.IdentityWritesPerMin)
	rate := cap / 60.0
	return l.acquire(classWrites+ident, cap, rate, 1)
}

// AcquireBytes records that identity ident produced n bytes of request body.
// Allow=false means the identity is over its byte budget for the minute.
func (l *Limiter) AcquireBytes(ident string, n int) Decision {
	if l.cfg.IdentityBytesPerMin < 0 || n <= 0 {
		return Decision{Allow: true}
	}
	cap := float64(l.cfg.IdentityBytesPerMin)
	rate := cap / 60.0
	return l.acquire(classBytes+ident, cap, rate, float64(n))
}

// AcquireAuthAttempt charges 1 token against the per-IP "may we even
// try to verify auth on this request" bucket. Called BEFORE body
// read / signature verify / DB lookup, so a key-rotating attacker
// can't bypass the per-pk write limit by changing pk every request.
//
// Codex security audit (🔴 auth.go:70/98/115): without this, an
// unauthenticated attacker rotating self-signed keys would hit
// body-read + sig-verify + IsUserRegistered for each request and
// only get rate-limited at the per-pk write layer (which they
// bypass by definition of key rotation).
func (l *Limiter) AcquireAuthAttempt(ip string) Decision {
	if l.cfg.AuthAttemptsPerMin < 0 {
		return Decision{Allow: true}
	}
	cap := float64(l.cfg.AuthAttemptsPerMin)
	rate := cap / 60.0
	return l.acquire(classAuthAttempt+ip, cap, rate, 1)
}

// AcquireRegister checks whether ip may register one more user.
func (l *Limiter) AcquireRegister(ip string) Decision {
	if l.cfg.RegisterPerHour < 0 {
		return Decision{Allow: true}
	}
	cap := float64(l.cfg.RegisterPerHour)
	rate := cap / 3600.0
	return l.acquire(classRegister+ip, cap, rate, 1)
}

// AcquireProof charges 1 token against the per-IP unauthenticated
// translog proof bucket. Closes the T48 residual-exposure flagged
// by codex threat-model review: handleSTH /
// handleInclusionProof / handleConsistencyProof walk SQL per
// request and are NOT cached, so an attacker with a high-fanout
// client could drive non-trivial CPU + IO without authenticating.
//
// Cap is generous (default 120/min = 2/sec) so legitimate clients
// verifying many proofs in a single pull don't get 429-out, but
// a single hostile IP can't saturate the proof query path either.
//
// THREAT: T48 (per-IP DoS at unauthenticated translog endpoints).
func (l *Limiter) AcquireProof(ip string) Decision {
	if l.cfg.ProofRequestsPerMin < 0 {
		return Decision{Allow: true}
	}
	cap := float64(l.cfg.ProofRequestsPerMin)
	rate := cap / 60.0
	return l.acquire(classProof+ip, cap, rate, 1)
}

// acquire is the shared bucket update path. We look up (or lazily create) a
// bucket for key, refill based on elapsed time, then attempt to deduct cost.
func (l *Limiter) acquire(key string, capacity, refillPerSec, cost float64) Decision {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{
			tokens:     capacity,
			capacity:   capacity,
			refillRate: refillPerSec,
			lastRefill: now,
		}
		l.buckets[key] = b
	}
	// Refill.
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refillRate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.lastRefill = now
	}
	b.lastUsed = now
	if b.tokens >= cost {
		b.tokens -= cost
		return Decision{Allow: true}
	}
	// Compute time-to-refill of (cost - tokens) tokens.
	deficit := cost - b.tokens
	if b.refillRate <= 0 {
		return Decision{Allow: false, Retry: time.Hour}
	}
	wait := time.Duration(deficit / b.refillRate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return Decision{Allow: false, Retry: wait}
}

// gcLoop evicts buckets unused for at least IdleEvict. Cheap: O(N) scan
// over the map every GCInterval.
func (l *Limiter) gcLoop(ctx context.Context) {
	t := time.NewTicker(l.cfg.GCInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.gcOnce()
		}
	}
}

// gcOnce drops idle buckets. Public-by-name only for the test harness; the
// production path runs gcLoop instead.
func (l *Limiter) gcOnce() {
	cutoff := l.cfg.Now().Add(-l.cfg.IdleEvict)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.lastUsed.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// Size returns the number of live buckets. Test-only.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
