package witness

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// Witness ties together the Store, an HTTP client, and a logger. One
// instance handles many (server_url, chain_id) pairs configured by
// the operator. Run() starts the polling loop; PollOnce drives a
// single round (used by tests + the manual `verify` command).
//
// CosignPriv is the witness's own ed25519 cosign keypair (TRANSLOG.md
// §10). When non-nil, every successfully-verified STH is also signed
// and the cosign is persisted alongside the row. May be nil in unit
// tests that don't exercise the cosign protocol.
// Observer receives per-poll events so external collectors (Prometheus
// metrics, audit feeds) can be wired in without coupling the witness to
// any specific instrumentation. All methods take a server+chain pair so
// dashboards can pivot by either.
//
// Pass a nil Observer (or noopObserver{}) to disable. The witness calls
// these synchronously from pollOne — implementations must not block on
// network IO or panic; the package's NoopObserver does nothing and is
// safe to leave wired in production until a real one is plugged in.
type Observer interface {
	// OnPoll fires once per chain per polling round. `result` is
	// "ok" / "fetch_failed" / "bad_signature" / "chain_mismatch" /
	// "archive_failed".
	OnPoll(server, chain, result string)
	// OnCosign fires when the witness has just signed a new STH —
	// the operational signal "this witness is actually working".
	OnCosign(server, chain string)
	// OnEquivocation fires every time the archive detects a fork at
	// any tree_size. A counter going > 0 means the server has lied.
	OnEquivocation(server, chain string)
	// OnConsistencyFailure fires when a consistency-proof check
	// between two STHs fails.
	OnConsistencyFailure(server, chain string)
	// OnTreeSize is called after a successful archive so collectors
	// can publish the current max tree_size as a gauge.
	OnTreeSize(server, chain string, size uint64)
}

// NoopObserver does nothing. Useful as the default so callers don't
// need to nil-check; safe to plug in tests.
type NoopObserver struct{}

func (NoopObserver) OnPoll(string, string, string)                {}
func (NoopObserver) OnCosign(string, string)                      {}
func (NoopObserver) OnEquivocation(string, string)                {}
func (NoopObserver) OnConsistencyFailure(string, string)          {}
func (NoopObserver) OnTreeSize(string, string, uint64)            {}

type Witness struct {
	Store      *Store
	HTTP       *http.Client
	Log        *slog.Logger
	Now        func() time.Time // injectable for tests
	Config     Config
	CosignPriv ed25519.PrivateKey
	Observer   Observer
}

// New constructs a Witness with sensible defaults. cfg drives the
// poll targets; logger is required (callers usually pass slog.Default).
func New(store *Store, cfg Config, log *slog.Logger) *Witness {
	if log == nil {
		log = slog.Default()
	}
	return &Witness{
		Store:    store,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Log:      log,
		Now:      time.Now,
		Config:   cfg,
		Observer: NoopObserver{},
	}
}

// EnsurePins persists the pubkey of every configured target into the
// store. Called once at boot so subsequent PollOnce calls can verify
// signatures without re-reading config.
//
// If the operator changes a config pubkey for an already-pinned URL,
// the store rejects with ErrPinMismatch — see Store.PinServer.
func (w *Witness) EnsurePins(ctx context.Context) error {
	c := &w.Config
	if len(c.ServerPub) == 0 {
		// TOFU mode. If a prior run already pinned, reuse the DB row
		// as canonical and don't even talk to the server. If not,
		// fetch /v1/server-info, verify the self-signature, persist.
		pub, err := w.Store.PinnedPub(ctx, c.ServerURL)
		if err == nil {
			w.Log.Info("witness: using existing TOFU pin from store",
				"server", c.ServerURL,
				"pub", fmt.Sprintf("%x", pub[:8]))
			c.ServerPub = pub
		} else {
			if !errors.Is(err, ErrNotPinned) {
				return fmt.Errorf("pin lookup %s: %w", c.ServerURL, err)
			}
			pub, ferr := w.fetchAndVerifyServerPub(ctx, c.ServerURL)
			if ferr != nil {
				return fmt.Errorf("pin_on_first_use %s: %w", c.ServerURL, ferr)
			}
			c.ServerPub = pub
			w.Log.Warn("witness: pinning server pubkey on first contact (TOFU) — verify out-of-band",
				"server", c.ServerURL,
				"pub_hex", fmt.Sprintf("%x", pub))
		}
	}
	if err := w.Store.PinServer(ctx, c.ServerURL, ed25519.PublicKey(c.ServerPub)); err != nil {
		return fmt.Errorf("pin %s: %w", c.ServerURL, err)
	}
	return nil
}

// fetchAndVerifyServerPub fetches /v1/server-info, validates the
// self-signature, and returns the embedded pubkey. The self-signature
// only proves "this server has the key"; out-of-band verification
// against website + other witnesses is still the operator's job.
func (w *Witness) fetchAndVerifyServerPub(ctx context.Context, serverURL string) (ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", serverURL+"/v1/server-info", nil)
	if err != nil {
		return nil, err
	}
	resp, err := w.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /v1/server-info: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTranslogResponseBytes))
	if err != nil {
		return nil, err
	}
	var info translog.ServerInfo
	if err := proto.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("decode server-info: %w", err)
	}
	if err := translog.VerifyServerInfo(info); err != nil {
		return nil, fmt.Errorf("verify server-info: %w", err)
	}
	if len(info.ServerPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("server-info pub wrong size: %d", len(info.ServerPub))
	}
	return ed25519.PublicKey(info.ServerPub), nil
}

// PollOnce runs a single polling pass over every (target, chain).
// Errors per chain are logged but not propagated — one bad chain
// shouldn't take down the whole loop. Returns nil unless the loop
// itself can't proceed (e.g., DB shutting down).
func (w *Witness) PollOnce(ctx context.Context) error {
	for _, chainID := range w.effectiveChains(ctx) {
		w.pollOne(ctx, chainID)
	}
	return nil
}

// effectiveChains returns the union of Config.Chains (static) and the
// server-discovered chain list when Config.AutoDiscover is true.
// Dedupe is O(n) via a set. Discovery failures degrade gracefully —
// the witness keeps polling whatever's in Config.Chains so a flaky
// /v1/chains can't silently drop coverage.
func (w *Witness) effectiveChains(ctx context.Context) []string {
	t := w.Config
	if !t.AutoDiscover {
		return t.Chains
	}
	discovered, err := w.fetchChains(ctx, w.Config.ServerURL)
	if err != nil {
		w.Log.Warn("witness: chain discovery failed — falling back to static config",
			"server", w.Config.ServerURL, "err", err)
		return t.Chains
	}
	seen := make(map[string]struct{}, len(t.Chains)+len(discovered))
	out := make([]string, 0, len(t.Chains)+len(discovered))
	for _, c := range t.Chains {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	for _, c := range discovered {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// Run starts the polling loop. Returns when ctx is canceled.
//
// Per-target poll intervals override the global default. A target's
// first poll fires immediately on Run start; subsequent polls fire
// at the configured interval. If a poll takes longer than the
// interval, the next poll waits one interval after THIS poll
// completes — no overlap.
func (w *Witness) Run(ctx context.Context) error {
	if err := w.EnsurePins(ctx); err != nil {
		return err
	}
	w.Log.Info("witness running", "server", w.Config.ServerURL, "poll_interval", w.Config.PollInterval)
	// First pass.
	_ = w.PollOnce(ctx)
	tick := w.Config.PollInterval
	if tick < time.Second {
		tick = time.Second
	}
	timer := time.NewTicker(tick)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			for _, chainID := range w.effectiveChains(ctx) {
				w.pollOne(ctx, chainID)
			}
		}
	}
}

// smallestInterval is no longer needed (single target). Kept as a
// stub returning Config.PollInterval for any in-tree caller.
func (w *Witness) smallestInterval() time.Duration {
	return w.Config.PollInterval
}

// pollOne handles a single (target, chain_id):
//
//  1. Fetch /v1/sth/{chain_id} → STH
//  2. Verify STH.Signature against the pinned server pubkey + the
//     structural invariants (tree_size > 0 ⇒ root != EmptyRoot, etc.)
//     via translog.VerifySTH.
//  3. Compare against the most-recently-archived STH for this
//     (server, chain):
//     - If no prior STH: archive, log "first STH".
//     - If new tree_size < prior: REGRESSION — log ERROR, archive
//       (so the older + newer rows coexist as evidence of the
//       server going backwards).
//     - If new tree_size == prior + same root: idempotent re-poll,
//       silently no-op.
//     - If new tree_size == prior + DIFFERENT root: same-size
//       fork — log ERROR, archive (Store.Insert sets
//       EquivocationDetected).
//     - If new tree_size > prior: fetch /v1/proof/consistency from
//       prior to new, verify against the pure-layer
//       translog.VerifyConsistency. On failure log ERROR and
//       archive both.
//
// All log emissions go through w.Log so an operator running
// `fd0-witness run | tee /var/log/fd0-witness.log` gets a clean
// audit trail.
func (w *Witness) pollOne(ctx context.Context, chainID string) {
	// Observer hooks. result is set on every early-return branch; the
	// deferred OnPoll fires once per call regardless of how pollOne
	// exits. Collectors get RED-style observability over the loop.
	result := "ok"
	defer func() { w.Observer.OnPoll(w.Config.ServerURL, chainID, result) }()

	pub, err := w.Store.PinnedPub(ctx, w.Config.ServerURL)
	if err != nil {
		result = "missing_pin"
		w.Log.Warn("witness: missing pin", "server", w.Config.ServerURL, "err", err)
		return
	}
	sth, err := w.fetchSTH(ctx, w.Config.ServerURL, chainID)
	if err != nil {
		result = "fetch_failed"
		w.Log.Warn("witness: fetch sth failed", "server", w.Config.ServerURL, "chain", chainID, "err", err)
		return
	}
	if err := translog.VerifySTH(pub, sth); err != nil {
		result = "bad_signature"
		w.Log.Error("witness: BAD STH SIGNATURE — possible MITM or wrong pin",
			"server", w.Config.ServerURL, "chain", chainID, "err", err)
		return
	}
	// Chain-ID binding: STH MUST embed the chain we asked about.
	// Without this check, server could return a sig-valid STH for a
	// different chain and the witness would archive it under the
	// wrong chain (codex C5 review #3).
	if sth.Head.ChainID != chainID {
		result = "chain_mismatch"
		w.Log.Error("witness: STH chain_id mismatch — server returned a different chain",
			"server", w.Config.ServerURL, "requested_chain", chainID, "sth_chain", sth.Head.ChainID)
		return
	}
	// Compute the cosign once — the STH has already passed sig +
	// chain_id binding checks, so attesting "I saw this STH from
	// this server" is honest regardless of any prior-STH comparison
	// outcomes below.
	cosign, cerr := w.signCosign(w.Config.ServerURL, sth)
	if cerr != nil {
		// Cosign is purely additive — log and proceed without it
		// rather than dropping the archive entry.
		w.Log.Warn("witness: cosign skipped", "server", w.Config.ServerURL, "chain", chainID, "err", cerr)
		cosign = nil
	}

	// Trust anchor for the next consistency proof. When this
	// witness has a cosign key, prefer the latest VERIFIED+
	// COSIGNED row — a non-cosigned consistency-fail evidence
	// row must NOT become the anchor (codex audit 🔴 witness.go:200,
	// the "fork laundering" path). Without a cosign key (legacy
	// passive-archive mode), no row is ever cosigned, so the
	// laundering risk doesn't apply and we fall back to the plain
	// LatestSTH semantics.
	var prior translog.STH
	if w.CosignPriv != nil {
		prior, err = w.Store.LatestVerifiedSTH(ctx, w.Config.ServerURL, chainID)
	} else {
		prior, err = w.Store.LatestSTH(ctx, w.Config.ServerURL, chainID)
	}
	switch {
	case errors.Is(err, ErrNoSTH):
		// First contact for this (server, chain). Archive directly.
		res, ierr := w.Store.Insert(ctx, w.Config.ServerURL, sth, w.Now().Unix(), cosign)
		if ierr != nil {
			result = "archive_failed"
			w.Log.Error("witness: archive failed", "err", ierr)
			return
		}
		w.Log.Info("witness: first STH archived",
			"server", w.Config.ServerURL, "chain", chainID,
			"tree_size", sth.Head.TreeSize, "stored", res.Stored, "cosigned", cosign != nil)
		w.Observer.OnTreeSize(w.Config.ServerURL, chainID, sth.Head.TreeSize)
		if cosign != nil {
			w.Observer.OnCosign(w.Config.ServerURL, chainID)
		}
		if res.EquivocationDetected {
			w.Observer.OnEquivocation(w.Config.ServerURL, chainID)
		}
		return
	case err != nil:
		result = "store_failed"
		w.Log.Error("witness: store lookup failed", "err", err)
		return
	}
	// Compare against prior.
	w.compareAndArchive(ctx, chainID, pub, prior, sth, cosign)
}

// signCosign produces a witness cosign over (sth, serverURL) using
// w.CosignPriv. Returns (nil, nil) when no key is configured — the
// caller treats that as "no cosign for this row".
func (w *Witness) signCosign(serverURL string, sth translog.STH) ([]byte, error) {
	if w.CosignPriv == nil {
		return nil, nil
	}
	wsth, err := translog.SignWitnessedSTH(w.CosignPriv, sth, serverURL)
	if err != nil {
		return nil, err
	}
	return wsth.WitnessSig, nil
}

// compareAndArchive contains the prior-vs-new STH decision tree.
// Pulled out so tests can drive it directly without HTTP. `cosign`
// is the witness's signature over (sth, w.Config.ServerURL); may be nil
// if no cosign key is configured or signing failed.
//
// SECURITY: a cosign attests "I observed this STH AND its growth
// from my prior STH was consistent". Any growth-side failure
// (regression, fetch-fail, verify-fail) MUST archive the STH as
// evidence WITHOUT a cosign — otherwise the witness becomes a
// signing oracle for inconsistent forks and a malicious server
// can launder fork evidence into client-acceptable confirmation.
func (w *Witness) compareAndArchive(ctx context.Context, chainID string, pub ed25519.PublicKey, prior, sth translog.STH, cosign []byte) {
	switch {
	case sth.Head.TreeSize < prior.Head.TreeSize:
		// Regression: server is publishing a smaller tree than we
		// previously witnessed. Hard equivocation signal — DO NOT
		// cosign (codex fix #1).
		w.Log.Error("witness: TREE_SIZE REGRESSION (cosign withheld)",
			"server", w.Config.ServerURL, "chain", chainID,
			"prior_size", prior.Head.TreeSize, "new_size", sth.Head.TreeSize)
		// SECURITY (codex audit 🔴 witness.go:255): evidence
		// writes MUST surface their errors. Swallowing them lets
		// disk-full / DB-lock / context-cancel drop equivocation
		// evidence while logs imply it was archived.
		if _, ierr := w.Store.Insert(ctx, w.Config.ServerURL, sth, w.Now().Unix(), nil); ierr != nil {
			w.Log.Error("witness: FAILED to archive regression evidence",
				"server", w.Config.ServerURL, "chain", chainID, "err", ierr)
		}

	case sth.Head.TreeSize == prior.Head.TreeSize:
		// Same size. Either same root (idempotent) or different
		// (equivocation). We DO cosign here — same-size repolls of
		// an unchanged head are routine, and even when the new row
		// is part of equivocation evidence the cosign on each
		// branch is itself the proof artifact (publishing two
		// validly-cosigned WitnessedSTHs at the same size with
		// different roots is the smoking gun).
		res, err := w.Store.Insert(ctx, w.Config.ServerURL, sth, w.Now().Unix(), cosign)
		if err != nil {
			w.Log.Error("witness: archive failed", "err", err)
			return
		}
		w.Observer.OnTreeSize(w.Config.ServerURL, chainID, sth.Head.TreeSize)
		if cosign != nil {
			w.Observer.OnCosign(w.Config.ServerURL, chainID)
		}
		if res.EquivocationDetected {
			w.Observer.OnEquivocation(w.Config.ServerURL, chainID)
			w.emitEquivocationEvidence(ctx, w.Config.ServerURL, chainID, sth.Head.TreeSize)
		}

	default: // sth.Head.TreeSize > prior.Head.TreeSize
		// Tree grew — fetch consistency proof and verify. Only the
		// FULLY-VERIFIED growth gets cosigned. Failed-consistency
		// rows are still archived (so audit can find them) but
		// without the cosign, so the HTTP endpoint will return 404
		// for that size and downstream clients can't be tricked
		// into counting an inconsistent growth as confirmation.
		now := w.Now().Unix()
		proof, err := w.fetchConsistencyProof(ctx, w.Config.ServerURL, chainID, prior.Head.TreeSize, sth.Head.TreeSize)
		if err != nil {
			w.Log.Error("witness: fetch consistency proof failed — archiving STH as unverified-growth evidence (cosign withheld)",
				"server", w.Config.ServerURL, "chain", chainID,
				"from", prior.Head.TreeSize, "to", sth.Head.TreeSize, "err", err)
			if _, ierr := w.Store.Insert(ctx, w.Config.ServerURL, sth, now, nil); ierr != nil {
				w.Log.Error("witness: FAILED to archive unverified-growth evidence",
					"server", w.Config.ServerURL, "chain", chainID, "err", ierr)
			}
			if rerr := w.Store.RecordConsistencyFailure(ctx, w.Config.ServerURL, chainID,
				prior.Head.TreeSize, prior.Head.RootHash,
				sth.Head.TreeSize, sth.Head.RootHash,
				"fetch_failed", now); rerr != nil {
				w.Log.Error("witness: FAILED to record consistency-fetch failure",
					"server", w.Config.ServerURL, "chain", chainID, "err", rerr)
			}
			w.Observer.OnConsistencyFailure(w.Config.ServerURL, chainID)
			return
		}
		if err := translog.VerifyConsistency(prior.Head.TreeSize, sth.Head.TreeSize, proof.Nodes, prior.Head.RootHash, sth.Head.RootHash); err != nil {
			w.Log.Error("witness: CONSISTENCY PROOF FAILED — possible server rewrite or different-size fork (cosign withheld)",
				"server", w.Config.ServerURL, "chain", chainID,
				"from_size", prior.Head.TreeSize, "to_size", sth.Head.TreeSize, "err", err)
			if _, ierr := w.Store.Insert(ctx, w.Config.ServerURL, sth, now, nil); ierr != nil {
				w.Log.Error("witness: FAILED to archive consistency-fail evidence",
					"server", w.Config.ServerURL, "chain", chainID, "err", ierr)
			}
			if rerr := w.Store.RecordConsistencyFailure(ctx, w.Config.ServerURL, chainID,
				prior.Head.TreeSize, prior.Head.RootHash,
				sth.Head.TreeSize, sth.Head.RootHash,
				"verify_failed", now); rerr != nil {
				w.Log.Error("witness: FAILED to record consistency-verify failure",
					"server", w.Config.ServerURL, "chain", chainID, "err", rerr)
			}
			w.Observer.OnConsistencyFailure(w.Config.ServerURL, chainID)
			return
		}
		res, err := w.Store.Insert(ctx, w.Config.ServerURL, sth, now, cosign)
		if err != nil {
			w.Log.Error("witness: archive failed", "err", err)
			return
		}
		if res.Stored {
			w.Log.Info("witness: STH advanced + verified",
				"server", w.Config.ServerURL, "chain", chainID,
				"prior_size", prior.Head.TreeSize, "new_size", sth.Head.TreeSize, "cosigned", cosign != nil)
			w.Observer.OnTreeSize(w.Config.ServerURL, chainID, sth.Head.TreeSize)
			if cosign != nil {
				w.Observer.OnCosign(w.Config.ServerURL, chainID)
			}
		}
	}
}

// emitEquivocationEvidence prints every archived STH at the given
// (server, chain, size) so operators (or downstream automation) can
// publish the multi-root proof.
func (w *Witness) emitEquivocationEvidence(ctx context.Context, serverURL, chainID string, treeSize uint64) {
	rows, err := w.Store.EquivocationsAt(ctx, serverURL, chainID, treeSize)
	if err != nil {
		w.Log.Error("witness: fetch equivocation evidence failed", "err", err)
		return
	}
	w.Log.Error("witness: EQUIVOCATION DETECTED",
		"server", serverURL, "chain", chainID,
		"tree_size", treeSize, "n_distinct_roots", len(rows))
	for i, r := range rows {
		w.Log.Error("witness: equivocation evidence",
			"idx", i, "root_hash_hex", fmt.Sprintf("%x", r.RootHash),
			"timestamp", r.Timestamp, "fetched_at", r.FetchedAt)
	}
}

// fetchSTH issues GET /v1/sth/{chain_id}. The server endpoint is
// unauthenticated by spec (TRANSLOG.md §5).
//
// SECURITY (codex audit 🟡 witness.go:353): bound the read at
// 1 MiB. A malicious pinned server could otherwise OOM the witness
// by streaming an unbounded body before CBOR limits applied.
const maxTranslogResponseBytes = 1 << 20

func (w *Witness) fetchSTH(ctx context.Context, serverURL, chainID string) (translog.STH, error) {
	endpoint := serverURL + "/v1/sth/" + url.PathEscape(chainID)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return translog.STH{}, err
	}
	resp, err := w.HTTP.Do(req)
	if err != nil {
		return translog.STH{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return translog.STH{}, fmt.Errorf("GET /v1/sth/%s: %s", chainID, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTranslogResponseBytes))
	if err != nil {
		return translog.STH{}, err
	}
	var sth translog.STH
	if err := proto.Unmarshal(body, &sth); err != nil {
		return translog.STH{}, fmt.Errorf("decode sth: %w", err)
	}
	return sth, nil
}

// fetchChains issues GET /v1/chains and returns the server's chain
// list. Used by effectiveChains when Target.AutoDiscover is set.
//
// No signature check on the response: chain IDs are not authenticated
// individually (they get authenticated implicitly when the witness
// tries to fetch an STH for one — a MITM-injected fake chain ID just
// produces a 404 or an unverifiable STH and gets logged + skipped).
func (w *Witness) fetchChains(ctx context.Context, serverURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", serverURL+"/v1/chains", nil)
	if err != nil {
		return nil, err
	}
	resp, err := w.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /v1/chains: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTranslogResponseBytes))
	if err != nil {
		return nil, err
	}
	var payload struct {
		Chains []string `cbor:"chains"`
	}
	if err := proto.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode /v1/chains: %w", err)
	}
	return payload.Chains, nil
}

// fetchConsistencyProof issues GET /v1/proof/consistency.
func (w *Witness) fetchConsistencyProof(ctx context.Context, serverURL, chainID string, fromSize, toSize uint64) (translog.ConsistencyProof, error) {
	endpoint := fmt.Sprintf("%s/v1/proof/consistency?chain_id=%s&from_size=%d&to_size=%d",
		serverURL, url.QueryEscape(chainID), fromSize, toSize)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return translog.ConsistencyProof{}, err
	}
	resp, err := w.HTTP.Do(req)
	if err != nil {
		return translog.ConsistencyProof{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return translog.ConsistencyProof{}, fmt.Errorf("GET /v1/proof/consistency: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTranslogResponseBytes))
	if err != nil {
		return translog.ConsistencyProof{}, err
	}
	var p translog.ConsistencyProof
	if err := proto.Unmarshal(body, &p); err != nil {
		return translog.ConsistencyProof{}, fmt.Errorf("decode consistency proof: %w", err)
	}
	return p, nil
}

// VerifyArchive walks every archived STH and re-verifies the
// signature + scans for equivocations. Used by `fd0-witness verify`.
// Returns the count of (errors, equivocations).
func (w *Witness) VerifyArchive(ctx context.Context) (errs, equivs int, err error) {
	sums, err := w.Store.Summary(ctx)
	if err != nil {
		return 0, 0, err
	}
	for _, sr := range sums {
		pub, perr := w.Store.PinnedPub(ctx, sr.ServerURL)
		if perr != nil {
			w.Log.Error("witness verify: missing pin", "server", sr.ServerURL, "err", perr)
			errs++
			continue
		}
		// Walk every STH for this (server, chain) and re-verify sig.
		rows, qerr := w.Store.db.QueryContext(ctx,
			`SELECT tree_size, root_hash, timestamp, signature
			   FROM witness_sths
			  WHERE server_url = ? AND chain_id = ?
			  ORDER BY tree_size`,
			sr.ServerURL, sr.ChainID,
		)
		if qerr != nil {
			return errs, equivs, qerr
		}
		// Codex linter (sqlclosecheck): defer Close so any
		// early-return path doesn't leak the rows iterator.
		defer rows.Close() //nolint:sqlclosecheck // explicit Close below for hot path
		for rows.Next() {
			var (
				size int64
				root []byte
				ts   int64
				sig  []byte
			)
			if scerr := rows.Scan(&size, &root, &ts, &sig); scerr != nil {
				return errs, equivs, scerr
			}
			sth := translog.STH{
				Head: translog.TreeHead{
					ChainID: sr.ChainID, TreeSize: uint64(size),
					RootHash: root, Timestamp: uint64(ts),
				},
				Signature: sig,
			}
			if verr := translog.VerifySTH(pub, sth); verr != nil {
				w.Log.Error("witness verify: BAD STH SIGNATURE",
					"server", sr.ServerURL, "chain", sr.ChainID,
					"tree_size", size, "err", verr)
				errs++
			}
		}
		// Codex audit (🟡 witness.go:417): rows.Err() must be
		// checked AFTER iteration. A cursor / context / SQLite
		// error after a partial scan would otherwise let
		// VerifyArchive report a clean archive while it actually
		// stopped early.
		if rerr := rows.Err(); rerr != nil {
			rows.Close()
			return errs, equivs, rerr
		}
		rows.Close()
		if sr.HasEquivAt {
			equivs++
			w.Log.Error("witness verify: EQUIVOCATION ARCHIVED (same-size multi-root)",
				"server", sr.ServerURL, "chain", sr.ChainID)
		}
		if sr.ConsistencyFailureCount > 0 {
			equivs++
			w.Log.Error("witness verify: CONSISTENCY FAILURES ARCHIVED",
				"server", sr.ServerURL, "chain", sr.ChainID,
				"count", sr.ConsistencyFailureCount)
		}
	}
	return errs, equivs, nil
}
