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
type Witness struct {
	Store      *Store
	HTTP       *http.Client
	Log        *slog.Logger
	Now        func() time.Time // injectable for tests
	Config     Config
	CosignPriv ed25519.PrivateKey
}

// New constructs a Witness with sensible defaults. cfg drives the
// poll targets; logger is required (callers usually pass slog.Default).
func New(store *Store, cfg Config, log *slog.Logger) *Witness {
	if log == nil {
		log = slog.Default()
	}
	return &Witness{
		Store:  store,
		HTTP:   &http.Client{Timeout: 30 * time.Second},
		Log:    log,
		Now:    time.Now,
		Config: cfg,
	}
}

// EnsurePins persists the pubkey of every configured target into the
// store. Called once at boot so subsequent PollOnce calls can verify
// signatures without re-reading config.
//
// If the operator changes a config pubkey for an already-pinned URL,
// the store rejects with ErrPinMismatch — see Store.PinServer.
func (w *Witness) EnsurePins(ctx context.Context) error {
	for _, t := range w.Config.Targets {
		if err := w.Store.PinServer(ctx, t.ServerURL, ed25519.PublicKey(t.ServerPub)); err != nil {
			return fmt.Errorf("pin %s: %w", t.ServerURL, err)
		}
	}
	return nil
}

// PollOnce runs a single polling pass over every (target, chain).
// Errors per chain are logged but not propagated — one bad chain
// shouldn't take down the whole loop. Returns nil unless the loop
// itself can't proceed (e.g., DB shutting down).
func (w *Witness) PollOnce(ctx context.Context) error {
	for _, t := range w.Config.Targets {
		for _, chainID := range t.Chains {
			w.pollOne(ctx, t, chainID)
		}
	}
	return nil
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
	w.Log.Info("witness running", "targets", len(w.Config.Targets))
	// First pass.
	_ = w.PollOnce(ctx)
	// Use the smallest configured interval as the global tick. Each
	// target keeps its own "next poll" time so longer-interval ones
	// just skip ticks. Simple, no goroutine-per-target zoo.
	tick := w.smallestInterval()
	if tick < time.Second {
		tick = time.Second
	}
	timer := time.NewTicker(tick)
	defer timer.Stop()
	// Key by target index (not URL) so two targets sharing the same
	// URL but with different chains/intervals are tracked
	// independently — codex C5 review #4.
	nextPoll := make(map[int]time.Time, len(w.Config.Targets))
	for i, t := range w.Config.Targets {
		nextPoll[i] = w.Now().Add(t.PollInterval)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			now := w.Now()
			for i, t := range w.Config.Targets {
				if nextPoll[i].After(now) {
					continue
				}
				for _, chainID := range t.Chains {
					w.pollOne(ctx, t, chainID)
				}
				nextPoll[i] = now.Add(t.PollInterval)
			}
		}
	}
}

func (w *Witness) smallestInterval() time.Duration {
	min := time.Hour
	for _, t := range w.Config.Targets {
		if t.PollInterval > 0 && t.PollInterval < min {
			min = t.PollInterval
		}
	}
	return min
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
func (w *Witness) pollOne(ctx context.Context, t Target, chainID string) {
	pub, err := w.Store.PinnedPub(ctx, t.ServerURL)
	if err != nil {
		w.Log.Warn("witness: missing pin", "server", t.ServerURL, "err", err)
		return
	}
	sth, err := w.fetchSTH(ctx, t.ServerURL, chainID)
	if err != nil {
		w.Log.Warn("witness: fetch sth failed", "server", t.ServerURL, "chain", chainID, "err", err)
		return
	}
	if err := translog.VerifySTH(pub, sth); err != nil {
		w.Log.Error("witness: BAD STH SIGNATURE — possible MITM or wrong pin",
			"server", t.ServerURL, "chain", chainID, "err", err)
		return
	}
	// Chain-ID binding: STH MUST embed the chain we asked about.
	// Without this check, server could return a sig-valid STH for a
	// different chain and the witness would archive it under the
	// wrong chain (codex C5 review #3).
	if sth.Head.ChainID != chainID {
		w.Log.Error("witness: STH chain_id mismatch — server returned a different chain",
			"server", t.ServerURL, "requested_chain", chainID, "sth_chain", sth.Head.ChainID)
		return
	}
	// Compute the cosign once — the STH has already passed sig +
	// chain_id binding checks, so attesting "I saw this STH from
	// this server" is honest regardless of any prior-STH comparison
	// outcomes below.
	cosign, cerr := w.signCosign(t.ServerURL, sth)
	if cerr != nil {
		// Cosign is purely additive — log and proceed without it
		// rather than dropping the archive entry.
		w.Log.Warn("witness: cosign skipped", "server", t.ServerURL, "chain", chainID, "err", cerr)
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
		prior, err = w.Store.LatestVerifiedSTH(ctx, t.ServerURL, chainID)
	} else {
		prior, err = w.Store.LatestSTH(ctx, t.ServerURL, chainID)
	}
	switch {
	case errors.Is(err, ErrNoSTH):
		// First contact for this (server, chain). Archive directly.
		res, ierr := w.Store.Insert(ctx, t.ServerURL, sth, w.Now().Unix(), cosign)
		if ierr != nil {
			w.Log.Error("witness: archive failed", "err", ierr)
			return
		}
		w.Log.Info("witness: first STH archived",
			"server", t.ServerURL, "chain", chainID,
			"tree_size", sth.Head.TreeSize, "stored", res.Stored, "cosigned", cosign != nil)
		return
	case err != nil:
		w.Log.Error("witness: store lookup failed", "err", err)
		return
	}
	// Compare against prior.
	w.compareAndArchive(ctx, t, chainID, pub, prior, sth, cosign)
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
// is the witness's signature over (sth, t.ServerURL); may be nil
// if no cosign key is configured or signing failed.
//
// SECURITY: a cosign attests "I observed this STH AND its growth
// from my prior STH was consistent". Any growth-side failure
// (regression, fetch-fail, verify-fail) MUST archive the STH as
// evidence WITHOUT a cosign — otherwise the witness becomes a
// signing oracle for inconsistent forks and a malicious server
// can launder fork evidence into client-acceptable confirmation.
func (w *Witness) compareAndArchive(ctx context.Context, t Target, chainID string, pub ed25519.PublicKey, prior, sth translog.STH, cosign []byte) {
	switch {
	case sth.Head.TreeSize < prior.Head.TreeSize:
		// Regression: server is publishing a smaller tree than we
		// previously witnessed. Hard equivocation signal — DO NOT
		// cosign (codex fix #1).
		w.Log.Error("witness: TREE_SIZE REGRESSION (cosign withheld)",
			"server", t.ServerURL, "chain", chainID,
			"prior_size", prior.Head.TreeSize, "new_size", sth.Head.TreeSize)
		// SECURITY (codex audit 🔴 witness.go:255): evidence
		// writes MUST surface their errors. Swallowing them lets
		// disk-full / DB-lock / context-cancel drop equivocation
		// evidence while logs imply it was archived.
		if _, ierr := w.Store.Insert(ctx, t.ServerURL, sth, w.Now().Unix(), nil); ierr != nil {
			w.Log.Error("witness: FAILED to archive regression evidence",
				"server", t.ServerURL, "chain", chainID, "err", ierr)
		}

	case sth.Head.TreeSize == prior.Head.TreeSize:
		// Same size. Either same root (idempotent) or different
		// (equivocation). We DO cosign here — same-size repolls of
		// an unchanged head are routine, and even when the new row
		// is part of equivocation evidence the cosign on each
		// branch is itself the proof artifact (publishing two
		// validly-cosigned WitnessedSTHs at the same size with
		// different roots is the smoking gun).
		res, err := w.Store.Insert(ctx, t.ServerURL, sth, w.Now().Unix(), cosign)
		if err != nil {
			w.Log.Error("witness: archive failed", "err", err)
			return
		}
		if res.EquivocationDetected {
			w.emitEquivocationEvidence(ctx, t.ServerURL, chainID, sth.Head.TreeSize)
		}

	default: // sth.Head.TreeSize > prior.Head.TreeSize
		// Tree grew — fetch consistency proof and verify. Only the
		// FULLY-VERIFIED growth gets cosigned. Failed-consistency
		// rows are still archived (so audit can find them) but
		// without the cosign, so the HTTP endpoint will return 404
		// for that size and downstream clients can't be tricked
		// into counting an inconsistent growth as confirmation.
		now := w.Now().Unix()
		proof, err := w.fetchConsistencyProof(ctx, t.ServerURL, chainID, prior.Head.TreeSize, sth.Head.TreeSize)
		if err != nil {
			w.Log.Error("witness: fetch consistency proof failed — archiving STH as unverified-growth evidence (cosign withheld)",
				"server", t.ServerURL, "chain", chainID,
				"from", prior.Head.TreeSize, "to", sth.Head.TreeSize, "err", err)
			if _, ierr := w.Store.Insert(ctx, t.ServerURL, sth, now, nil); ierr != nil {
				w.Log.Error("witness: FAILED to archive unverified-growth evidence",
					"server", t.ServerURL, "chain", chainID, "err", ierr)
			}
			if rerr := w.Store.RecordConsistencyFailure(ctx, t.ServerURL, chainID,
				prior.Head.TreeSize, prior.Head.RootHash,
				sth.Head.TreeSize, sth.Head.RootHash,
				"fetch_failed", now); rerr != nil {
				w.Log.Error("witness: FAILED to record consistency-fetch failure",
					"server", t.ServerURL, "chain", chainID, "err", rerr)
			}
			return
		}
		if err := translog.VerifyConsistency(prior.Head.TreeSize, sth.Head.TreeSize, proof.Nodes, prior.Head.RootHash, sth.Head.RootHash); err != nil {
			w.Log.Error("witness: CONSISTENCY PROOF FAILED — possible server rewrite or different-size fork (cosign withheld)",
				"server", t.ServerURL, "chain", chainID,
				"from_size", prior.Head.TreeSize, "to_size", sth.Head.TreeSize, "err", err)
			if _, ierr := w.Store.Insert(ctx, t.ServerURL, sth, now, nil); ierr != nil {
				w.Log.Error("witness: FAILED to archive consistency-fail evidence",
					"server", t.ServerURL, "chain", chainID, "err", ierr)
			}
			if rerr := w.Store.RecordConsistencyFailure(ctx, t.ServerURL, chainID,
				prior.Head.TreeSize, prior.Head.RootHash,
				sth.Head.TreeSize, sth.Head.RootHash,
				"verify_failed", now); rerr != nil {
				w.Log.Error("witness: FAILED to record consistency-verify failure",
					"server", t.ServerURL, "chain", chainID, "err", rerr)
			}
			return
		}
		res, err := w.Store.Insert(ctx, t.ServerURL, sth, now, cosign)
		if err != nil {
			w.Log.Error("witness: archive failed", "err", err)
			return
		}
		if res.Stored {
			w.Log.Info("witness: STH advanced + verified",
				"server", t.ServerURL, "chain", chainID,
				"prior_size", prior.Head.TreeSize, "new_size", sth.Head.TreeSize, "cosigned", cosign != nil)
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return translog.STH{}, err
	}
	var sth translog.STH
	if err := proto.Unmarshal(body, &sth); err != nil {
		return translog.STH{}, fmt.Errorf("decode sth: %w", err)
	}
	return sth, nil
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
	body, err := io.ReadAll(resp.Body)
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
		for rows.Next() {
			var (
				size int64
				root []byte
				ts   int64
				sig  []byte
			)
			if scerr := rows.Scan(&size, &root, &ts, &sig); scerr != nil {
				rows.Close()
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
