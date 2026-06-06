package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// ErrWitnessEquivocation is returned when ANY configured witness
// presents a cosigned STH whose root_hash differs from the
// server-provided STH at the same tree_size. This is the
// equivocation-detected case from TRANSLOG.md §11; the client MUST
// refuse to advance.
var ErrWitnessEquivocation = errors.New("witness cross-check: equivocation detected (server's STH disagrees with witness cosign)")

// ErrWitnessInsufficientCosigns is returned when fewer than
// MinCosigns witnesses produced a matching cosign. Distinguished
// from ErrWitnessEquivocation: this one is "couldn't get enough
// confirmation" while the other is "got contradictory evidence".
var ErrWitnessInsufficientCosigns = errors.New("witness cross-check: insufficient matching cosigns")

// WitnessCheckClient cross-checks server-provided STHs against
// configured witnesses. Constructed once per sync round; reused
// across the per-chain verification calls so a single
// misconfiguration doesn't surface six different ways.
type WitnessCheckClient struct {
	HTTP     *http.Client
	Policy   fdhome.WitnessPolicy
	Pinned   []pinnedWitness
	LogF     func(format string, args ...any) // optional debug hook
}

// pinnedWitness pre-decodes the operator-supplied hex pubkey so the
// hot path (one fetch per sync per witness) doesn't do hex parsing.
type pinnedWitness struct {
	URL string
	Pub ed25519.PublicKey
}

// NewWitnessCheckClient builds a client from a Config. Returns nil
// when cross-check is disabled (no [[witness]] entries OR
// MinCosigns == 0). A nil client is the well-defined "no-op" — the
// caller checks for nil and skips the cross-check.
//
// Errors only on hard config problems (bad hex, wrong key length,
// duplicate (URL, pub) tuples). Empty/disabled config is NOT an
// error.
//
// SECURITY: duplicate witness entries are REJECTED at config-load
// rather than deduped silently. Counting the same witness twice
// would let an operator typo or a malicious config edit inflate
// the cross-check quorum: with one real witness duplicated to look
// like two, min_cosigns=2 would be satisfied by a single matching
// response. Loud rejection forces the operator to fix the config.
func NewWitnessCheckClient(cfg fdhome.Config) (*WitnessCheckClient, error) {
	if !cfg.WitnessCrossCheckEnabled() {
		return nil, nil
	}
	pinned := make([]pinnedWitness, 0, len(cfg.Witnesses))
	seen := make(map[string]int, len(cfg.Witnesses)) // key → first-occurrence index
	for i, w := range cfg.Witnesses {
		if w.URL == "" {
			return nil, fmt.Errorf("[[witness]] #%d: url is required", i)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(w.PubHex))
		if err != nil {
			return nil, fmt.Errorf("[[witness]] %s: pub hex decode: %w", w.URL, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("[[witness]] %s: pub must be 32 bytes (got %d)", w.URL, len(raw))
		}
		canonURL := strings.TrimRight(w.URL, "/")
		// SECURITY (codex security audit 🟠 witness_check.go:83):
		// Reject duplicates by URL OR by pub independently. The
		// previous (url+pub) joint key let an attacker present
		// the SAME witness pub at TWO different URLs (e.g. via
		// DNS aliasing or proxy paths) and have both count
		// toward min_cosigns — the same pub signing a cosign
		// once is the same evidence, not two independent ones.
		// The threat: operator with one witness pub spins up a
		// dummy DNS alias and makes their solo witness pretend
		// to satisfy a 2-of-3 quorum.
		pubHex := hex.EncodeToString(raw)
		urlKey := "url:" + canonURL
		pubKey := "pub:" + pubHex
		if first, dup := seen[urlKey]; dup {
			return nil, fmt.Errorf("[[witness]] #%d duplicates [[witness]] #%d by URL %s — each URL must appear at most once",
				i, first, canonURL)
		}
		if first, dup := seen[pubKey]; dup {
			return nil, fmt.Errorf("[[witness]] #%d duplicates [[witness]] #%d by pub %s… — same witness pub at two URLs would inflate the cross-check quorum",
				i, first, pubHex[:16])
		}
		seen[urlKey] = i
		seen[pubKey] = i
		pinned = append(pinned, pinnedWitness{URL: canonURL, Pub: ed25519.PublicKey(raw)})
	}
	if cfg.WitnessP.MinCosigns > len(pinned) {
		return nil, fmt.Errorf("witness_policy.min_cosigns=%d exceeds configured witness count %d",
			cfg.WitnessP.MinCosigns, len(pinned))
	}
	return &WitnessCheckClient{
		HTTP:   &http.Client{Timeout: 10 * time.Second},
		Policy: cfg.WitnessP,
		Pinned: pinned,
	}, nil
}

// CrossCheckSTH consults every configured witness for a cosign at
// `sth.Head.TreeSize` for the given (serverURL, sth.Head.ChainID)
// and decides whether the policy threshold is met.
//
// Decision matrix (per witness):
//
//   - HTTP 200 + cosign verifies + roots match     → matching cosign (+1)
//   - HTTP 200 + cosign verifies + roots differ    → EQUIVOCATION → return immediately
//   - HTTP 200 + cosign verifies + chain_id differs → bad-cosign (skip)
//   - HTTP 200 + cosign verify fails               → bad-cosign (skip)
//   - HTTP 409 (witness archive holds multi-root)  → EQUIVOCATION → return immediately
//   - HTTP 404 (witness lagging or no cosign yet)  → no-confirmation (skip)
//   - any other transport error                    → unreachable (skip)
//
// MinCosigns is the ABSOLUTE floor — lag, unreachability, and
// bad-cosign all count equally as "this witness did not confirm".
// There is no policy knob that lowers the threshold based on
// observed witness behavior, because such a knob lets an attacker
// who can DOS witnesses also lower the cross-check bar to zero
// (codex fix #3).
//
// Equivocation (whether cross-witness or within a single witness
// archive) always rejects regardless of policy.
//
// THREAT: T35 (server equivocation between clients),
//         T39 (bad-cosign / forged witness response),
//         T40 (witness archive itself shows equivocation),
//         T41 (first-fetch checkpoint rollback — witness highest probe),
//         T43 (equivocation across servers by URL).
func (c *WitnessCheckClient) CrossCheckSTH(ctx context.Context, serverURL canon.URL, serverPub ed25519.PublicKey, sth translog.STH) error {
	if c == nil || c.Policy.MinCosigns <= 0 {
		return nil
	}
	// C4 + C5: chain-level probes are run per-witness AFTER its
	// cosign fetch (codex review fix: doing it as a separate
	// pre-pass leaves a race where the witness archives
	// evidence between probe and cosign lookup, and the now-
	// stale cosign would still count). Probes are best-effort
	// — non-200 / decode errors fall through to the threshold
	// check so an offline / old / lagging witness doesn't block
	// sync.
	// Probe a witness for chain-level evidence. Returns an error
	// suitable for CrossCheckSTH's hard-refuse path on positive
	// evidence; nil if the witness has nothing to report (or is
	// unreachable / running an older build that doesn't expose
	// these endpoints — best-effort semantics).
	checkChainProbes := func(w pinnedWitness) error {
		if eq, perr := c.fetchEquivocationProbe(ctx, w.URL, serverURL.String(), sth.Head.ChainID); perr == nil && eq {
			return fmt.Errorf("%w: chain=%s witness=%s reports historical multi-root",
				ErrWitnessEquivocation, sth.Head.ChainID, w.URL)
		}
		if hi, observed, perr := c.fetchHighestProbe(ctx, w.URL, serverURL.String(), sth.Head.ChainID); perr == nil && observed && hi > sth.Head.TreeSize {
			return fmt.Errorf("%w: chain=%s server_size=%d witness=%s observed_size=%d (rollback)",
				ErrWitnessEquivocation, sth.Head.ChainID, sth.Head.TreeSize, w.URL, hi)
		}
		return nil
	}
	matching := 0
	var skipReasons []string
	for _, w := range c.Pinned {
		// C4 + C5 (codex 3rd race-fix): chain-level probes run
		// UNCONDITIONALLY for every witness — regardless of
		// whether its size-N cosign counts. Two reasons:
		//   1. A witness that's only observed N+1 returns 404
		//      for /sth?tree_size=N but is exactly the witness
		//      that knows about the rollback evidence.
		//   2. Closes the original "probe at T1, witness archives
		//      at T2, cosign succeeds at T3 with stale T1
		//      probe-state" race — the probe runs AFTER the
		//      cosign fetch in this iteration so any state
		//      change between cosign and probe is caught here
		//      (and across iterations, the next witness gets a
		//      fresh probe regardless).
		out, err := c.fetchWitnessedSTH(ctx, w.URL, serverURL.String(), sth.Head.ChainID, sth.Head.TreeSize)
		switch {
		case errors.Is(err, errWitnessEquivocation):
			// Codex fix #2: witness archive itself holds the
			// smoking gun. Refuse to advance immediately.
			return fmt.Errorf("%w: chain=%s size=%d witness=%s reports multi-root archive",
				ErrWitnessEquivocation, sth.Head.ChainID, sth.Head.TreeSize, w.URL)
		case errors.Is(err, errWitnessNotObserved):
			// Witness has no cosign for this tree_size — but it
			// might have rollback / equivocation evidence at OTHER
			// sizes. Probe before continuing.
			if perr := checkChainProbes(w); perr != nil {
				return perr
			}
			skipReasons = append(skipReasons, fmt.Sprintf("%s: not-observed", w.URL))
			continue
		case err != nil:
			// Probe even on transport error so a witness that's
			// reachable for the cheaper probe endpoints (but not
			// /sth) can still surface evidence.
			if perr := checkChainProbes(w); perr != nil {
				return perr
			}
			skipReasons = append(skipReasons, fmt.Sprintf("%s: unreachable(%v)", w.URL, err))
			continue
		}
		// Cryptographic verification: cosign must be valid AND
		// embedded STH must verify under the SAME server pub the
		// client uses. Without this a hostile witness could sign
		// anything.
		// Codex fix #4: VerifyWitnessedSTH now requires the
		// expected chain_id. A cosign for a sibling chain on the
		// same server with the same (size, root) is rejected
		// inside the verifier, so the cli code path can't forget
		// the check.
		if err := translog.VerifyWitnessedSTH(serverPub, w.Pub, serverURL.String(), sth.Head.ChainID, out); err != nil {
			// Probe even on bad-cosign — the witness might still
			// have rollback / equivocation evidence at other
			// sizes despite returning a malformed cosign at this
			// one (codex 4th-round race-fix).
			if perr := checkChainProbes(w); perr != nil {
				return perr
			}
			skipReasons = append(skipReasons, fmt.Sprintf("%s: bad-cosign(%v)", w.URL, err))
			continue
		}
		if out.STH.Head.TreeSize != sth.Head.TreeSize {
			// Witness gave a row at a DIFFERENT tree_size despite
			// our explicit ?tree_size=N. Don't count it (the
			// witness is misbehaving). Probe before skipping.
			if perr := checkChainProbes(w); perr != nil {
				return perr
			}
			skipReasons = append(skipReasons, fmt.Sprintf("%s: size-drift(want=%d got=%d)", w.URL, sth.Head.TreeSize, out.STH.Head.TreeSize))
			continue
		}
		if !equalBytes(out.STH.Head.RootHash, sth.Head.RootHash) {
			return fmt.Errorf("%w: chain=%s size=%d server_root=%x witness=%s witness_root=%x",
				ErrWitnessEquivocation, sth.Head.ChainID, sth.Head.TreeSize,
				sth.Head.RootHash, w.URL, out.STH.Head.RootHash)
		}
		// Probe AFTER successful cosign so any archive update
		// during the cosign fetch surfaces here (closes the
		// original race codex caught).
		if perr := checkChainProbes(w); perr != nil {
			return perr
		}
		matching++
	}
	if matching < c.Policy.MinCosigns {
		return fmt.Errorf("%w: got %d matching, need %d for chain=%s size=%d (%s)",
			ErrWitnessInsufficientCosigns, matching, c.Policy.MinCosigns,
			sth.Head.ChainID, sth.Head.TreeSize, strings.Join(skipReasons, "; "))
	}
	return nil
}

// Internal sentinels for HTTP outcomes; the policy logic only
// special-cases these two so every other transport / decode
// failure collapses to a generic "unreachable" error.
var (
	errWitnessNotObserved = errors.New("witness has not observed this size")
	errWitnessEquivocation = errors.New("witness archive holds multiple distinct roots at this size")
)

func (c *WitnessCheckClient) fetchWitnessedSTH(ctx context.Context, witnessURL, serverURL, chainID string, treeSize uint64) (translog.WitnessedSTH, error) {
	endpoint := fmt.Sprintf("%s/v1/sth/%s/%s?tree_size=%d",
		witnessURL,
		encodeServerURL(serverURL),
		chainID,
		treeSize,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return translog.WitnessedSTH{}, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return translog.WitnessedSTH{}, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to body decode
	case http.StatusNotFound:
		return translog.WitnessedSTH{}, errWitnessNotObserved
	case http.StatusConflict:
		// 409 = witness's own archive holds multi-root evidence
		// (codex fix #2). Caller surfaces this as equivocation.
		return translog.WitnessedSTH{}, errWitnessEquivocation
	default:
		return translog.WitnessedSTH{}, fmt.Errorf("witness returned HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return translog.WitnessedSTH{}, err
	}
	var w translog.WitnessedSTH
	if err := proto.Unmarshal(body, &w); err != nil {
		return translog.WitnessedSTH{}, fmt.Errorf("decode WitnessedSTH: %w", err)
	}
	return w, nil
}

// encodeServerURL is base64.RawURLEncoding (no padding, path-safe).
// Identical to witness.EncodeServerURL on the server side; we
// inline rather than import to keep the cli package leaf-only.
func encodeServerURL(raw string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// highestProbeResponse mirrors witness.HighestResponse on the
// wire so we don't import the witness package (cli must stay
// leaf-only on the server-side packages).
type highestProbeResponse struct {
	Observed bool   `cbor:"observed"`
	TreeSize uint64 `cbor:"tree_size"`
}

// equivProbeResponse mirrors witness.EquivocationResponse.
type equivProbeResponse struct {
	Equivocated bool `cbor:"equivocated"`
}

// fetchHighestProbe queries
// GET /v1/highest/<server>/<chain> for the C4 freshness
// probe. Returns (max_tree_size, observed, error). A 404 / non-OK
// response or any decode error returns observed=false so the
// caller treats it as "witness can't help here, fall through to
// the cosign loop" rather than refusing. Hard refusal happens
// only when observed=true AND the witness's max > server-supplied
// size.
func (c *WitnessCheckClient) fetchHighestProbe(ctx context.Context, witnessURL, serverURL, chainID string) (uint64, bool, error) {
	endpoint := fmt.Sprintf("%s/v1/highest/%s/%s",
		witnessURL, encodeServerURL(serverURL), chainID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, false, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("witness highest: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return 0, false, err
	}
	var r highestProbeResponse
	if err := proto.Unmarshal(body, &r); err != nil {
		return 0, false, err
	}
	return r.TreeSize, r.Observed, nil
}

// fetchEquivocationProbe queries
// GET /v1/equivocation/<server>/<chain> for the C5
// chain-level equivocation probe. Returns (equivocated, error).
// On any non-OK / decode failure returns false so the caller
// treats the probe as "witness can't help here" rather than
// refusing.
func (c *WitnessCheckClient) fetchEquivocationProbe(ctx context.Context, witnessURL, serverURL, chainID string) (bool, error) {
	endpoint := fmt.Sprintf("%s/v1/equivocation/%s/%s",
		witnessURL, encodeServerURL(serverURL), chainID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("witness equivocation: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return false, err
	}
	var r equivProbeResponse
	if err := proto.Unmarshal(body, &r); err != nil {
		return false, err
	}
	return r.Equivocated, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
