package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// Translog client-side verification + first-contact pinning lives in
// this file (TRANSLOG.md §6). The split from sync.go is deliberate:
// the sync flow remains the network state machine, while everything
// related to "trust this server's pubkey" and "verify this STH/proof"
// is grouped here so a future audit can read the verification logic
// in one place without spelunking sync.

// Sentinel errors for client-side translog enforcement.
var (
	// ErrPinnedKeyMismatch fires when /v1/server-info returns a
	// pubkey for a server URL that doesn't match the previously-
	// pinned bytes. Per TRANSLOG.md §6.4, the client MUST refuse
	// any further interaction with this URL until the user
	// re-pins (typically via a `fd0 server pin --reset` ceremony,
	// not implemented in v1.0).
	ErrPinnedKeyMismatch = errors.New("translog: pinned server pubkey mismatch — refusing all interaction (TRANSLOG.md §6.4)")

	// ErrServerInfoUnsigned fires when /v1/server-info is missing
	// or its self-signature does not verify. Strongly indicates the
	// server is not running an fd0-server build with translog
	// support, or the response was tampered in transit (TLS broken).
	ErrServerInfoUnsigned = errors.New("translog: /v1/server-info self-signature failed")

	// ErrSTHMissing fires when a server response that should carry
	// an STH (per TRANSLOG.md §5.4 "MANDATORY") omits it. Treated as
	// a hard fail — accepting events without STH would defeat the
	// equivocation-detection guarantee.
	ErrSTHMissing = errors.New("translog: server response missing mandatory STH")

	// ErrInclusionMismatch / ErrConsistencyMismatch promote the
	// pure-layer ErrInclusionProofInvalid / ErrConsistencyProofInvalid
	// to client-facing errors that doctor / sync surface as red
	// banners.
	ErrInclusionMismatch  = errors.New("translog: inclusion proof failed")
	ErrConsistencyMismatch = errors.New("translog: consistency proof failed — possible server equivocation or rewrite")
)

// FD0AutoPinEnv, when set to "1", auto-confirms first-contact pinning
// without an interactive prompt. Used by integration tests and by
// non-interactive operator workflows. Production interactive use
// SHOULD always go through the prompt — auto-pin disables the safety-
// number ceremony entirely.
const FD0AutoPinEnv = "FD0_AUTO_PIN"

// NormalizeServerURL canonicalises a server URL for use as the map key
// in PinnedServers. Two visually different URLs that point at the same
// server (e.g., trailing slash, mixed case host) MUST produce the same
// pin entry — otherwise a user types one form, pins, then later types
// the other and gets a TOFU prompt for "the same" server.
//
// Normalisation:
//   - lowercase scheme
//   - lowercase host (RFC 3986 §3.2.2)
//   - strip trailing slash from path
//   - drop fragment + query (a server URL must not carry these)
//
// Returns (normalised, error). An empty URL or a parse failure yields
// a non-nil error so callers don't silently skip the pinning gate.
func NormalizeServerURL(s string) (string, error) {
	if s == "" {
		return "", errors.New("server URL is empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("server URL must include scheme and host: %q", s)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// ServerFingerprint is the user-facing display string for a server
// pubkey, formatted exactly like SafetyNumber for identity cards so
// the operator's eyes don't have to learn a second visual idiom.
//
//	digest = SHA-256("fd0-server-fingerprint-v1" || cbor({url, pub}))
//	first 24 bytes → 12 groups of 5 decimal digits → 3 lines × 4 groups
//
// Binding the digest to the URL prevents a swapped-server-with-same-pub
// attack from being indistinguishable from a legitimate re-pin.
func ServerFingerprint(serverURL string, pub []byte) (string, error) {
	body, err := proto.Marshal(struct {
		URL string `cbor:"url"`
		Pub []byte `cbor:"pub"`
	}{serverURL, pub})
	if err != nil {
		return "", err
	}
	in := append([]byte(proto.DomainServerFingerprint), body...)
	sum := sha256.Sum256(in)
	groups := make([]string, 12)
	for i := 0; i < 12; i++ {
		v := uint16(sum[i*2])<<8 | uint16(sum[i*2+1])
		groups[i] = fmt.Sprintf("%05d", v)
	}
	var lines []string
	for i := 0; i < 12; i += 4 {
		lines = append(lines, strings.Join(groups[i:i+4], " "))
	}
	return strings.Join(lines, "\n"), nil
}

// EnsurePinnedServer reads the current pin for serverURL from the
// vault. If absent, fetches /v1/server-info, verifies the
// self-signature, runs the safety-number ceremony (or auto-confirms
// when FD0_AUTO_PIN=1), and persists the pin. If present, refetches
// /v1/server-info and refuses on mismatch.
//
// Returns the pinned pubkey on success. Persists the vault on first
// pin AND on no-op refetch (to update PinnedAt timestamp would be
// wasteful — we don't bother, persistence only happens on first pin).
//
// The session is mutated in place (s.Body.PinnedServers gets a new
// entry on first pin); caller is responsible for s.ReSeal afterwards.
func (s *Session) EnsurePinnedServer(ctx context.Context, serverURL string) (ed25519.PublicKey, error) {
	canonical, err := NormalizeServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	info, err := fetchServerInfo(ctx, canonical)
	if err != nil {
		return nil, err
	}
	if err := translog.VerifyServerInfo(info); err != nil {
		return nil, ErrServerInfoUnsigned
	}
	if s.Body.PinnedServers == nil {
		s.Body.PinnedServers = map[string]proto.PinnedServer{}
	}
	if existing, ok := s.Body.PinnedServers[canonical]; ok {
		// Re-pin gate: the cached pub MUST match what the server
		// just published. Any divergence is either rotation
		// (legitimate, but requires manual ceremony — out of v1.0
		// scope) or attack (illegitimate). Either way: refuse.
		if !bytes.Equal(existing.ServerPub, info.ServerPub) {
			return nil, ErrPinnedKeyMismatch
		}
		return ed25519.PublicKey(existing.ServerPub), nil
	}
	// First contact: TOFU.
	if err := pinningPrompt(canonical, info.ServerPub); err != nil {
		return nil, err
	}
	s.Body.PinnedServers[canonical] = proto.PinnedServer{
		ServerPub: append([]byte(nil), info.ServerPub...),
		PinnedAt:  uint64(nowUnix()),
	}
	if err := s.ReSeal(); err != nil {
		return nil, fmt.Errorf("persist pinned server: %w", err)
	}
	return ed25519.PublicKey(info.ServerPub), nil
}

// pinningPrompt displays the safety number for (url, pub) and gates
// the pin on user confirmation.
//
// Policy:
//   - Interactive (stdin is TTY): prompt y/N. User confirms after
//     verifying the fingerprint out of band.
//   - Non-interactive (no TTY) AND FD0_AUTO_PIN=1: auto-confirm. The
//     opt-in env var is required so an operator must consciously
//     enable scripted pinning. Otherwise a MITM during the very first
//     agent-spawned sync could pin its own pubkey and the user would
//     never see the prompt.
//   - Non-interactive WITHOUT FD0_AUTO_PIN=1: refuse with an error
//     pointing at the env var. Codex C4 review #3.
//
// The fingerprint is ALWAYS printed; the only thing the auto-confirm
// path skips is blocking on stdin.
func pinningPrompt(canonical string, pub []byte) error {
	fp, err := ServerFingerprint(canonical, pub)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nFirst contact with server %s\n", canonical)
	fmt.Fprintf(os.Stderr, "Server fingerprint (verify out-of-band):\n%s\n\n", indent(fp, "  "))
	autoPin := os.Getenv(FD0AutoPinEnv) == "1"
	tty := IsTTY(os.Stdin)
	switch {
	case autoPin:
		fmt.Fprintln(os.Stderr, "✓ auto-pinned (FD0_AUTO_PIN=1; verify the fingerprint above out of band)")
		return nil
	case !tty:
		return fmt.Errorf("first-contact pinning required but stdin is not a TTY; set %s=1 to opt into unattended pinning (and verify the printed fingerprint out of band)", FD0AutoPinEnv)
	}
	fmt.Fprint(os.Stderr, "Pin this server? [y/N] ")
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read confirmation: %w", err)
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "y" && line != "yes" {
		return errors.New("server pinning refused by user")
	}
	return nil
}

// fetchServerInfo issues an unauthenticated GET /v1/server-info to
// canonicalURL and decodes the response. Used by EnsurePinnedServer
// (boot-time first contact) and by future repin commands.
func fetchServerInfo(ctx context.Context, canonicalURL string) (translog.ServerInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", canonicalURL+"/v1/server-info", nil)
	if err != nil {
		return translog.ServerInfo{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return translog.ServerInfo{}, fmt.Errorf("fetch /v1/server-info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return translog.ServerInfo{}, fmt.Errorf("/v1/server-info: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return translog.ServerInfo{}, err
	}
	var info translog.ServerInfo
	if err := proto.Unmarshal(body, &info); err != nil {
		return translog.ServerInfo{}, fmt.Errorf("decode /v1/server-info: %w", err)
	}
	return info, nil
}

// ErrSTHTreeSizeRegression fires when the server publishes a smaller
// tree_size than the client's persisted LastSTH. Per TRANSLOG.md §6.4
// this is a hard refuse — server invariant break (tree only grows).
var ErrSTHTreeSizeRegression = errors.New("translog: STH tree_size went backwards — refusing")

// VerifyTranslogResponse checks the STH signature + chain_id binding,
// every inclusion proof (with leaf_index and tree_size matching), and
// the optional consistency proof for one chain's response payload.
//
// Parameters:
//   - pinnedPub: the previously-pinned server pubkey (binds STH origin).
//   - expectedChainID: the chain we asked about ("user:..." or
//     "scope:..."). The server's STH MUST embed this exact id, else
//     it could swap chains across requests undetectably.
//   - sth: the response's STH (mandatory when chain has events).
//   - priorSTH: client's persisted LastSTH (nil = fresh subscription).
//   - inclusionProofs / expectedLeafIndices / eventLeafHashes: each
//     slice must be the same length; index i lines up across all
//     three. expectedLeafIndices MUST match what the server returned
//     in proof.LeafIndex — otherwise a malicious server could prove
//     leaf 5 is in the tree while the client thinks it proved leaf 7.
//   - consistency: present iff caller supplied last_sth_size > 0.
//
// Empty-events shortcut: if `sth == nil` AND no events, this is a
// no-op (per TRANSLOG.md §6.2 "MAY include" for empty pulls). Caller
// should NOT update LastSTH in that case.
//
// All verification errors are surfaced as ErrInclusionMismatch /
// ErrConsistencyMismatch / ErrSTHMissing / ErrSTHTreeSizeRegression
// so the caller can react uniformly.
func VerifyTranslogResponse(
	pinnedPub ed25519.PublicKey,
	expectedChainID string,
	sth *translog.STH,
	priorSTH *translog.STH,
	inclusionProofs []translog.InclusionProof,
	expectedLeafIndices []uint64,
	eventLeafHashes [][]byte,
	consistency *translog.ConsistencyProof,
) error {
	if sth == nil {
		if len(eventLeafHashes) == 0 && priorSTH == nil {
			// No data, no anchor — nothing to verify.
			return nil
		}
		return ErrSTHMissing
	}
	if sth.Head.ChainID != expectedChainID {
		return fmt.Errorf("translog: STH chain_id %q != expected %q",
			sth.Head.ChainID, expectedChainID)
	}
	if priorSTH != nil && sth.Head.TreeSize < priorSTH.Head.TreeSize {
		return fmt.Errorf("%w: %d < %d", ErrSTHTreeSizeRegression,
			sth.Head.TreeSize, priorSTH.Head.TreeSize)
	}
	if err := translog.VerifySTH(pinnedPub, *sth); err != nil {
		return fmt.Errorf("STH signature: %w", err)
	}
	if len(inclusionProofs) != len(eventLeafHashes) || len(inclusionProofs) != len(expectedLeafIndices) {
		return fmt.Errorf("translog: inclusion-proof / leaf-index / leaf-hash slice lengths %d/%d/%d disagree",
			len(inclusionProofs), len(expectedLeafIndices), len(eventLeafHashes))
	}
	for i, p := range inclusionProofs {
		if p.TreeSize != sth.Head.TreeSize {
			return fmt.Errorf("translog: inclusion proof[%d] tree_size=%d, want %d",
				i, p.TreeSize, sth.Head.TreeSize)
		}
		if p.LeafIndex != expectedLeafIndices[i] {
			return fmt.Errorf("translog: inclusion proof[%d] leaf_index=%d, want %d",
				i, p.LeafIndex, expectedLeafIndices[i])
		}
		if err := translog.VerifyInclusion(eventLeafHashes[i], p.LeafIndex, p.TreeSize, p.AuditPath, sth.Head.RootHash); err != nil {
			return fmt.Errorf("%w: leaf %d: %v", ErrInclusionMismatch, p.LeafIndex, err)
		}
	}
	if priorSTH != nil && priorSTH.Head.TreeSize > 0 {
		if consistency == nil {
			return fmt.Errorf("%w: server omitted consistency proof from %d to %d",
				ErrConsistencyMismatch, priorSTH.Head.TreeSize, sth.Head.TreeSize)
		}
		if consistency.FromSize != priorSTH.Head.TreeSize {
			return fmt.Errorf("%w: from_size=%d, want %d", ErrConsistencyMismatch,
				consistency.FromSize, priorSTH.Head.TreeSize)
		}
		if consistency.ToSize != sth.Head.TreeSize {
			return fmt.Errorf("%w: to_size=%d, want %d", ErrConsistencyMismatch,
				consistency.ToSize, sth.Head.TreeSize)
		}
		if err := translog.VerifyConsistency(consistency.FromSize, consistency.ToSize, consistency.Nodes, priorSTH.Head.RootHash, sth.Head.RootHash); err != nil {
			return fmt.Errorf("%w: %v", ErrConsistencyMismatch, err)
		}
	}
	return nil
}

// PinnedServerPub returns the previously-pinned pubkey for serverURL,
// or an error if no pin exists. Used by reconcile-side push helpers
// that operate after the outer RunSync has already done first-contact
// pinning — they should not redo the ceremony, only trust what's in
// the vault.
func (s *Session) PinnedServerPub(serverURL string) (ed25519.PublicKey, error) {
	canonical, err := NormalizeServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	if entry, ok := s.Body.PinnedServers[canonical]; ok {
		return ed25519.PublicKey(entry.ServerPub), nil
	}
	return nil, fmt.Errorf("translog: no pinned pubkey for %s — outer sync must run first-contact pinning", canonical)
}

// EncodeSTH marshals an STH for storage in the vault's LastSTH /
// LastSTHUser fields. Wrapper for symmetry with DecodeSTH.
func EncodeSTH(sth translog.STH) ([]byte, error) {
	return proto.Marshal(sth)
}

// DecodeSTH parses a CBOR-encoded STH from the vault. Returns nil on
// empty input (no anchor yet — fresh chain or legacy vault) so the
// caller can treat "no proof" and "missing field" identically.
func DecodeSTH(b []byte) (*translog.STH, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var sth translog.STH
	if err := proto.Unmarshal(b, &sth); err != nil {
		return nil, fmt.Errorf("decode LastSTH: %w", err)
	}
	return &sth, nil
}

// nowUnix is wrapped so tests can stub. v1 just calls time.Now().Unix().
var nowUnix = func() int64 { return time.Now().Unix() }
