// Peer resolver: fetches /v1/server-info from each FD0_PEERS entry,
// verifies the self-signature, and TOFU-pins the peer's pubkey + label
// in the local peers table. The result is what GET /v1/server-info
// re-publishes (signed) so clients see "this server vouches that the
// following replicas exist with these pubkeys."
//
// Trust model: the publishing server only republishes peers it has
// successfully verified once. The client treats the published list as a
// HINT — pinning a peer is a separate, explicit action. See
// docs/PROTOCOL.md §11 (Peer Hints).
package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/server/store"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// canonicalisePeers normalises every FD0_PEERS entry through
// canon.ParseURL so the resolver and the peers-table key both see the
// same byte-stable form. Empty entries (from a trailing comma) are
// dropped. Duplicate URLs after canonicalisation are de-duped silently
// — they would only have produced redundant resolver calls.
func canonicalisePeers(raw []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := []string{}
	for _, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		u, err := canon.ParseURL(p)
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", p, err)
		}
		s := u.String()
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out, nil
}

// runPeerResolver loops every PeerResolveInterval, fetching each peer's
// /v1/server-info and upserting the result. Errors are logged at info
// level and do not abort the loop — a transient peer outage must not
// trigger noisy alerts or drop the peer from /v1/server-info.
//
// The first round runs immediately on startup so the published peer
// list is populated within the first round-trip rather than after the
// initial interval has elapsed.
func (s *Server) runPeerResolver(ctx context.Context) {
	// Immediate first pass — peer-listing on /v1/server-info shouldn't
	// take a full interval to populate after boot.
	s.resolveAllPeers(ctx)
	t := time.NewTicker(s.cfg.PeerResolveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.resolveAllPeers(ctx)
		}
	}
}

func (s *Server) resolveAllPeers(ctx context.Context) {
	for _, url := range s.cfg.Peers {
		if err := s.resolveOnePeer(ctx, url); err != nil {
			s.log.Info("peer resolve failed (keeping last known)", "peer", url, "err", err)
		}
	}
}

// resolveOnePeer fetches the peer's /v1/server-info, verifies it, and
// upserts the (url, pub, label) row. The TOFU-pin in store.UpsertPeer
// rejects pubkey rotation — operators must wipe the row by hand to
// allow a new key, so transient impersonation can't silently overwrite
// the pinned identity.
func (s *Server) resolveOnePeer(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url+"/v1/server-info", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	var info translog.ServerInfo
	if err := proto.Unmarshal(body, &info); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if err := translog.VerifyServerInfo(info); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	// Peer's label is only republished if it survives the same
	// charset filter we apply to our own. A malicious peer that ships
	// a label with ANSI escapes or control chars is downgraded to
	// "no label" — the pubkey + URL still pin, the operator still
	// sees the peer in their CLI, but downstream UI never renders the
	// hostile string.
	label := info.Label
	if !store.ValidLabel(label) {
		s.log.Info("peer label invalid, storing without label", "peer", url, "label", label)
		label = ""
	}
	err = s.store.UpsertPeer(ctx, url, info.ServerPub, label)
	switch {
	case errors.Is(err, store.ErrPeerKeyMismatch):
		s.log.Warn("peer pubkey rotation refused — wipe the row to re-pin",
			"peer", url, "published_pub", hex.EncodeToString(info.ServerPub))
		return err
	case err != nil:
		return fmt.Errorf("upsert: %w", err)
	}
	s.log.Debug("peer resolved", "peer", url, "label", label)
	return nil
}
