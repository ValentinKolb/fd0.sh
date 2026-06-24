package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/canon"
)

// Primary-per-scope routing (REPLICATION.md, [sync].mode = "primary").
//
// In multi-push mode the client pushes every scope to every server, which
// can leave replicas with divergent lineages that the reconcile path then
// safely refuses to converge (the simtest convergence gap on seed 42).
// Primary mode eliminates the divergence at the source: each scope is
// written / pulled / reconciled against exactly ONE primary server, so
// all members of a scope use the same ordering authority and never
// diverge.
//
// AGREEMENT (review RED #1): the primary MUST be the same for every
// member, even if members configure different local [sync].servers sets.
// A purely local computation (sorted pinned pubs indexed by H(scope_id))
// would let members with different sets pick different primaries and
// diverge. So the anchor is COMMITTED to the scope's shared _meta secret
// by the creator (writeScopeMeta with MetaKeyAnchor) and every member
// READS that committed value — it is member-agnostic. A member whose
// configured set does not contain the committed anchor fails loudly
// (review RED #2) rather than silently skipping the scope.
//
// Scopes created before primary mode have no committed anchor; they fall
// back to multi-push (safe, the unchanged default) until an anchor is
// committed.

// anchorIndex maps a scope id to a server index in [0, n) deterministically.
func anchorIndex(scopeID string, n int) int {
	h := sha256.Sum256([]byte(scopeID))
	return int(binary.BigEndian.Uint64(h[:8]) % uint64(n))
}

// computeScopeAnchor picks this scope's primary pubkey from the SORTED
// pinned pubkeys of the configured servers. Sorting makes the choice
// independent of config order. Requires every server to be pinnable so
// the candidate set is well-defined; used only by the creator to commit
// the anchor.
func (s *Session) computeScopeAnchor(ctx context.Context, scopeID string, servers []string) ([]byte, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers configured for anchor selection")
	}
	pubs := make([][]byte, 0, len(servers))
	for _, srv := range servers {
		u, err := canon.ParseURL(srv)
		if err != nil {
			return nil, fmt.Errorf("anchor: server URL %q: %w", srv, err)
		}
		pub, err := s.EnsurePinnedServer(ctx, u)
		if err != nil {
			return nil, fmt.Errorf("anchor: pin %s: %w", srv, err)
		}
		pubs = append(pubs, append([]byte(nil), pub...))
	}
	sort.Slice(pubs, func(i, j int) bool { return bytes.Compare(pubs[i], pubs[j]) < 0 })
	return pubs[anchorIndex(scopeID, len(pubs))], nil
}

// commitScopeAnchor computes and commits the scope's primary to _meta so
// all members read the same value. Called by the creator (RunScopeCreate)
// in primary mode. Best-effort: if servers aren't reachable to pin, the
// scope stays uncommitted (multi-push) until a later commit.
func (s *Session) commitScopeAnchor(ctx context.Context, scopeID string, servers []string) error {
	anchor, err := s.computeScopeAnchor(ctx, scopeID, servers)
	if err != nil {
		return err
	}
	return s.writeScopeMeta(scopeID, map[string]string{
		MetaKeyAnchor: base64.StdEncoding.EncodeToString(anchor),
	})
}

// routeDecision is how RunSync should treat a scope on the current server.
type routeDecision int

const (
	routeHere     routeDecision = iota // this server is the scope's primary → sync it
	routeElse                          // another server is the primary → skip here
	routeMultiAll                      // no committed anchor yet → multi-push fallback
	routeDeferred                      // can't decide yet (fleet not fully reachable) → skip, no error
)

// scopeRoute decides how to handle scopeID on the server identified by
// thisServerPub, in primary mode. The committed _meta anchor is
// authoritative; a committed anchor that is NOT in the configured/pinnable
// set is a hard error (caller surfaces it loudly).
func (s *Session) scopeRoute(ctx context.Context, scopeID string, servers []string, thisServerPub []byte) (routeDecision, error) {
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return routeDeferred, nil // can't read meta this round; don't guess
	}
	anchor := metaAnchorFromIndex(st.SecretIndex)
	if len(anchor) != 32 {
		return routeMultiAll, nil // not assigned yet → safe multi-push
	}
	if bytes.Equal(anchor, thisServerPub) {
		return routeHere, nil
	}
	// Committed elsewhere. Confirm the anchor is reachable in our config
	// before deciding it's "not us" vs "misconfigured". Use cached pins.
	matched, allPinned := s.anchorAmongConfigured(servers, anchor)
	if matched {
		return routeElse, nil
	}
	if allPinned {
		// Every configured server is pinned and none is the anchor — the
		// scope's primary is genuinely not in this client's config.
		return routeDeferred, fmt.Errorf(
			"scope %s is anchored at a server not in your [sync].servers — add that server (primary mode requires all members to share the scope's primary)",
			shortScopeID(scopeID))
	}
	// Some server is unreachable/unpinned; the anchor might be it. Defer
	// rather than risk a false misconfig error.
	return routeDeferred, nil
}

// anchorAmongConfigured reports whether `anchor` matches a configured
// server's pinned pub (matched), and whether ALL configured servers are
// currently pinned (allPinned). Cached lookups only — no network.
func (s *Session) anchorAmongConfigured(servers []string, anchor []byte) (matched, allPinned bool) {
	allPinned = true
	for _, srv := range servers {
		u, err := canon.ParseURL(srv)
		if err != nil {
			allPinned = false
			continue
		}
		pub, err := s.PinnedServerPub(u)
		if err != nil {
			allPinned = false
			continue
		}
		if bytes.Equal(pub, anchor) {
			matched = true
		}
	}
	return matched, allPinned
}
