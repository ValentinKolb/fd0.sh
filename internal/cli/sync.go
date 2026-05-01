package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// RunSync pushes any local-only events to the configured fd0-server and pulls
// new events from there.
//
// v1 is intentionally minimal: push is a single best-effort attempt; pull
// covers every locally-known scope from cursor=local_tip.
func RunSync(ctx context.Context, server string) error {
	if server == "" {
		server = os.Getenv("FD0_SERVER")
	}
	if server == "" {
		paths, _ := fdhome.Resolve()
		cfg, _ := fdhome.LoadConfig(paths.Config)
		server = cfg.Sync.Server
	}
	if server == "" {
		return errors.New("no server configured (--server, FD0_SERVER, or [sync].server)")
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	// First round-trip: discovery + pull for known scopes + push.
	pullScopes := map[string]any{}
	for sid, sd := range s.Body.Scopes {
		pullScopes[sid] = map[string]any{
			"cursor": map[string]any{"seq": sd.ChainTip.Seq, "hash": sd.ChainTip.Hash},
		}
	}
	// Build push: only events whose seq is at or above the per-scope
	// PushFloor (= "lowest seq we still need to push"). Foreign events
	// (authored by another member, fetched via pull) are skipped because
	// they're already on the server and would yield `bad_author`.
	//
	// Bandwidth invariant: PushFloor only advances after the server has
	// accepted (or de-duped) the corresponding event AND the vault has
	// been re-sealed. Any failure between push and re-seal leaves the
	// floor untouched, so the next sync repushes the same suffix; the
	// server idempotent-dedups by event_id. Worst case is extra traffic;
	// data loss is impossible by construction.
	pushItems := []any{}
	for sid, sd := range s.Body.Scopes {
		evs, err := chain.ReadScopeEvents(s.Paths.ScopeChain(sid))
		if err != nil {
			return err
		}
		for _, ev := range evs {
			if !bytes.Equal(ev.SignedPrefix.Author, s.UserSuperPub) {
				continue
			}
			if ev.SignedPrefix.Seq < sd.PushFloor {
				continue
			}
			if ev.SignedPrefix.Seq == 0 {
				pushItems = append(pushItems, map[string]any{"scope": "", "event": ev})
				continue
			}
			pushItems = append(pushItems, map[string]any{"scope": sid, "event": ev})
		}
	}
	req := map[string]any{
		"pull": map[string]any{
			"scopes":               pullScopes,
			"limit_per_scope":      uint64(1000),
			"discover_memberships": true,
		},
		"push": pushItems,
	}
	body, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := s.signedPOST(ctx, server+"/sync", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sync: %s: %s", resp.Status, rb)
	}
	var sr struct {
		Pull map[string]struct {
			Tip struct {
				Seq  uint64 `cbor:"seq"`
				Hash []byte `cbor:"hash"`
			} `cbor:"tip"`
			OEKVersionMax uint64             `cbor:"oek_version_max"`
			Events        []proto.ScopeEvent `cbor:"events"`
			Denied        bool               `cbor:"denied,omitempty"`
		} `cbor:"pull"`
		Memberships []struct {
			ScopeID    string `cbor:"scope_id"`
			OEKVersion uint64 `cbor:"oek_version"`
		} `cbor:"memberships"`
		Push []struct {
			Accepted bool   `cbor:"accepted"`
			Reason   string `cbor:"reason,omitempty"`
			ScopeID  string `cbor:"scope_id,omitempty"`
			Seq      uint64 `cbor:"seq,omitempty"`
			EventID  string `cbor:"event_id,omitempty"`
		} `cbor:"push"`
	}
	if err := proto.Unmarshal(rb, &sr); err != nil {
		return fmt.Errorf("sync: decode resp: %w", err)
	}
	// Apply pulled events for each known scope.
	dirty := false
	for sid, ps := range sr.Pull {
		// Server says caller is no longer authorised → drop the scope
		// locally (STORAGE.md §5.3).
		if ps.Denied {
			path := s.Paths.ScopeChain(sid)
			_ = os.Remove(path)
			delete(s.Body.Scopes, sid)
			fmt.Fprintf(os.Stderr, "  ↳ removed from scope %s\n", shortScopeID(sid))
			dirty = true
			continue
		}
		sd, ok := s.Body.Scopes[sid]
		if !ok {
			continue
		}
		// Pending-leave: the user has already issued `scope leave` and
		// we have a local member.change op=remove event queued for push.
		// Skip the pull processing (which would otherwise replay the
		// chain, see the local leave, hit the st.Left branch, and drop
		// the scope before the leave event has reached the server —
		// triggering a futile re-discovery on the next round). The push
		// in this same sync round will land the leave; the *next* sync
		// will get a clean Denied from pull and drop normally.
		if sd.Leaving {
			continue
		}
		path := s.Paths.ScopeChain(sid)
		// Snapshot size so we can rollback on replay failure (a malicious
		// server could otherwise poison the local chain file with bytes
		// that don't replay).
		preSize, _ := fileSize(path)
		for _, ev := range ps.Events {
			cb, err := proto.Marshal(&ev)
			if err != nil {
				return err
			}
			if err := chain.AppendRaw(path, cb); err != nil {
				return err
			}
		}
		st, err := replayScopeViaAgent(path, s.UserSuperPub, s.Agent)
		if err != nil {
			// Roll back, then reconcile: the most common cause is a local
			// write that occurred while the server already advanced past
			// its previous tip (some other member or device pushed). The
			// reconcile path handles divergent local-only events by saving
			// them as pending sets, rewriting the chain to the server's
			// authoritative copy, and rebuilding pendings on top.
			_ = os.Truncate(path, preSize)
			if rerr := s.reconcileAndRepush(ctx, server, sid, 3); rerr != nil {
				return fmt.Errorf("sync: replay %s rejected; reconcile failed: %w", sid, rerr)
			}
			dirty = true
			continue
		}
		if st == nil {
			continue
		}
		// We were removed from this scope: drop locally (STORAGE.md §5.3).
		if st.Left {
			_ = os.Remove(path)
			delete(s.Body.Scopes, sid)
			fmt.Fprintf(os.Stderr, "  ↳ removed from scope %s\n", scopeName(s, sid))
			dirty = true
			continue
		}
		sd.ChainTip = proto.ChainTip{Seq: st.TipSeq, Hash: st.TipHash}
		if k, ok := st.OEKs[st.CurrentOEKVer]; ok {
			has := false
			for _, e := range sd.OEKs {
				if e.Version == st.CurrentOEKVer {
					has = true
					break
				}
			}
			if !has {
				sd.OEKs = append(sd.OEKs, proto.OEKEntry{Version: st.CurrentOEKVer, Key: append([]byte(nil), k...)})
			}
		}
		// Refresh shared label from _meta if present.
		if l := metaLabelFromIndex(st.SecretIndex); l != "" {
			sd.Label = l
		}
		s.Body.Scopes[sid] = sd
		dirty = true
	}
	if dirty {
		if err := s.ReSeal(); err != nil {
			return err
		}
	}
	// Auto-discover: server reported memberships in scopes we don't track
	// locally yet. For each unknown scope_id we issue a second pull from
	// cursor=0 and replay; replay extracts our OEK from the admit event's
	// key_delivery via agent.OpenSeal (PROTOCOL.md §4.5 / STORAGE.md §6.1).
	for _, m := range sr.Memberships {
		if _, known := s.Body.Scopes[m.ScopeID]; known {
			continue
		}
		if err := s.discoverScope(ctx, server, m.ScopeID); err != nil {
			fmt.Fprintf(os.Stderr, "  skip discover %s: %v\n", m.ScopeID, err)
			continue
		}
	}
	// Summarise push results, and advance per-scope PushFloor on
	// accepted-or-dup'd events.
	//
	// Why dup? Because dup means "server already has this event_id".
	// Mathematically the seq has been pushed (by us, in some earlier round
	// whose vault flush failed, or by another device). Either way, future
	// syncs needn't repush; advancing the floor is safe and saves traffic.
	//
	// Floor advances monotonically: we never roll backwards even if the
	// server returns a stale-looking seq from an old retry.
	pushed, dups, failed := 0, 0, 0
	floorDirty := false
	for _, p := range sr.Push {
		switch {
		case p.Accepted:
			pushed++
		case p.Reason == "dup":
			dups++
		default:
			failed++
			fmt.Fprintf(os.Stderr, "  push refused: %s\n", p.Reason)
			continue
		}
		if p.ScopeID == "" {
			continue
		}
		sd, ok := s.Body.Scopes[p.ScopeID]
		if !ok {
			continue
		}
		next := p.Seq + 1
		if next > sd.PushFloor {
			sd.PushFloor = next
			s.Body.Scopes[p.ScopeID] = sd
			floorDirty = true
		}
	}
	// Persist PushFloor advances NOW (before any reconcile-on-failure path
	// that may rewrite the chain and update its own ChainTip/PushFloor).
	// If ReSeal fails here, every floor change in this round is lost; the
	// next sync re-pushes the same suffix and the server idempotent-dedups.
	// That's the no-data-loss invariant: floor never advances on disk
	// without an authoritative server confirmation having already landed.
	if floorDirty {
		if err := s.ReSeal(); err != nil {
			return err
		}
	}
	// Auto-retry: collect scopes whose pushes hit divergence/stale_oek and
	// run a reconcile-and-replay loop. PROTOCOL.md §7.1: up to 3 retries.
	if failed > 0 {
		conflictScopes := map[string]struct{}{}
		for _, p := range sr.Push {
			if p.Accepted {
				continue
			}
			if p.Reason != "divergence" && p.Reason != "stale_oek_version" {
				continue
			}
			if p.ScopeID != "" {
				conflictScopes[p.ScopeID] = struct{}{}
			}
		}
		retried, retryFailed := 0, 0
		for sid := range conflictScopes {
			if err := s.reconcileAndRepush(ctx, server, sid, 3); err != nil {
				fmt.Fprintf(os.Stderr, "  reconcile %s: %v\n", shortScopeID(sid), err)
				retryFailed++
				continue
			}
			retried++
		}
		if retryFailed > 0 {
			return fmt.Errorf("sync: %d scope(s) failed reconcile after retry; %d push(es) initially refused", retryFailed, failed)
		}
		if retried > 0 {
			fmt.Fprintf(os.Stderr, "✓ sync ok (pushed=%d dup=%d reconciled=%d)\n", pushed, dups, retried)
			return nil
		}
		return fmt.Errorf("sync: %d push(es) refused (pushed=%d dup=%d)", failed, pushed, dups)
	}
	// Best-effort compaction. Bounded by 2× the live keep_set per
	// STORAGE.md §5; we only rewrite when it actually shrinks.
	s.compactAfterSync()
	fmt.Fprintf(os.Stderr, "✓ sync ok (pushed=%d dup=%d)\n", pushed, dups)
	return nil
}

// compactAfterSync runs CompactScope on every scope chain file.
//
// User-chain compaction is intentionally NOT triggered automatically: the
// user chain is small (one auth.set per credential rotation) and our current
// ReplayUser requires events[0].Seq == 0. A future revision can add
// compacted-mode user-chain replay; until then we keep history.
func (s *Session) compactAfterSync() {
	for sid := range s.Body.Scopes {
		// Build the live event-id set for this scope from the in-memory
		// secret_index. Any secret.set whose event_id is in this set is
		// kept; older secret.sets for the same id are dropped.
		st, err := replayScopeViaAgent(s.Paths.ScopeChain(sid), s.UserSuperPub, s.Agent)
		if err != nil || st == nil {
			continue
		}
		live := map[string]struct{}{}
		for _, cur := range st.SecretIndex {
			if cur.EventID != "" {
				live[cur.EventID] = struct{}{}
			}
		}
		if changed, err := chain.CompactScope(s.Paths.ScopeChain(sid), live); err == nil && changed {
			fmt.Fprintf(os.Stderr, "  ↳ compacted scope %s\n", shortScopeID(sid))
		}
	}
}

// signedPOST performs an authenticated POST against the fd0-server.
func (s *Session) signedPOST(ctx context.Context, endpoint string, body []byte) (*http.Response, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ts := uint64(time.Now().Unix())
	qmap := map[string]string{}
	for k, vs := range u.Query() {
		qmap[k] = vs[0]
	}
	si, err := proto.HTTPSignedInput("POST", u.Path, qmap, ts, nonce, body)
	if err != nil {
		return nil, err
	}
	sig, err := s.Agent.Sign(si)
	if err != nil {
		return nil, err
	}
	r, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/cbor")
	r.Header.Set("Authorization",
		"fd0-sig v1 pk="+base64.StdEncoding.EncodeToString(s.UserSuperPub)+
			", nonce="+base64.StdEncoding.EncodeToString(nonce)+
			", ts="+strconv.FormatUint(ts, 10)+
			", sig="+base64.StdEncoding.EncodeToString(sig))
	return http.DefaultClient.Do(r)
}

// discoverScope pulls a fresh scope from cursor=0, persists its events, and
// adds it to the vault with the OEK extracted by replay.
func (s *Session) discoverScope(ctx context.Context, server, scopeID string) error {
	pullReq := map[string]any{
		"pull": map[string]any{
			"scopes": map[string]any{
				scopeID: map[string]any{
					"cursor": map[string]any{"seq": uint64(0), "hash": []byte(nil)},
				},
			},
			"limit_per_scope":      uint64(1000),
			"discover_memberships": false,
		},
		"push": []any{},
	}
	body, err := proto.Marshal(pullReq)
	if err != nil {
		return err
	}
	resp, err := s.signedPOST(ctx, server+"/sync", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, err := readAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("pull %s: %s", scopeID, resp.Status)
	}
	var sr struct {
		Pull map[string]struct {
			Tip struct {
				Seq  uint64 `cbor:"seq"`
				Hash []byte `cbor:"hash"`
			} `cbor:"tip"`
			OEKVersionMax uint64             `cbor:"oek_version_max"`
			Events        []proto.ScopeEvent `cbor:"events"`
			Denied        bool               `cbor:"denied,omitempty"`
		} `cbor:"pull"`
	}
	if err := proto.Unmarshal(rb, &sr); err != nil {
		return err
	}
	ps, ok := sr.Pull[scopeID]
	if !ok || len(ps.Events) == 0 {
		return errors.New("server returned no events for scope")
	}
	path := s.Paths.ScopeChain(scopeID)
	for _, ev := range ps.Events {
		cb, err := proto.Marshal(&ev)
		if err != nil {
			return err
		}
		if err := chain.AppendRaw(path, cb); err != nil {
			return err
		}
	}
	st, err := replayScopeViaAgent(path, s.UserSuperPub, s.Agent)
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("replay rejected: %w", err)
	}
	if st == nil || st.Left {
		_ = os.Remove(path)
		return errors.New("replay produced empty/left state")
	}
	curOEK, ok := st.OEKs[st.CurrentOEKVer]
	if !ok {
		_ = os.Remove(path)
		return fmt.Errorf("no current OEK after replay")
	}
	s.Body.Scopes[scopeID] = proto.ScopeVaultData{
		Label:    metaLabelFromIndex(st.SecretIndex),
		OEKs:     []proto.OEKEntry{{Version: st.CurrentOEKVer, Key: append([]byte(nil), curOEK...)}},
		ChainTip: proto.ChainTip{Seq: st.TipSeq, Hash: st.TipHash},
		// We received the entire chain from the server; everything up to
		// st.TipSeq is "already pushed" from our perspective. Without
		// this, the next sync would walk the full chain trying to push
		// foreign events (filtered out anyway by author check, but the
		// I/O is wasted work).
		PushFloor: st.TipSeq + 1,
	}
	if err := s.ReSeal(); err != nil {
		return err
	}
	// _meta and tombstones don't count as user-visible secrets.
	visible := 0
	for id, cur := range st.SecretIndex {
		if cur.Record == nil {
			continue
		}
		if isMetaSecret(id, cur.Record.Name) {
			continue
		}
		visible++
	}
	name := s.Body.Scopes[scopeID].Label
	if name == "" {
		name = shortScopeID(scopeID)
	} else {
		name = fmt.Sprintf("'%s' (%s)", name, shortScopeID(scopeID))
	}
	fmt.Fprintf(os.Stderr, "  ↳ discovered scope %s (%d secrets)\n", name, visible)
	return nil
}

// readAll is a tiny shim around io.ReadAll to avoid extra imports here.
func readAll(r interface{ Read(p []byte) (int, error) }) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}

// reconcileAndRepush handles a divergence-on-push by:
//   1. Fetching the full server chain (cursor=0, inclusive) for scope.
//   2. Diffing against the local chain to find the divergence point.
//   3. Saving local-only `secret.set` events authored by us as pending sets.
//   4. Overwriting the local chain with the server's authoritative copy.
//   5. Rebuilding the pending sets on top of the new tip and pushing them.
//
// member.change conflicts are surfaced — they require user judgement.
//
// Retries the whole loop up to maxRetries before returning an error.
func (s *Session) reconcileAndRepush(ctx context.Context, server, scopeID string, maxRetries int) error {
	for attempt := 0; attempt < maxRetries; attempt++ {
		serverEvents, err := s.fullPullScope(ctx, server, scopeID)
		if err != nil {
			return err
		}
		// Save local-only pending sets BEFORE we rewrite the chain.
		pending, err := s.savePendingLocalSets(scopeID, serverEvents)
		if err != nil {
			return err
		}
		// Backup the existing chain so we can roll back if replay fails on
		// the rewritten file.
		path := s.Paths.ScopeChain(scopeID)
		backup, _ := os.ReadFile(path)
		if err := s.replaceLocalChain(scopeID, serverEvents); err != nil {
			return err
		}
		if err := s.applyReplayedScope(scopeID); err != nil {
			// Roll back chain file on replay failure.
			if backup != nil {
				_ = os.WriteFile(path, backup, 0o600)
			}
			return fmt.Errorf("reconcile replay failed: %w", err)
		}
		// If we were removed, pending sets are moot.
		if _, still := s.Body.Scopes[scopeID]; !still {
			return nil
		}
		// Rebuild pending sets on the new tip.
		failed := 0
		for _, p := range pending {
			ok, err := s.rebuildAndPushSet(ctx, server, scopeID, p)
			if err != nil {
				return err
			}
			if !ok {
				failed++
			}
		}
		if failed == 0 {
			return nil
		}
		// Some rebuilds hit divergence again — loop.
	}
	return fmt.Errorf("scope %s: still diverging after %d retries", shortScopeID(scopeID), maxRetries)
}

// fullPullScope pages through the entire scope chain from seq=0. The server
// caps each response at 1000 events (API.md §2.4), so we loop until the
// returned tip equals the last event's hash.
func (s *Session) fullPullScope(ctx context.Context, server, scopeID string) ([]proto.ScopeEvent, error) {
	const pageSize = 1000
	var all []proto.ScopeEvent
	cursorSeq := uint64(0)
	cursorHash := []byte(nil) // sentinel: include seq=0 (server fresh-discovery)
	for round := 0; round < 64; round++ {
		req := map[string]any{
			"pull": map[string]any{
				"scopes": map[string]any{
					scopeID: map[string]any{
						"cursor": map[string]any{"seq": cursorSeq, "hash": cursorHash},
					},
				},
				"limit_per_scope":      uint64(pageSize),
				"discover_memberships": false,
			},
			"push": []any{},
		}
		body, err := proto.Marshal(req)
		if err != nil {
			return nil, err
		}
		resp, err := s.signedPOST(ctx, server+"/sync", body)
		if err != nil {
			return nil, err
		}
		rb, err := readAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("full pull %s: %s", scopeID, resp.Status)
		}
		var sr struct {
			Pull map[string]struct {
				Tip struct {
					Seq  uint64 `cbor:"seq"`
					Hash []byte `cbor:"hash"`
				} `cbor:"tip"`
				Events []proto.ScopeEvent `cbor:"events"`
				Denied bool               `cbor:"denied,omitempty"`
			} `cbor:"pull"`
		}
		if err := proto.Unmarshal(rb, &sr); err != nil {
			return nil, err
		}
		ps, ok := sr.Pull[scopeID]
		if !ok {
			return nil, errors.New("server returned no pull entry for scope")
		}
		if ps.Denied {
			return nil, errors.New("denied: not a member")
		}
		all = append(all, ps.Events...)
		if len(ps.Events) == 0 || ps.Events[len(ps.Events)-1].SignedPrefix.Seq >= ps.Tip.Seq {
			// We've reached the server's reported tip; verify last event's
			// hash matches it before trusting the page.
			if len(all) > 0 {
				lastPrefix, _ := all[len(all)-1].PrevHashInput()
				lastHash := proto.HashPrefix(lastPrefix)
				if !bytes.Equal(lastHash[:], ps.Tip.Hash) {
					return nil, fmt.Errorf("server tip hash mismatch")
				}
			}
			return all, nil
		}
		// Advance cursor and loop.
		cursorSeq = ps.Events[len(ps.Events)-1].SignedPrefix.Seq
		lastPrefix, _ := ps.Events[len(ps.Events)-1].PrevHashInput()
		h := proto.HashPrefix(lastPrefix)
		cursorHash = h[:]
	}
	return nil, fmt.Errorf("full pull %s: page limit exceeded", scopeID)
}

// pendingSet is one secret.set we built locally but failed to push.
type pendingSet struct {
	body *proto.SecretBody
}

// savePendingLocalSets compares local and server events by content-addressed
// event_id (slice-index diffs are wrong when local is compacted vs. server
// is full). Returns decrypted bodies of every local-only secret.set we
// authored. A local-only member.change surfaces as a conflict.
func (s *Session) savePendingLocalSets(scopeID string, serverEvents []proto.ScopeEvent) ([]pendingSet, error) {
	path := s.Paths.ScopeChain(scopeID)
	localEvents, err := chain.ReadScopeEvents(path)
	if err != nil {
		return nil, err
	}
	serverIDs := make(map[string]struct{}, len(serverEvents))
	for _, ev := range serverEvents {
		prefix, _ := ev.PrevHashInput()
		serverIDs[proto.EventID(prefix)] = struct{}{}
	}
	sd := s.Body.Scopes[scopeID]
	var pending []pendingSet
	for _, ev := range localEvents {
		prefix, _ := ev.PrevHashInput()
		if _, onServer := serverIDs[proto.EventID(prefix)]; onServer {
			continue
		}
		if !bytes.Equal(ev.SignedPrefix.Author, s.UserSuperPub) {
			continue
		}
		if ev.SignedPrefix.Kind != proto.KindSecretSet {
			return nil, fmt.Errorf("member.change conflict on scope %s — manual reconcile required", shortScopeID(scopeID))
		}
		var oek []byte
		for _, e := range sd.OEKs {
			if e.Version == ev.SignedPrefix.OEKVersion {
				oek = e.Key
				break
			}
		}
		if oek == nil {
			return nil, fmt.Errorf("missing OEK v%d for divergent event", ev.SignedPrefix.OEKVersion)
		}
		body, err := decryptSecretBody(ev, oek)
		if err != nil {
			return nil, err
		}
		pending = append(pending, pendingSet{body: body})
	}
	return pending, nil
}

// replaceLocalChain rewrites the chain file with a fresh server-authoritative
// sequence. Atomic via chain.WriteAll's tmp+rename.
func (s *Session) replaceLocalChain(scopeID string, events []proto.ScopeEvent) error {
	path := s.Paths.ScopeChain(scopeID)
	bytesList := make([][]byte, 0, len(events))
	for _, ev := range events {
		b, err := proto.Marshal(&ev)
		if err != nil {
			return err
		}
		bytesList = append(bytesList, b)
	}
	return chain.WriteAll(path, bytesList)
}

// applyReplayedScope replays the (possibly rewritten) chain and updates vault
// (chain_tip, OEKs, label). Drops the scope on leave.
func (s *Session) applyReplayedScope(scopeID string) error {
	path := s.Paths.ScopeChain(scopeID)
	st, err := replayScopeViaAgent(path, s.UserSuperPub, s.Agent)
	if err != nil {
		return err
	}
	if st == nil {
		return errors.New("empty chain after reconcile")
	}
	if st.Left {
		_ = os.Remove(path)
		delete(s.Body.Scopes, scopeID)
		return s.ReSeal()
	}
	sd := s.Body.Scopes[scopeID]
	sd.ChainTip = proto.ChainTip{Seq: st.TipSeq, Hash: st.TipHash}
	if k, ok := st.OEKs[st.CurrentOEKVer]; ok {
		has := false
		for _, e := range sd.OEKs {
			if e.Version == st.CurrentOEKVer {
				has = true
				break
			}
		}
		if !has {
			sd.OEKs = append(sd.OEKs, proto.OEKEntry{Version: st.CurrentOEKVer, Key: append([]byte(nil), k...)})
		}
	}
	if l := metaLabelFromIndex(st.SecretIndex); l != "" {
		sd.Label = l
	}
	// After a reconcile, the local chain has been rewritten from the
	// server's authoritative copy. Every event up to and including st.TipSeq
	// is therefore guaranteed to already exist on the server; the next event
	// we'd push starts at st.TipSeq+1. Advance the floor so the immediately
	// following rebuilt secret.sets aren't accompanied by a costly replay
	// of the entire restored history on every subsequent sync.
	if next := st.TipSeq + 1; next > sd.PushFloor {
		sd.PushFloor = next
	}
	s.Body.Scopes[scopeID] = sd
	return s.ReSeal()
}

// rebuildAndPushSet appends a fresh secret.set built on the current tip and
// pushes it. Returns (false, nil) on a fresh divergence (caller retries).
func (s *Session) rebuildAndPushSet(ctx context.Context, server, scopeID string, p pendingSet) (bool, error) {
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return false, err
	}
	sd := s.Body.Scopes[scopeID]
	var curOEK proto.OEKEntry
	for _, e := range sd.OEKs {
		if e.Version == st.CurrentOEKVer {
			curOEK = e
			break
		}
	}
	if curOEK.Version == 0 {
		return false, fmt.Errorf("missing OEK v%d after reconcile", st.CurrentOEKVer)
	}
	// If the secret has a name and another member already wrote the same
	// name to a different id, prefer the existing id (last-writer-wins on
	// the same id). Otherwise keep the original id.
	if p.body.Record != nil {
		for id, cur := range st.SecretIndex {
			if cur.Record != nil && cur.Record.Name == p.body.Record.Name && id != p.body.ID {
				p.body.ID = id
				break
			}
		}
	}
	ev, err := buildSecretSetAgent(s.Agent, s.UserSuperPub, scopeID,
		st.TipSeq, st.TipHash, curOEK.Key, curOEK.Version, p.body)
	if err != nil {
		return false, err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(scopeID), ev); err != nil {
		return false, err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd.ChainTip = proto.ChainTip{Seq: st.TipSeq + 1, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	// Pre-push: do NOT advance PushFloor yet. The push below may still fail.
	// The append above is local-only; if the push fails the next sync will
	// retry it (PushFloor stays at <= sd.ChainTip.Seq+1, and the rebuilt
	// event's seq matches that, so it's still in scope).
	if err := s.ReSeal(); err != nil {
		return false, err
	}
	// Push the single event.
	push := []any{map[string]any{"scope": scopeID, "event": ev}}
	body, err := proto.Marshal(map[string]any{
		"pull": map[string]any{"scopes": map[string]any{}, "limit_per_scope": uint64(0)},
		"push": push,
	})
	if err != nil {
		return false, err
	}
	resp, err := s.signedPOST(ctx, server+"/sync", body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	rb, err := readAll(resp.Body)
	if err != nil {
		return false, err
	}
	var sr struct {
		Push []struct {
			Accepted bool   `cbor:"accepted"`
			Reason   string `cbor:"reason,omitempty"`
			Seq      uint64 `cbor:"seq,omitempty"`
		} `cbor:"push"`
	}
	if err := proto.Unmarshal(rb, &sr); err != nil {
		return false, err
	}
	if len(sr.Push) == 0 {
		return false, errors.New("server returned no push result")
	}
	r := sr.Push[0]
	if r.Accepted || r.Reason == "dup" {
		// Persist PushFloor advance: the event with seq=ChainTip.Seq is now
		// authoritatively on the server (or a retry observed it as already
		// there), so future syncs needn't push it again.
		sdNow := s.Body.Scopes[scopeID]
		if next := sdNow.ChainTip.Seq + 1; next > sdNow.PushFloor {
			sdNow.PushFloor = next
			s.Body.Scopes[scopeID] = sdNow
			if err := s.ReSeal(); err != nil {
				// ReSeal failure is non-fatal here: the push already
				// landed on the server; floor staleness only costs a
				// re-push on the next sync (server dedups). We surface
				// the error to the caller so it shows up in logs.
				return true, fmt.Errorf("re-seal after push-floor advance: %w", err)
			}
		}
		return true, nil
	}
	if r.Reason == "divergence" || r.Reason == "stale_oek_version" {
		return false, nil // caller retries
	}
	return false, fmt.Errorf("push refused: %s", r.Reason)
}

// decryptSecretBody returns the SecretBody plaintext from a secret.set event
// using oek (32 B). The AAD is the same one the writer used.
func decryptSecretBody(ev *proto.ScopeEvent, oek []byte) (*proto.SecretBody, error) {
	sp := &ev.SignedPrefix
	if len(sp.Payload.EncBody) < 12 {
		return nil, errors.New("bad enc_body")
	}
	aad, err := bodyAADAgent(ev)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.AEADOpen(oek, sp.Payload.EncBody[:12], sp.Payload.EncBody[12:], aad)
	if err != nil {
		return nil, err
	}
	var body proto.SecretBody
	if err := proto.Unmarshal(plain, &body); err != nil {
		return nil, err
	}
	return &body, nil
}

// fileSize returns the size of path or 0 if missing.
func fileSize(path string) (int64, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return st.Size(), nil
}

// _ silences unused-import lint when the only HTTP client use is Default.
var _ = agent.OpStatus
