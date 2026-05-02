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
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// pullCursor is the per-scope position we want the server to send events
// from, in /sync requests. (seq=0, hash=nil) means "send from the
// genesis"; otherwise the server sends events with seq > Seq whose
// prev_hash chain-binds to Hash.
//
// LastSTHSize anchors the translog consistency check (TRANSLOG.md §5.4).
// Zero = no anchor yet (fresh subscription) → server omits the
// consistency proof. Non-zero = client demands a consistency proof
// from this size to the current STH; client will refuse to advance
// LastSTH if the proof doesn't verify.
type pullCursor struct {
	Seq         uint64
	Hash        []byte
	LastSTHSize uint64
}

// buildSyncRequestBody marshals the CBOR body for POST /sync. The schema
// (PROTOCOL.md §7) lives here once; four call sites used to inline it
// with map[string]any literals, which silently typo'd into server-side
// "missing field" errors.
//
// `scopes` maps scope_id → cursor (or empty for a push-only request).
// `push` is the list of events to push (nil normalised to []any{}).
// `discover` toggles the server's membership-discovery scan.
// `limit` is the per-scope event cap (0 = none requested).
//
// Each scope entry's LastSTHSize and each push item's LastSTHSize ride
// on the wire as `last_sth_size` (CBOR omitempty when 0). The server
// echoes consistency proofs only when these are > 0.
func buildSyncRequestBody(scopes map[string]pullCursor, push []any, discover bool, limit uint64) ([]byte, error) {
	pulls := make(map[string]any, len(scopes))
	for sid, c := range scopes {
		entry := map[string]any{
			"cursor": map[string]any{"seq": c.Seq, "hash": c.Hash},
		}
		if c.LastSTHSize > 0 {
			entry["last_sth_size"] = c.LastSTHSize
		}
		pulls[sid] = entry
	}
	if push == nil {
		push = []any{}
	}
	return proto.Marshal(map[string]any{
		"pull": map[string]any{
			"scopes":               pulls,
			"limit_per_scope":      limit,
			"discover_memberships": discover,
		},
		"push": push,
	})
}

// pushItemFor returns a map[string]any wire-form of a single push event
// with optional last_sth_size for synchronous consistency proof. Used
// by every push-side call site (RunSync, pushRebuiltEvent) so the
// last_sth_size omitempty rule is enforced in one place.
func pushItemFor(scope string, ev *proto.ScopeEvent, lastSTHSize uint64) map[string]any {
	out := map[string]any{"scope": scope, "event": ev}
	if lastSTHSize > 0 {
		out["last_sth_size"] = lastSTHSize
	}
	return out
}

// leafHashAtSeq reads the local scope chain file and returns the leaf
// hash for the event at `seq`. Used by the push-side translog verifier
// to confirm the server's inclusion proof matches our pushed event
// bytes. A mismatch means the server is claiming our slot for some
// other event — refuse to advance LastSTH.
func (s *Session) leafHashAtSeq(scopeID string, seq uint64) ([]byte, error) {
	evs, err := chain.ReadScopeEvents(s.Paths.ScopeChain(scopeID))
	if err != nil {
		return nil, err
	}
	for _, ev := range evs {
		if ev.SignedPrefix.Seq != seq {
			continue
		}
		prefix, err := ev.PrevHashInput()
		if err != nil {
			return nil, err
		}
		return translog.LeafHashOfPrevInput(prefix), nil
	}
	return nil, fmt.Errorf("scope %s: no local event at seq %d", scopeID, seq)
}

// scopeLastSTHSize returns the persisted LastSTH tree_size for a scope,
// or 0 if absent / undecodable. The CBOR-level errors are not surfaced
// here — a corrupt LastSTH downgrades to "no anchor" rather than
// failing the sync, since a verified next response will overwrite it
// anyway. doctor surfaces decode failures as warnings.
func scopeLastSTHSize(sd proto.ScopeVaultData) uint64 {
	sth, _ := DecodeSTH(sd.LastSTH)
	if sth == nil {
		return 0
	}
	return sth.Head.TreeSize
}

// RunSync pushes any local-only events to the configured fd0-server and pulls
// new events from there.
//
// v1 is intentionally minimal: push is a single best-effort attempt; pull
// covers every locally-known scope from cursor=local_tip.
func RunSync(ctx context.Context, server string) error {
	if server == "" {
		server = os.Getenv("FD0_SERVER")
	}
	paths, _ := fdhome.Resolve()
	cfg, _ := fdhome.LoadConfig(paths.Config)
	if server == "" {
		server = cfg.Sync.Server
	}
	if server == "" {
		return errors.New("no server configured (--server, FD0_SERVER, or [sync].server)")
	}
	// Build the witness cross-check client BEFORE opening the
	// session. A bad [[witness]] config should fail loudly, not get
	// hidden behind the unlock prompt.
	wcc, err := NewWitnessCheckClient(cfg)
	if err != nil {
		return fmt.Errorf("witness config: %w", err)
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	// First-contact pinning: ensure (server URL, server pubkey) is in
	// the vault before any STH from this server is trusted. Subsequent
	// rounds short-circuit (the pin is persistent across syncs).
	pinnedPub, err := s.EnsurePinnedServer(ctx, server)
	if err != nil {
		return err
	}

	// Snapshot pre-sync LastSTH per scope. Both pull AND push
	// consistency proofs in this round are relative to the request's
	// last_sth_size, which we computed from the pre-sync state. After
	// pull processing succeeds we update sd.LastSTH; without this
	// snapshot the push verify would compare the server's "from K"
	// proof against an "from N (post-pull)" anchor and falsely reject.
	preSyncLastSTH := map[string]*translog.STH{}
	for sid, sd := range s.Body.Scopes {
		preSyncLastSTH[sid], _ = DecodeSTH(sd.LastSTH)
	}

	// First round-trip: discovery + pull for known scopes + push.
	pullScopes := map[string]pullCursor{}
	for sid, sd := range s.Body.Scopes {
		pullScopes[sid] = pullCursor{
			Seq:         sd.ChainTip.Seq,
			Hash:        sd.ChainTip.Hash,
			LastSTHSize: scopeLastSTHSize(sd),
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
		lastSize := scopeLastSTHSize(sd)
		for _, ev := range evs {
			if !bytes.Equal(ev.SignedPrefix.Author, s.UserSuperPub) {
				continue
			}
			if ev.SignedPrefix.Seq < sd.PushFloor {
				continue
			}
			scopeRef := sid
			if ev.SignedPrefix.Seq == 0 {
				scopeRef = ""
			}
			pushItems = append(pushItems, pushItemFor(scopeRef, ev, lastSize))
		}
	}
	body, err := buildSyncRequestBody(pullScopes, pushItems, true, 1000)
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
			OEKVersionMax    uint64                     `cbor:"oek_version_max"`
			Events           []proto.ScopeEvent         `cbor:"events"`
			Denied           bool                       `cbor:"denied,omitempty"`
			STH              *translog.STH              `cbor:"sth,omitempty"`
			InclusionProofs  []translog.InclusionProof  `cbor:"inclusion_proofs,omitempty"`
			ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
		} `cbor:"pull"`
		Memberships []struct {
			ScopeID    string `cbor:"scope_id"`
			OEKVersion uint64 `cbor:"oek_version"`
		} `cbor:"memberships"`
		Push []struct {
			Accepted         bool                       `cbor:"accepted"`
			Reason           string                     `cbor:"reason,omitempty"`
			ScopeID          string                     `cbor:"scope_id,omitempty"`
			Seq              uint64                     `cbor:"seq,omitempty"`
			EventID          string                     `cbor:"event_id,omitempty"`
			STH              *translog.STH              `cbor:"sth,omitempty"`
			InclusionProof   *translog.InclusionProof   `cbor:"inclusion_proof,omitempty"`
			ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
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
		// Translog verification: hard-fail BEFORE any local state
		// mutation. Server invariant per TRANSLOG.md §5.4: STH is
		// mandatory whenever a non-denied response carries chain
		// data. Inclusion proofs cover ps.Events one-for-one,
		// leaf_index == event.Seq for each. Consistency proof covers
		// our PRE-SYNC LastSTH → server's current STH (not the
		// just-updated LastSTH — see snapshot rationale at top).
		priorSTH := preSyncLastSTH[sid]
		leafHashes := make([][]byte, 0, len(ps.Events))
		leafIndices := make([]uint64, 0, len(ps.Events))
		for i := range ps.Events {
			prefix, err := ps.Events[i].PrevHashInput()
			if err != nil {
				return fmt.Errorf("translog: leaf hash for scope %s: %w", sid, err)
			}
			leafHashes = append(leafHashes, translog.LeafHashOfPrevInput(prefix))
			leafIndices = append(leafIndices, ps.Events[i].SignedPrefix.Seq)
		}
		expectedChainID := "scope:" + sid
		if err := VerifyAndCrossCheck(ctx, wcc, server, pinnedPub, expectedChainID, ps.STH, priorSTH, ps.InclusionProofs, leafIndices, leafHashes, ps.ConsistencyProof); err != nil {
			return fmt.Errorf("scope %s: %w", sid, err)
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
		st, err := replayScopeViaAgent(path, s.UserSuperPub, s.UserX25519Pub, s.Agent)
		if err != nil {
			// Roll back, then reconcile: the most common cause is a local
			// write that occurred while the server already advanced past
			// its previous tip (some other member or device pushed). The
			// reconcile path handles divergent local-only events by saving
			// them as pending sets, rewriting the chain to the server's
			// authoritative copy, and rebuilding pendings on top.
			_ = os.Truncate(path, preSize)
			if rerr := s.reconcileAndRepush(ctx, wcc, server, sid, 3); rerr != nil {
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
			sd.OEKs = upsertOEK(sd.OEKs, st.CurrentOEKVer, k)
		}
		// Refresh shared label from _meta if present.
		if l := metaLabelFromIndex(st.SecretIndex); l != "" {
			sd.Label = l
		}
		// Persist the verified STH as the new anchor. Verification
		// already passed above; we couldn't reach this line otherwise.
		if ps.STH != nil {
			encoded, err := EncodeSTH(*ps.STH)
			if err != nil {
				return fmt.Errorf("encode LastSTH for scope %s: %w", sid, err)
			}
			sd.LastSTH = encoded
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
		if err := s.discoverScope(ctx, wcc, server, m.ScopeID); err != nil {
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
		// Translog verification per accepted/dup result. STH +
		// InclusionProof are MANDATORY on accepted/dup per
		// TRANSLOG.md §5.4 — missing them is a server protocol
		// violation; refuse to advance.
		if p.STH == nil || p.InclusionProof == nil {
			return fmt.Errorf("scope %s push: %w (server returned %s without STH/inclusion proof)",
				p.ScopeID, ErrSTHMissing, p.Reason)
		}
		leafHash, lerr := s.leafHashAtSeq(p.ScopeID, p.Seq)
		if lerr != nil {
			return fmt.Errorf("scope %s push verify: %w", p.ScopeID, lerr)
		}
		// Use the PRE-SYNC LastSTH for the consistency anchor — the
		// request's last_sth_size was based on the pre-sync state.
		// The pull-side update of sd.LastSTH happened in this same
		// round and is irrelevant to the push proof.
		priorSTH := preSyncLastSTH[p.ScopeID]
		expectedChainID := "scope:" + p.ScopeID
		if err := VerifyAndCrossCheck(ctx, wcc, server, pinnedPub, expectedChainID, p.STH, priorSTH, []translog.InclusionProof{*p.InclusionProof}, []uint64{p.Seq}, [][]byte{leafHash}, p.ConsistencyProof); err != nil {
			return fmt.Errorf("scope %s push verify: %w", p.ScopeID, err)
		}
		encoded, err := EncodeSTH(*p.STH)
		if err != nil {
			return fmt.Errorf("encode LastSTH: %w", err)
		}
		sd.LastSTH = encoded
		floorDirty = true
		next := p.Seq + 1
		if next > sd.PushFloor {
			sd.PushFloor = next
			floorDirty = true
		}
		s.Body.Scopes[p.ScopeID] = sd
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
			if err := s.reconcileAndRepush(ctx, wcc, server, sid, 3); err != nil {
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
		st, err := replayScopeViaAgent(s.Paths.ScopeChain(sid), s.UserSuperPub, s.UserX25519Pub, s.Agent)
		if err != nil || st == nil {
			continue
		}
		// chain.CompactScope derives the live event-id set from the
		// post-replay snapshot (st.SecretIndex). It refuses to compact
		// if the snapshot is stale relative to the chain file, so a
		// silent-drop bug here would surface as an error.
		changed, dropped, err := chain.CompactScope(s.Paths.ScopeChain(sid), st)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ↳ compact %s skipped: %v\n", shortScopeID(sid), err)
			continue
		}
		if changed {
			fmt.Fprintf(os.Stderr, "  ↳ compacted scope %s (dropped %d superseded set(s))\n",
				shortScopeID(sid), len(dropped))
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
// adds it to the vault with the OEK extracted by replay. `wcc` is the
// witness cross-check client (nil = cross-check disabled).
func (s *Session) discoverScope(ctx context.Context, wcc *WitnessCheckClient, server, scopeID string) error {
	body, err := buildSyncRequestBody(
		map[string]pullCursor{scopeID: {Seq: 0, Hash: nil}},
		nil, false, 1000,
	)
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
			OEKVersionMax    uint64                     `cbor:"oek_version_max"`
			Events           []proto.ScopeEvent         `cbor:"events"`
			Denied           bool                       `cbor:"denied,omitempty"`
			STH              *translog.STH              `cbor:"sth,omitempty"`
			InclusionProofs  []translog.InclusionProof  `cbor:"inclusion_proofs,omitempty"`
			ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
		} `cbor:"pull"`
	}
	if err := proto.Unmarshal(rb, &sr); err != nil {
		return err
	}
	ps, ok := sr.Pull[scopeID]
	if !ok || len(ps.Events) == 0 {
		return errors.New("server returned no events for scope")
	}
	// Translog verify the discovered chain BEFORE writing to disk.
	// priorSTH is nil — fresh subscription, no anchor. STH MUST be
	// present and inclusion proofs MUST cover every event.
	pinnedPub, err := s.PinnedServerPub(server)
	if err != nil {
		return err
	}
	leafHashes := make([][]byte, 0, len(ps.Events))
	leafIndices := make([]uint64, 0, len(ps.Events))
	for i := range ps.Events {
		prefix, perr := ps.Events[i].PrevHashInput()
		if perr != nil {
			return fmt.Errorf("translog: leaf hash for discovered scope %s: %w", scopeID, perr)
		}
		leafHashes = append(leafHashes, translog.LeafHashOfPrevInput(prefix))
		leafIndices = append(leafIndices, ps.Events[i].SignedPrefix.Seq)
	}
	expectedChainID := "scope:" + scopeID
	if err := VerifyAndCrossCheck(ctx, wcc, server, pinnedPub, expectedChainID, ps.STH, nil, ps.InclusionProofs, leafIndices, leafHashes, ps.ConsistencyProof); err != nil {
		return fmt.Errorf("discover %s: %w", scopeID, err)
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
	st, err := replayScopeViaAgent(path, s.UserSuperPub, s.UserX25519Pub, s.Agent)
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
	// Persist verified STH as the initial LastSTH for this scope.
	encodedSTH, err := EncodeSTH(*ps.STH)
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("encode initial LastSTH: %w", err)
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
		LastSTH:   encodedSTH,
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
//  1. Fetching the full server chain (cursor=0, inclusive) for scope.
//  2. Saving every local-only event authored by us as a pendingEvent —
//     either a secret.set (decrypted body cached) or a member.change
//     (op + target captured for three-way merge).
//  3. Overwriting the local chain with the server's authoritative copy.
//  4. Replaying to derive the post-merge running state (member set, OEK).
//  5. Rebuilding each pending event in original chain order on top of
//     the new tip:
//     - secret.set → re-encrypt under the post-replay OEK and push.
//     - member.change → semantic rebase via
//     chain.RebaseMemberChangeMeaningful; drop on no-op, otherwise
//     emit a fresh member.change (rotates OEK) and push.
//
// Retries the whole loop up to maxRetries before returning an error.
// Each retry restarts from a fresh server pull, so a rebuilt event that
// races a third party (yet another concurrent push) gets another
// chance.
func (s *Session) reconcileAndRepush(ctx context.Context, wcc *WitnessCheckClient, server, scopeID string, maxRetries int) error {
	for attempt := 0; attempt < maxRetries; attempt++ {
		serverEvents, finalSTH, err := s.fullPullScope(ctx, wcc, server, scopeID)
		if err != nil {
			return err
		}
		// Save local-only pending events BEFORE we rewrite the chain.
		pending, err := s.savePendingLocalEvents(scopeID, serverEvents)
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
		// Persist the verified-on-pull final STH as the new anchor.
		// fullPullScope already verified its signature + per-page
		// inclusion proofs; we just have to store it. Skip if the
		// scope was dropped (st.Left handled inside applyReplayedScope).
		if sd, still := s.Body.Scopes[scopeID]; still && finalSTH != nil {
			encoded, eerr := EncodeSTH(*finalSTH)
			if eerr != nil {
				return fmt.Errorf("encode reconcile LastSTH: %w", eerr)
			}
			sd.LastSTH = encoded
			s.Body.Scopes[scopeID] = sd
			if rerr := s.ReSeal(); rerr != nil {
				return fmt.Errorf("persist reconcile LastSTH: %w", rerr)
			}
		}
		// If we were removed, pending sets are moot.
		if _, still := s.Body.Scopes[scopeID]; !still {
			return nil
		}
		// Rebuild pending events on the new tip, in their original
		// chain order. member.changes rotate the OEK and feed the
		// running state for any subsequent secret.sets in the same
		// rebuild pass; rebuildAndPushSet picks up the new OEK via
		// replayAndCheckScope before encrypting.
		//
		// If any single rebuild hits a fresh divergence we BREAK
		// immediately and let the outer loop restart from
		// fullPullScope+replaceLocalChain. Continuing past a `!ok`
		// would build subsequent events on top of a locally-appended
		// but server-rejected predecessor, guaranteeing a cascade of
		// further divergences and inflating stale-OEK exposure.
		diverged := false
		for _, p := range pending {
			var (
				ok   bool
				rerr error
			)
			switch p.kind {
			case proto.KindSecretSet:
				ok, rerr = s.rebuildAndPushSet(ctx, wcc, server, scopeID, p)
			case proto.KindMemberChange:
				ok, rerr = s.rebuildAndPushMemberChange(ctx, wcc, server, scopeID, p)
			default:
				return fmt.Errorf("reconcile: unknown pending kind %q", p.kind)
			}
			if rerr != nil {
				return rerr
			}
			if !ok {
				diverged = true
				break
			}
		}
		if !diverged {
			return nil
		}
		// Diverged — outer loop will refresh server state and retry.
	}
	return fmt.Errorf("scope %s: still diverging after %d retries", shortScopeID(scopeID), maxRetries)
}

// fullPullScope pages through the entire scope chain from seq=0. The server
// caps each response at 1000 events (API.md §2.4), so we loop until the
// returned tip equals the last event's hash.
//
// Translog: each page's STH is verified against the pinned server pub
// + inclusion proofs against that page's events. The final STH (= the
// one covering all returned events) is returned to the caller for
// persistence as the new LastSTH after the reconcile commits.
func (s *Session) fullPullScope(ctx context.Context, wcc *WitnessCheckClient, server, scopeID string) ([]proto.ScopeEvent, *translog.STH, error) {
	pinnedPub, err := s.PinnedServerPub(server)
	if err != nil {
		return nil, nil, err
	}
	const pageSize = 1000
	var all []proto.ScopeEvent
	var finalSTH *translog.STH
	cursorSeq := uint64(0)
	cursorHash := []byte(nil) // sentinel: include seq=0 (server fresh-discovery)
	for round := 0; round < 64; round++ {
		body, err := buildSyncRequestBody(
			map[string]pullCursor{scopeID: {Seq: cursorSeq, Hash: cursorHash}},
			nil, false, pageSize,
		)
		if err != nil {
			return nil, nil, err
		}
		resp, err := s.signedPOST(ctx, server+"/sync", body)
		if err != nil {
			return nil, nil, err
		}
		rb, err := readAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if resp.StatusCode != 200 {
			return nil, nil, fmt.Errorf("full pull %s: %s", scopeID, resp.Status)
		}
		var sr struct {
			Pull map[string]struct {
				Tip struct {
					Seq  uint64 `cbor:"seq"`
					Hash []byte `cbor:"hash"`
				} `cbor:"tip"`
				Events           []proto.ScopeEvent         `cbor:"events"`
				Denied           bool                       `cbor:"denied,omitempty"`
				STH              *translog.STH              `cbor:"sth,omitempty"`
				InclusionProofs  []translog.InclusionProof  `cbor:"inclusion_proofs,omitempty"`
				ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
			} `cbor:"pull"`
		}
		if err := proto.Unmarshal(rb, &sr); err != nil {
			return nil, nil, err
		}
		ps, ok := sr.Pull[scopeID]
		if !ok {
			return nil, nil, errors.New("server returned no pull entry for scope")
		}
		if ps.Denied {
			return nil, nil, errors.New("denied: not a member")
		}
		// Per-page translog verify. priorSTH is nil because we
		// don't carry an anchor across pages — the STH must verify
		// independently per page (and the final page's STH is what
		// we persist).
		leafHashes := make([][]byte, 0, len(ps.Events))
		leafIndices := make([]uint64, 0, len(ps.Events))
		for i := range ps.Events {
			prefix, perr := ps.Events[i].PrevHashInput()
			if perr != nil {
				return nil, nil, fmt.Errorf("translog: leaf hash on full pull: %w", perr)
			}
			leafHashes = append(leafHashes, translog.LeafHashOfPrevInput(prefix))
			leafIndices = append(leafIndices, ps.Events[i].SignedPrefix.Seq)
		}
		expectedChainID := "scope:" + scopeID
		if err := VerifyAndCrossCheck(ctx, wcc, server, pinnedPub, expectedChainID, ps.STH, nil, ps.InclusionProofs, leafIndices, leafHashes, ps.ConsistencyProof); err != nil {
			return nil, nil, fmt.Errorf("full pull %s: %w", scopeID, err)
		}
		if ps.STH != nil {
			finalSTH = ps.STH
		}

		all = append(all, ps.Events...)
		if len(ps.Events) == 0 || ps.Events[len(ps.Events)-1].SignedPrefix.Seq >= ps.Tip.Seq {
			// We've reached the server's reported tip; verify last event's
			// hash matches it before trusting the page.
			if len(all) > 0 {
				lastPrefix, _ := all[len(all)-1].PrevHashInput()
				lastHash := proto.HashPrefix(lastPrefix)
				if !bytes.Equal(lastHash[:], ps.Tip.Hash) {
					return nil, nil, fmt.Errorf("server tip hash mismatch")
				}
			}
			return all, finalSTH, nil
		}
		// Advance cursor and loop.
		cursorSeq = ps.Events[len(ps.Events)-1].SignedPrefix.Seq
		lastPrefix, _ := ps.Events[len(ps.Events)-1].PrevHashInput()
		h := proto.HashPrefix(lastPrefix)
		cursorHash = h[:]
	}
	return nil, nil, fmt.Errorf("full pull %s: page limit exceeded", scopeID)
}

// pendingEvent is one local-only event we need to rebuild on the new server
// tip after a divergence. Discriminated by `kind`:
//
//   - kind == KindSecretSet : `body` carries the decrypted SecretBody so the
//     rebuild loop can re-encrypt under the post-reconcile OEK.
//   - kind == KindMemberChange : `op` (add|remove) and `target` carry the
//     intent so the rebuild loop can re-emit a fresh member.change against
//     the post-replay member set (three-way merge — STORAGE.md §5.3).
type pendingEvent struct {
	kind   string
	body   *proto.SecretBody // KindSecretSet
	op     string            // KindMemberChange
	target []byte            // KindMemberChange
}

// savePendingLocalEvents identifies events that exist in our local chain
// but not on the server (the events we authored after the divergence
// point) and packages them for the rebuild loop. Two recoverable kinds:
//
//   - secret.set: decrypt body under the OEK era it was sealed with so we
//     can re-encrypt against the post-reconcile OEK.
//   - member.change: capture op + target so we can re-emit a fresh
//     member.change against the post-replay running state (three-way
//     merge). chain.RebaseMemberChangeMeaningful decides at rebuild time
//     whether the rebased event is still meaningful.
//
// The set-diff itself is delegated to chain.LocalOnlyEvents (pure, unit
// tested in chain). Foreign events (authored by another member yet
// somehow local-only — should never happen in practice) are skipped.
func (s *Session) savePendingLocalEvents(scopeID string, serverEvents []proto.ScopeEvent) ([]pendingEvent, error) {
	localPtrs, err := chain.ReadScopeEvents(s.Paths.ScopeChain(scopeID))
	if err != nil {
		return nil, err
	}
	// chain.ReadScopeEvents returns pointers (decoder ergonomics); the
	// server-response side is values. Materialise both as values so the
	// pure helper has a uniform signature.
	localEvents := make([]proto.ScopeEvent, len(localPtrs))
	for i, p := range localPtrs {
		localEvents[i] = *p
	}
	sd := s.Body.Scopes[scopeID]
	var pending []pendingEvent
	for _, ev := range chain.LocalOnlyEvents(localEvents, serverEvents) {
		if !bytes.Equal(ev.SignedPrefix.Author, s.UserSuperPub) {
			continue
		}
		switch ev.SignedPrefix.Kind {
		case proto.KindSecretSet:
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
			body, err := decryptSecretBody(&ev, oek)
			if err != nil {
				return nil, err
			}
			pending = append(pending, pendingEvent{kind: proto.KindSecretSet, body: body})
		case proto.KindMemberChange:
			pending = append(pending, pendingEvent{
				kind:   proto.KindMemberChange,
				op:     ev.SignedPrefix.Payload.Op,
				target: append([]byte(nil), ev.SignedPrefix.Payload.Member...),
			})
		default:
			return nil, fmt.Errorf("unexpected local-only event kind %q on scope %s", ev.SignedPrefix.Kind, shortScopeID(scopeID))
		}
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
	st, err := replayScopeViaAgent(path, s.UserSuperPub, s.UserX25519Pub, s.Agent)
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
		sd.OEKs = upsertOEK(sd.OEKs, st.CurrentOEKVer, k)
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
func (s *Session) rebuildAndPushSet(ctx context.Context, wcc *WitnessCheckClient, server, scopeID string, p pendingEvent) (bool, error) {
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
	ev, err := chain.BuildSecretSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub, scopeID,
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
	return s.pushRebuiltEvent(ctx, wcc, server, scopeID, ev)
}

// rebuildAndPushMemberChange rebases a divergent local-only member.change
// onto the post-replay running member set (three-way merge), pushes it,
// and updates the local OEK ring. Symmetric to rebuildAndPushSet but
// rotates the OEK and persists a fresh OEKEntry — same as a normal
// `scope add-member` / `remove-member` would.
//
// Returns:
//   - (true, nil)  on accept/dup, or when the rebase is a semantic no-op
//     (drop without pushing — see chain.RebaseMemberChangeMeaningful).
//   - (false, nil) on fresh divergence/stale_oek_version (caller retries).
//   - (false, err) on terminal failure.
func (s *Session) rebuildAndPushMemberChange(ctx context.Context, wcc *WitnessCheckClient, server, scopeID string, p pendingEvent) (bool, error) {
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return false, err
	}
	// Semantic rebase: drop if the running state already matches our intent.
	if !chain.RebaseMemberChangeMeaningful(st.MemberSet, p.op, p.target) {
		shortPub := base64.StdEncoding.EncodeToString(p.target)
		if len(shortPub) > 12 {
			shortPub = shortPub[:12]
		}
		fmt.Fprintf(os.Stderr, "  ↳ rebase: %s op=%s target=%s… now a no-op, dropped\n",
			shortScopeID(scopeID), p.op, shortPub)
		return true, nil
	}
	// Re-emit against the post-replay tip + member set. New OEK is rotated
	// inside BuildMemberChange and must be installed in the vault BEFORE
	// the push (so a successful push doesn't strand secrets unable to
	// decrypt against the just-promoted era).
	proj := projectionFromIndex(st.SecretIndex)
	ev, newOEK, err := chain.BuildMemberChange(
		AgentSigner{Agent: s.Agent}, s.UserSuperPub,
		scopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
		p.op, p.target, st.MemberSet, proj,
	)
	if err != nil {
		return false, err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(scopeID), ev); err != nil {
		return false, err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.OEKs = upsertOEK(sd.OEKs, ev.SignedPrefix.OEKVersion, newOEK)
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return false, err
	}
	return s.pushRebuiltEvent(ctx, wcc, server, scopeID, ev)
}

// pushRebuiltEvent posts a single locally-appended event to the server
// and reconciles the response. Shared between rebuildAndPushSet and
// rebuildAndPushMemberChange — both want the same accept/dup/divergence
// disposition and the same PushFloor advance.
//
// Contract:
//   - (true, nil)  : accepted or de-duplicated; PushFloor advanced.
//   - (false, nil) : divergence / stale_oek_version → caller loops the
//     reconcile (server-tip moved again).
//   - (false, err) : transport error or terminal "refused" reason.
func (s *Session) pushRebuiltEvent(ctx context.Context, wcc *WitnessCheckClient, server, scopeID string, ev *proto.ScopeEvent) (bool, error) {
	// Snapshot pre-push LastSTH for the consistency anchor: the
	// request's last_sth_size is read here, server's consistency
	// proof is relative to it. Reading after a successful push would
	// see the just-updated LastSTH and verify wrong (same root cause
	// as the RunSync snapshot pattern).
	sdPre := s.Body.Scopes[scopeID]
	preSTH, _ := DecodeSTH(sdPre.LastSTH)
	preSize := uint64(0)
	if preSTH != nil {
		preSize = preSTH.Head.TreeSize
	}

	push := []any{pushItemFor(scopeID, ev, preSize)}
	body, err := buildSyncRequestBody(nil, push, false, 0)
	if err != nil {
		return false, err
	}
	// Server pin must already be installed in the vault by the
	// outer RunSync. Reconcile-on-conflict only runs after a
	// successful first round, so the pin lookup is a map read.
	pinnedPub, perr := s.PinnedServerPub(server)
	if perr != nil {
		return false, perr
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
			Accepted         bool                       `cbor:"accepted"`
			Reason           string                     `cbor:"reason,omitempty"`
			Seq              uint64                     `cbor:"seq,omitempty"`
			STH              *translog.STH              `cbor:"sth,omitempty"`
			InclusionProof   *translog.InclusionProof   `cbor:"inclusion_proof,omitempty"`
			ConsistencyProof *translog.ConsistencyProof `cbor:"consistency_proof,omitempty"`
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
		// Translog verify before persisting any state. STH +
		// InclusionProof are MANDATORY on accepted/dup per
		// TRANSLOG.md §5.4 — missing them is a server protocol
		// violation; refuse to advance.
		if r.STH == nil || r.InclusionProof == nil {
			return false, fmt.Errorf("scope %s rebuilt-push: %w (server returned %s without STH/inclusion proof)",
				scopeID, ErrSTHMissing, r.Reason)
		}
		leafHash, lerr := s.leafHashAtSeq(scopeID, r.Seq)
		if lerr != nil {
			return false, fmt.Errorf("scope %s rebuilt-push verify: %w", scopeID, lerr)
		}
		expectedChainID := "scope:" + scopeID
		if err := VerifyAndCrossCheck(ctx, wcc, server, pinnedPub, expectedChainID, r.STH, preSTH, []translog.InclusionProof{*r.InclusionProof}, []uint64{r.Seq}, [][]byte{leafHash}, r.ConsistencyProof); err != nil {
			return false, fmt.Errorf("scope %s rebuilt-push verify: %w", scopeID, err)
		}
		sdNow := s.Body.Scopes[scopeID]
		encoded, eerr := EncodeSTH(*r.STH)
		if eerr != nil {
			return false, fmt.Errorf("encode LastSTH: %w", eerr)
		}
		sdNow.LastSTH = encoded
		if next := sdNow.ChainTip.Seq + 1; next > sdNow.PushFloor {
			sdNow.PushFloor = next
		}
		s.Body.Scopes[scopeID] = sdNow
		if err := s.ReSeal(); err != nil {
			// ReSeal failure is non-fatal here: the push already
			// landed on the server; floor staleness only costs a
			// re-push on the next sync (server dedups). Surface so
			// it shows up in logs.
			return true, fmt.Errorf("re-seal after push-floor advance: %w", err)
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
	aad, err := chain.BodyAAD(ev)
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

// upsertOEK inserts (version, key) into ring or replaces the existing entry
// for that version. The "replace" branch matters: a failed local
// member.change push leaves a stale OEK at version v in the vault. When the
// authoritative server-chain replay later returns a different bytewise key
// at the same version, the stale entry MUST be overwritten — otherwise
// rebuildAndPushSet (which looks up the current OEK by version in the vault
// ring) would encrypt subsequent secret.sets under the stale key, and peers
// would silently fail to decrypt them. The defensive upsert matches the
// invariant "vault.OEKs is authoritative for the most recent replay".
func upsertOEK(ring []proto.OEKEntry, version uint64, key []byte) []proto.OEKEntry {
	for i, e := range ring {
		if e.Version == version {
			ring[i].Key = append([]byte(nil), key...)
			return ring
		}
	}
	return append(ring, proto.OEKEntry{Version: version, Key: append([]byte(nil), key...)})
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
