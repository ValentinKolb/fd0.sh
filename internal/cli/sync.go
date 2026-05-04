package cli

// Sync orchestrator. The big workhorse is RunSync: one round-trip
// covers pull + push + discovery + per-scope translog verification,
// followed by best-effort compaction. Divergence handling, scope
// discovery, and shared helpers are split out:
//
//   - sync_internal.go   — buildSyncRequestBody, leafHashAtSeq,
//                          decryptSecretBody, upsertOEK, fileSize, …
//   - sync_discover.go   — first-time pull of newly admitted scopes
//   - sync_reconcile.go  — divergence recovery + rebuild loop
//
// signedPOST stays here because every file above eventually goes
// through this transport seam — keeping it next to RunSync makes
// the auth contract (server_pub binding for cross-server replay
// resistance) easy to find.

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
	// Codex audit fix (🔴 auth.go:87 + cli/sync.go:131): the server
	// requires user_super_pub be registered via POST /users before
	// honouring any authenticated request. Wire the registration
	// here so first-time users see no "unregistered_pk" rejection.
	// Idempotent on subsequent syncs (PinnedServer.Registered cache).
	if err := s.EnsureUserRegistered(ctx, server); err != nil {
		return fmt.Errorf("user registration: %w", err)
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
		evs, err := chain.ReadScopeEvents(s.Paths.ScopeChain(proto.ScopeID(sid)))
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
		//
		// SECURITY (codex audit 🔴 sync.go:266): vault state must
		// be re-sealed BEFORE removing the chain file. Doing it
		// after meant a ReSeal failure (later in the loop) left
		// the file deleted but the vault still referencing the
		// scope — next sync replayed a missing chain and silently
		// dropped the scope without notification. Order: update
		// vault map → ReSeal → remove file. If ReSeal fails the
		// chain file survives and the scope can be re-discovered.
		if ps.Denied {
			delete(s.Body.Scopes, sid)
			if err := s.ReSeal(); err != nil {
				return fmt.Errorf("scope %s denied: ReSeal failed (chain file kept for retry): %w", sid, err)
			}
			path := s.Paths.ScopeChain(proto.ScopeID(sid))
			_ = os.Remove(path)
			fmt.Fprintf(os.Stderr, "  ↳ removed from scope %s\n", shortScopeID(sid))
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

		path := s.Paths.ScopeChain(proto.ScopeID(sid))
		// Snapshot size so we can rollback on replay failure (a malicious
		// server could otherwise poison the local chain file with bytes
		// that don't replay).
		preSize, _ := fileSize(path)
		// SECURITY (subagent regression hunt 🔴): check every
		// event's signed_prefix.scope BEFORE persisting any of
		// them. The post-AppendRaw replay-then-check path leaves
		// a crash window: events fsync'd, server crashes, file
		// has wrong-scope events at restart. Pre-check is cheap
		// and closes the window.
		for i, ev := range ps.Events {
			sp := &ev.SignedPrefix
			// Genesis events legitimately have nil scope; any
			// other event MUST embed the scope we're pulling.
			if sp.Scope != nil && *sp.Scope != sid {
				return fmt.Errorf("scope %s: server returned event[%d] for scope %s (chain swap, pre-write)",
					sid, i, *sp.Scope)
			}
		}
		// SECURITY (codex audit 🔴 sync.go:319): if AppendRaw fails
		// mid-loop, we leave the file half-extended AND fsync'd
		// between events. Truncate back to preSize on any error so
		// the next sync starts from a consistent state.
		appendErr := func() error {
			for _, ev := range ps.Events {
				cb, err := proto.Marshal(&ev)
				if err != nil {
					return err
				}
				if err := chain.AppendRaw(path, cb); err != nil {
					return err
				}
			}
			return nil
		}()
		// rollbackTruncate is used at multiple failure points
		// below. Codex regression hunt (🟡 sync.go:355/366/382):
		// previously each site did `_ = os.Truncate(...)` —
		// silently dropping truncate errors meant a chain file
		// could be left half-extended on disk after a "rolled
		// back" return path. Surface the error explicitly so the
		// user sees a corrupt-chain warning rather than a silent
		// data-corruption setup.
		rollbackTruncate := func() error {
			if terr := os.Truncate(path, preSize); terr != nil {
				return fmt.Errorf("scope %s: rollback truncate to %d bytes failed (chain may be corrupt on disk): %w", sid, preSize, terr)
			}
			return nil
		}

		if appendErr != nil {
			if terr := rollbackTruncate(); terr != nil {
				return fmt.Errorf("%w (truncate rollback also failed: %v)", appendErr, terr)
			}
			return fmt.Errorf("scope %s: AppendRaw failed mid-batch (rolled back): %w", sid, appendErr)
		}
		st, err := replayScopeViaAgent(path, s.UserSuperPub, s.UserX25519Pub, s.Agent)
		if err != nil {
			// Roll back, then reconcile: the most common cause is a local
			// write that occurred while the server already advanced past
			// its previous tip (some other member or device pushed). The
			// reconcile path handles divergent local-only events by saving
			// them as pending sets, rewriting the chain to the server's
			// authoritative copy, and rebuilding pendings on top.
			if terr := rollbackTruncate(); terr != nil {
				return terr
			}
			if rerr := s.reconcileAndRepush(ctx, wcc, server, sid, 3); rerr != nil {
				return fmt.Errorf("sync: replay %s rejected; reconcile failed: %w", sid, rerr)
			}
			dirty = true
			continue
		}
		if st == nil {
			continue
		}
		// SECURITY (codex audit 🔴 sync.go:328): the replayed
		// state's ScopeID MUST match the chain we asked about.
		// Without this, a server returning a (signature-valid)
		// chain for a different scope would land under our
		// requested scope's vault entry.
		if string(st.ScopeID) != sid {
			if terr := rollbackTruncate(); terr != nil {
				return terr
			}
			return fmt.Errorf("scope %s: server returned chain for scope %s (chain swap)", sid, st.ScopeID)
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
		// SECURITY (subagent regression hunt 🔴 sync.go:394):
		// merge ALL OEK versions from the replayed state, not
		// just the current. Previously only `st.OEKs[CurrentOEKVer]`
		// was upserted, so historic versions in `st.OEKs` (still
		// needed to decrypt pre-rotation secrets in pending-event
		// reconcile) were never persisted to the vault. The next
		// `savePendingLocalEvents` would error with "missing OEK
		// v%d" — silently losing local-only secrets authored
		// under an older era.
		for v, k := range st.OEKs {
			sd.OEKs = upsertOEK(sd.OEKs, v, k)
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
	//
	// SECURITY (codex audit 🔴 sync.go:447): track the highest STH
	// tree_size we've persisted PER SCOPE in this round. Without
	// this, push results returned in non-monotone order could
	// overwrite the latest LastSTH with an older one (the verify
	// against PRE-SYNC priorSTH passes for both, but the persisted
	// anchor must always be the highest tree_size seen).
	pushed, dups, failed := 0, 0, 0
	floorDirty := false
	maxSizePersisted := map[string]uint64{} // scope_id → max sth.head.tree_size
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
		// SECURITY (codex audit 🔴 sync.go:430): the push verify
		// must prove the SUBMITTED event's leaf, not whatever
		// leaf the server claims at p.Seq. Compute the expected
		// leaf hash from the LOCAL chain entry that produced
		// this push — if the server proved a different leaf at
		// the same seq (e.g. a re-org we haven't replayed yet),
		// VerifyAndCrossCheck will reject. leafHashAtSeq reads
		// from the local chain file by seq.
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
		// Track per-scope max so post-loop persistence picks the
		// highest STH (codex audit 🔴 sync.go:447). Only update
		// when strictly greater.
		if p.STH.Head.TreeSize >= maxSizePersisted[p.ScopeID] {
			sd.LastSTH = encoded
			maxSizePersisted[p.ScopeID] = p.STH.Head.TreeSize
		}
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
		st, err := replayScopeViaAgent(s.Paths.ScopeChain(proto.ScopeID(sid)), s.UserSuperPub, s.UserX25519Pub, s.Agent)
		if err != nil || st == nil {
			continue
		}
		// chain.CompactScope derives the live event-id set from the
		// post-replay snapshot (st.SecretIndex). It refuses to compact
		// if the snapshot is stale relative to the chain file, so a
		// silent-drop bug here would surface as an error.
		changed, dropped, err := chain.CompactScope(s.Paths.ScopeChain(proto.ScopeID(sid)), st)
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
//
// SECURITY (signature subagent audit 🔴): the signed input includes
// the destination server's pinned pubkey, binding the signature to
// a specific server. Without this, a malicious server-A operator
// could replay the signed request to server-B (where the user is
// also registered) and have it accepted.
func (s *Session) signedPOST(ctx context.Context, endpoint string, body []byte) (*http.Response, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	// Look up the server's pinned pub from the canonical URL (not
	// `endpoint` which carries the path). PinnedServerPub returns
	// an error if the server isn't pinned yet, but EnsurePinnedServer
	// is always called before any signedPOST.
	canonical, err := NormalizeServerURL((&url.URL{Scheme: u.Scheme, Host: u.Host}).String())
	if err != nil {
		return nil, err
	}
	serverPub, err := s.PinnedServerPub(canonical)
	if err != nil {
		return nil, fmt.Errorf("signedPOST: %w", err)
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
	si, err := proto.HTTPSignedInput("POST", u.Path, qmap, ts, nonce, body, []byte(serverPub))
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

// _ silences unused-import lint when the only HTTP client use is Default.
var _ = agent.OpStatus
