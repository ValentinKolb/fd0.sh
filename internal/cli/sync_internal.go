package cli

// Shared sync helpers extracted from sync.go (Wave B decomposition).
// No behaviour change. These helpers are called from RunSync,
// discoverScope, reconcileAndRepush, fullPullScope, and the
// rebuild* push paths — concentrating them here keeps the
// orchestration (sync.go) and the divergence-recovery flow
// (sync_reconcile.go) focused on their respective invariants.

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

var errScopePullDiverged = errors.New("scope pull diverged")

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
func buildSyncRequestBody(
	scopes map[string]pullCursor,
	push []any,
	discover bool,
	membershipAfter string,
	limit uint64,
) ([]byte, error) {
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
	pull := map[string]any{
		"scopes":               pulls,
		"limit_per_scope":      limit,
		"discover_memberships": discover,
	}
	if membershipAfter != "" {
		pull["membership_after"] = membershipAfter
	}
	if discover {
		pull["membership_limit"] = uint64(membershipPageSize)
	}
	return proto.Marshal(map[string]any{
		"pull": pull,
		"push": push,
	})
}

func buildMembershipDiscoveryRequest(after string) ([]byte, error) {
	return proto.Marshal(map[string]any{
		"pull": map[string]any{
			"scopes":               map[string]any{},
			"limit_per_scope":      uint64(0),
			"discover_memberships": true,
			"membership_after":     after,
			"membership_limit":     uint64(membershipPageSize),
		},
		"push": []any{},
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

// validateScopePullPage requires a server response to be the exact suffix
// requested by cursor. Local replay may legitimately contain compaction gaps,
// but newly received network history may not skip, duplicate, or swap events.
func validateScopePullPage(scopeID string, cursor pullCursor, tipSeq uint64, tipHash []byte, events []proto.ScopeEvent) error {
	expectedSeq := uint64(0)
	prevHash := cursor.Hash
	if cursor.Hash != nil {
		expectedSeq = cursor.Seq + 1
	}
	if len(events) == 0 {
		switch {
		case cursor.Hash == nil:
			return fmt.Errorf("%w: fresh pull omitted genesis", errScopePullDiverged)
		case tipSeq > cursor.Seq:
			return fmt.Errorf("%w: empty page before server tip %d", errScopePullDiverged, tipSeq)
		case tipSeq == cursor.Seq && !bytes.Equal(tipHash, cursor.Hash):
			return fmt.Errorf("%w: server tip hash differs at seq %d", errScopePullDiverged, tipSeq)
		default:
			// tipSeq < cursor.Seq is expected while this client has local
			// events queued for push in the same sync request.
			return nil
		}
	}
	for i := range events {
		ev := &events[i]
		sp := &ev.SignedPrefix
		if sp.Seq != expectedSeq {
			return fmt.Errorf("%w: server returned event seq %d, want %d",
				errScopePullDiverged, sp.Seq, expectedSeq)
		}
		if expectedSeq == 0 {
			if sp.Scope != nil || len(sp.PrevHash) != 0 {
				return fmt.Errorf("server returned invalid scope genesis")
			}
		} else {
			if sp.Scope == nil || *sp.Scope != scopeID {
				return fmt.Errorf("server returned event for a different scope")
			}
			if !bytes.Equal(sp.PrevHash, prevHash) {
				return fmt.Errorf("%w: server returned event seq %d with non-contiguous prev_hash",
					errScopePullDiverged, sp.Seq)
			}
		}
		prefix, err := ev.PrevHashInput()
		if err != nil {
			return fmt.Errorf("canonical event input: %w", err)
		}
		if expectedSeq == 0 {
			if got := proto.DeriveScopeID(proto.EventID(prefix)).String(); got != scopeID {
				return fmt.Errorf("server genesis derives scope %s, want %s", got, scopeID)
			}
		}
		hash := proto.HashPrefix(prefix)
		prevHash = hash[:]
		expectedSeq++
	}
	lastSeq := events[len(events)-1].SignedPrefix.Seq
	switch {
	case lastSeq > tipSeq:
		return fmt.Errorf("server returned event seq %d beyond tip %d", lastSeq, tipSeq)
	case lastSeq == tipSeq && !bytes.Equal(prevHash, tipHash):
		return fmt.Errorf("server tip hash does not match event seq %d", lastSeq)
	}
	return nil
}

// leafHashAtSeq reads the local scope chain file and returns the leaf
// hash for the event at `seq`. Used by the push-side translog verifier
// to confirm the server's inclusion proof matches our pushed event
// bytes. A mismatch means the server is claiming our slot for some
// other event — refuse to advance LastSTH.
//
// THREAT: T37 (server returns inclusion proof for the wrong leaf).
func (s *Session) leafHashAtSeq(scopeID string, seq uint64) ([]byte, error) {
	evs, err := chain.ReadScopeEvents(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)))
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
//
// Legacy single-server callers (e.g. doctor) use this signature.
// Multi-server callers should use scopeLastSTHSizeFor with the
// canonical server URL.
func scopeLastSTHSize(sd proto.ScopeVaultData) uint64 {
	sth, _ := DecodeSTH(sd.LastSTH)
	if sth == nil {
		return 0
	}
	return sth.Head.TreeSize
}

// scopeLastSTHSizeFor returns the persisted LastSTH tree_size for one
// (scope, server) pair. Per-server lookups (v0.0.5+) keep server A's
// STH from anchoring a consistency check against server B's tree.
func scopeLastSTHSizeFor(sd proto.ScopeVaultData, serverKey string) uint64 {
	sth, _ := DecodeSTH(sd.LastSTHFor(serverKey))
	if sth == nil {
		return 0
	}
	return sth.Head.TreeSize
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
//
// THREAT: T31 (OEK ring stale after failed local push).
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
