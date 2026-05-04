package cli

// discoverScope: full first-time pull of a scope membership the server
// surfaced via /sync's discover_memberships scan. Extracted from
// sync.go in Wave B so the new-subscription path has a single home —
// translog verify before disk write, replay before vault commit, no
// half-state on any failure.

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// discoverScope pulls a fresh scope from cursor=0, persists its events, and
// adds it to the vault with the OEK extracted by replay. `wcc` is the
// witness cross-check client (nil = cross-check disabled).
//
// Codex C-1.1 review fix: scopeID is server-supplied (from a /sync
// memberships response) — validate at entry so a malformed value
// returns a controlled error rather than panicking via MustParseScopeID
// downstream. The validated proto.ScopeID is then carried through the
// rest of the function; .String() recovers the underlying form for
// helpers that still take a raw string.
func (s *Session) discoverScope(ctx context.Context, wcc *WitnessCheckClient, server canon.URL, scopeID string) error {
	pid, err := proto.ParseScopeID(scopeID)
	if err != nil {
		return fmt.Errorf("discover: invalid server-supplied scope_id: %w", err)
	}
	body, err := buildSyncRequestBody(
		map[string]pullCursor{scopeID: {Seq: 0, Hash: nil}},
		nil, false, 1000,
	)
	if err != nil {
		return err
	}
	resp, err := s.signedPOST(ctx, server.JoinPath("/sync"), body)
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
	path := s.Paths.ScopeChain(pid)
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
