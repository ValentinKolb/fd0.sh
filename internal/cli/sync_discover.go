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
	events, verifiedSTH, err := s.fullPullScope(ctx, wcc, server, scopeID)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return errors.New("server returned no events for scope")
	}
	if verifiedSTH == nil {
		return fmt.Errorf("discover %s: verifier returned nil STH for non-empty events", scopeID)
	}
	path := s.Paths.ScopeChain(pid)
	for _, ev := range events {
		cb, err := proto.Marshal(&ev)
		if err != nil {
			_ = os.Remove(path)
			return err
		}
		if err := chain.AppendRaw(path, cb); err != nil {
			_ = os.Remove(path)
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
	// Wave D: type-state — only the value returned by Verify can be
	// encoded here.
	encodedSTH, err := EncodeSTH(*verifiedSTH)
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("encode initial LastSTH: %w", err)
	}
	// v0.0.5: discovery sets PushFloor + LastSTH for the SPECIFIC
	// server we discovered from. Other configured servers may not have
	// this scope's data yet; their state stays at defaults so the next
	// sync to those servers re-pushes the events (which the source
	// server already has → no-op via id-based dedup; the target server
	// has none → ingests them).
	sd := proto.ScopeVaultData{
		Label:    metaLabelFromIndex(st.SecretIndex),
		OEKs:     []proto.OEKEntry{{Version: st.CurrentOEKVer, Key: append([]byte(nil), curOEK...)}},
		ChainTip: proto.ChainTip{Seq: st.TipSeq, Hash: st.TipHash},
	}
	sd.SetPushFloorFor(server.String(), st.TipSeq+1)
	sd.SetLastSTHFor(server.String(), encodedSTH)
	s.Body.Scopes[scopeID] = sd
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
		name = fmt.Sprintf("'%s' (%s)", terminalSafe(name), shortScopeID(scopeID))
	}
	fmt.Fprintf(os.Stderr, "  ↳ discovered scope %s (%d secrets)\n", name, visible)
	return nil
}
