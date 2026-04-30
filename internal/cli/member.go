package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// RunScopeAddMember adds the holder of memberCardOrLabel to scopeID. The
// argument is either a card URL (`fd0://card/...`) or a pinned-identity
// label (see `fd0 card import`). Rotates the OEK on accept.
func RunScopeAddMember(ctx context.Context, scopeID, memberCardOrLabel string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	memberPub, err := s.resolveMember(memberCardOrLabel)
	if err != nil {
		return err
	}
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	for _, m := range st.MemberSet {
		if bytes.Equal(m, memberPub) {
			return fmt.Errorf("already a member of %s", scopeName(s, scopeID))
		}
	}
	// Build current projection.
	proj := projectionFromIndex(st.SecretIndex)
	ev, newOEK, err := buildMemberChangeAgent(
		s.Agent, s.UserSuperPub,
		scopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
		proto.OpAdd, memberPub, st.MemberSet, proj,
	)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(scopeID), ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.OEKs = append(sd.OEKs, proto.OEKEntry{Version: ev.SignedPrefix.OEKVersion, Key: append([]byte(nil), newOEK...)})
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ added %s… to %s (oek=v%d)\n",
		base64.StdEncoding.EncodeToString(memberPub)[:12],
		scopeName(s, scopeID), ev.SignedPrefix.OEKVersion)
	return nil
}

// RunScopeRemoveMember removes the holder of memberCardOrLabel from scopeID.
// Rotates the OEK on accept.
func RunScopeRemoveMember(ctx context.Context, scopeID, memberCardOrLabel string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	memberPub, err := s.resolveMember(memberCardOrLabel)
	if err != nil {
		return err
	}
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	if bytes.Equal(memberPub, s.UserSuperPub) {
		return errors.New("use `fd0 scope leave` to remove yourself")
	}
	found := false
	for _, m := range st.MemberSet {
		if bytes.Equal(m, memberPub) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%s… is not a member of %s",
			base64.StdEncoding.EncodeToString(memberPub)[:12], scopeName(s, scopeID))
	}
	proj := projectionFromIndex(st.SecretIndex)
	ev, newOEK, err := buildMemberChangeAgent(
		s.Agent, s.UserSuperPub,
		scopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
		proto.OpRemove, memberPub, st.MemberSet, proj,
	)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(scopeID), ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd := s.Body.Scopes[scopeID]
	sd.OEKs = append(sd.OEKs, proto.OEKEntry{Version: ev.SignedPrefix.OEKVersion, Key: append([]byte(nil), newOEK...)})
	sd.ChainTip = proto.ChainTip{Seq: ev.SignedPrefix.Seq, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ removed %s… from %s (oek=v%d)\n",
		base64.StdEncoding.EncodeToString(memberPub)[:12],
		scopeName(s, scopeID), ev.SignedPrefix.OEKVersion)
	return nil
}

// RunScopeLeave removes the local user from scopeID and drops the scope
// locally (chain file unlink + vault prune).
func RunScopeLeave(ctx context.Context, scopeID string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	// Build the event with op=remove, member=self.
	proj := projectionFromIndex(st.SecretIndex)
	ev, _, err := buildMemberChangeAgent(
		s.Agent, s.UserSuperPub,
		scopeID, st.TipSeq, st.TipHash, st.CurrentOEKVer,
		proto.OpRemove, s.UserSuperPub, st.MemberSet, proj,
	)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(scopeID), ev); err != nil {
		return err
	}
	// Drop scope locally per STORAGE.md §5.3:
	// 1) unlink chain file 2) drop scope from vault 3) re-seal.
	if err := os.Remove(s.Paths.ScopeChain(scopeID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	delete(s.Body.Scopes, scopeID)
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ left %s\n", scopeName(nil, scopeID))
	return nil
}

// RunScopeMembers prints the member list of one scope.
func RunScopeMembers(ctx context.Context, scopeID string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	pubs := make([][]byte, len(st.MemberSet))
	copy(pubs, st.MemberSet)
	sort.Slice(pubs, func(i, j int) bool { return bytes.Compare(pubs[i], pubs[j]) < 0 })
	for _, p := range pubs {
		marker := "  "
		if bytes.Equal(p, s.UserSuperPub) {
			marker = "* "
		}
		fmt.Printf("%s%s\n", marker, base64.StdEncoding.EncodeToString(p))
	}
	return nil
}

// RunScopeRename updates a scope's shared label. The label rides on the
// reserved `_meta` secret (see internal/cli/meta.go) so all members see the
// new name after their next sync.
func RunScopeRename(ctx context.Context, scopeOrLabel, newLabel string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scopeID, err := s.resolveScopeID(scopeOrLabel)
	if err != nil {
		return err
	}
	old := s.Body.Scopes[scopeID].Label
	if err := s.writeScopeMeta(scopeID, map[string]string{MetaKeyLabel: newLabel}); err != nil {
		return err
	}
	if old == "" {
		fmt.Fprintf(os.Stderr, "✓ scope %s labeled '%s'\n", shortScopeID(scopeID), newLabel)
	} else {
		fmt.Fprintf(os.Stderr, "✓ scope renamed: '%s' → '%s' (%s)\n", old, newLabel, shortScopeID(scopeID))
	}
	return nil
}

// projectionFromIndex builds a MemberProjection from the in-memory secret
// index, omitting tombstones.
func projectionFromIndex(idx map[string]chain.ScopeSecret) *proto.MemberProjection {
	out := &proto.MemberProjection{Secrets: make([]proto.SecretInProjection, 0, len(idx))}
	for id, cur := range idx {
		if cur.Record == nil {
			continue
		}
		out.Secrets = append(out.Secrets, proto.SecretInProjection{ID: id, Record: cur.Record})
	}
	sort.Slice(out.Secrets, func(i, j int) bool { return out.Secrets[i].ID < out.Secrets[j].ID })
	return out
}
