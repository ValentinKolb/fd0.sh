package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// RunAuthList prints the active auth methods. Marks the currently-unlocked
// method with `*`.
func RunAuthList(ctx context.Context) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	uctx, err := chain.ReplayUser(s.Paths.UserChain)
	if err != nil {
		return err
	}
	if uctx == nil || uctx.LatestAuthSet == nil {
		return errors.New("no auth methods on user chain")
	}
	st, _ := s.Agent.Status()
	active := ""
	if st != nil {
		active = st.ActiveMethodID
	}
	methods := append([]proto.AuthMethod{}, uctx.LatestAuthSet.Payload.Active...)
	sort.Slice(methods, func(i, j int) bool { return methods[i].MethodID < methods[j].MethodID })
	for _, m := range methods {
		marker := "  "
		if m.MethodID == active {
			marker = "* "
		}
		fmt.Printf("%s%s  type=%s\n", marker, m.MethodID, m.MethodType)
	}
	return nil
}

// RunAuthAdd derives a new K_unlock from a fresh passphrase, encrypts
// super_priv under it (via the agent), appends a new auth.set with the
// extended active set, and adds a new wrap to the vault.
func RunAuthAdd(ctx context.Context) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	uctx, err := chain.ReplayUser(s.Paths.UserChain)
	if err != nil {
		return err
	}
	if uctx == nil || uctx.LatestAuthSet == nil {
		return errors.New("no auth methods on user chain")
	}
	pass, err := ReadPassphraseConfirm("New passphrase: ", "Confirm: ")
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)

	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	pp, err := vault.NewPassphraseParams(salt, crypto.DefaultArgon2)
	if err != nil {
		return err
	}
	newK, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		return fmt.Errorf("derive K_unlock: %w", err)
	}
	defer crypto.Wipe(newK)
	newID := "am_" + ulid.Make().String()

	// Agent encrypts super_priv under the new K_unlock for the new method.
	encSP, err := s.Agent.EncryptSuperPriv(newK, newID)
	if err != nil {
		return err
	}

	// Build new auth.set (appends new method to active set).
	newActive := append([]proto.AuthMethod{}, uctx.LatestAuthSet.Payload.Active...)
	newActive = append(newActive, proto.AuthMethod{
		MethodID:           newID,
		MethodType:         proto.AuthPassphrase,
		PublicParams:       pp,
		EncryptedSuperPriv: encSP,
	})
	ev, err := chain.BuildUserAuthSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub, uctx.TipSeq, uctx.TipHash, newActive)
	if err != nil {
		return err
	}
	// Atomicity ordering: vault wrap FIRST, then chain advertisement.
	//
	// Rationale (THREATS.md §2 trust boundary):
	//   - If AddWrap fails: the user-chain has not been mutated; the user
	//     can simply retry. No half-state.
	//   - If AddWrap succeeds and chain.AppendUser fails: the vault has an
	//     orphan wrap whose method_id isn't in the active set. `auth ls`
	//     won't show it (chain is the source of truth for "what exists"),
	//     and `fd0 doctor` flags the inconsistency.
	//   - If we instead did chain first and AddWrap failed, the chain
	//     would advertise a method with no wrap → unlock with that method
	//     fails confusingly; the user has no obvious way to recover
	//     without a doctor-driven cleanup.
	if err := s.Agent.AddWrap(s.Paths.Vault, newID, proto.AuthPassphrase, pp, newK); err != nil {
		return err
	}
	if err := chain.AppendUser(s.Paths.UserChain, ev); err != nil {
		// Best-effort rollback: drop the wrap we just added so the vault
		// returns to a consistent state. If this also fails, doctor will
		// surface the orphan and the user can run `fd0 auth add` again
		// (AddWrap is idempotent on duplicate method_id).
		_ = s.Agent.RemoveWrap(s.Paths.Vault, newID)
		return err
	}
	prefix, _ := ev.PrevHashInput()
	h := proto.HashPrefix(prefix)
	s.Body.AuthTip = proto.ChainTip{Seq: ev.Seq, Hash: h[:]}
	// Re-seal vault body to push the new auth_tip into the body.
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ added auth method %s\n", newID)
	return nil
}

// RunAuthRemove removes a method from the active set and drops its vault
// wrap. Refuses if the target is the currently-unlocked method or if it
// would leave zero active methods.
func RunAuthRemove(ctx context.Context, methodID string, yes bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	uctx, err := chain.ReplayUser(s.Paths.UserChain)
	if err != nil {
		return err
	}
	if uctx == nil || uctx.LatestAuthSet == nil {
		return errors.New("no auth methods on user chain")
	}
	st, _ := s.Agent.Status()
	if st != nil && methodID == st.ActiveMethodID {
		return errors.New("cannot remove the currently-unlocked method (lock first, unlock with another, then retry)")
	}
	// Build the new active set sans the target.
	newActive := make([]proto.AuthMethod, 0, len(uctx.LatestAuthSet.Payload.Active))
	found := false
	for _, m := range uctx.LatestAuthSet.Payload.Active {
		if m.MethodID == methodID {
			found = true
			continue
		}
		newActive = append(newActive, m)
	}
	if !found {
		return fmt.Errorf("auth method %q not found", methodID)
	}
	if len(newActive) == 0 {
		return errors.New("refuse to remove the last auth method (would lock you out forever)")
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove auth method %s?", methodID)); err != nil {
		return err
	}
	ev, err := chain.BuildUserAuthSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub, uctx.TipSeq, uctx.TipHash, newActive)
	if err != nil {
		return err
	}
	// Atomicity ordering: vault wrap deletion FIRST, then chain
	// advertisement. THIS IS A SECURITY-CRITICAL ORDERING.
	//
	// Rationale: vault.Open iterates wraps independently of the chain.
	// If we wrote the chain first (announcing the method gone) and then
	// RemoveWrap failed, an attacker holding the just-revoked credential
	// could STILL UNLOCK because the wrap remained in vault.enc. By
	// removing the wrap first we close the credential's effectiveness
	// before we declare it removed; if chain.AppendUser fails afterwards
	// the chain still lists the method (so `auth ls` is misleading) but
	// unlock with that credential will fail at the wrap-decrypt step
	// (the wrap is gone). The user can re-issue `auth rm` and
	// RemoveWrap is idempotent on "not found".
	if err := s.Agent.RemoveWrap(s.Paths.Vault, methodID); err != nil {
		return err
	}
	if err := chain.AppendUser(s.Paths.UserChain, ev); err != nil {
		// Don't roll back: the wrap removal stays — that was the
		// security-critical step. Doctor will surface the orphan
		// chain entry and the user can retry `auth rm` (which is
		// now idempotent and will just append the chain event).
		return err
	}
	prefix, _ := ev.PrevHashInput()
	h := proto.HashPrefix(prefix)
	s.Body.AuthTip = proto.ChainTip{Seq: ev.Seq, Hash: h[:]}
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ removed auth method %s\n", methodID)
	return nil
}
