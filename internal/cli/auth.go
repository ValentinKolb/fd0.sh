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
	newK := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
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
	ev, err := buildUserAuthSetAgent(s.Agent, s.UserSuperPub, uctx.TipSeq, uctx.TipHash, newActive)
	if err != nil {
		return err
	}
	if err := chain.AppendUser(s.Paths.UserChain, ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	h := proto.HashPrefix(prefix)
	s.Body.AuthTip = proto.ChainTip{Seq: ev.Seq, Hash: h[:]}

	// Vault: add wrap. The agent encrypts its cached payload_key under
	// newK and atomically rewrites the vault file.
	if err := s.Agent.AddWrap(s.Paths.Vault, newID, proto.AuthPassphrase, pp, newK); err != nil {
		return err
	}
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
func RunAuthRemove(ctx context.Context, methodID string) error {
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
	ev, err := buildUserAuthSetAgent(s.Agent, s.UserSuperPub, uctx.TipSeq, uctx.TipHash, newActive)
	if err != nil {
		return err
	}
	if err := chain.AppendUser(s.Paths.UserChain, ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	h := proto.HashPrefix(prefix)
	s.Body.AuthTip = proto.ChainTip{Seq: ev.Seq, Hash: h[:]}

	if err := s.Agent.RemoveWrap(s.Paths.Vault, methodID); err != nil {
		return err
	}
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ removed auth method %s\n", methodID)
	return nil
}
