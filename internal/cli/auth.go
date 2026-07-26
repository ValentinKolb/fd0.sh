package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
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
	defaultMethodID := ""
	if cfg, err := fdhome.LoadConfig(s.Paths.Config); err == nil && strings.TrimSpace(cfg.Auth.DefaultMethod) != "" {
		if m, err := pickUnlockMethod(uctx.LatestAuthSet.Payload.Active, cfg.Auth.DefaultMethod); err == nil {
			defaultMethodID = m.MethodID
		}
	}
	methods := append([]proto.AuthMethod{}, uctx.LatestAuthSet.Payload.Active...)
	sort.Slice(methods, func(i, j int) bool { return methods[i].MethodID < methods[j].MethodID })
	for _, m := range methods {
		marker := "  "
		if m.MethodID == active {
			marker = "* "
		}
		suffix := ""
		if m.MethodID == defaultMethodID {
			suffix = " default"
		}
		fmt.Printf("%s%s  type=%s%s\n", marker, m.MethodID, m.MethodType, suffix)
	}
	return nil
}

// RunAuthDefault shows, sets, or clears the device-local default unlock
// method. The setting lives in ~/.fd0/config.toml and is never synced.
func RunAuthDefault(ctx context.Context, method string, clear bool) error {
	_ = ctx
	method = strings.TrimSpace(method)
	if clear && method != "" {
		return errors.New("pass either a method or --clear, not both")
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	uctx, err := chain.ReplayUser(paths.UserChain)
	if err != nil {
		return fmt.Errorf("replay user chain: %w", err)
	}
	if uctx == nil || uctx.LatestAuthSet == nil {
		return errors.New("no auth methods on user chain — run `fd0 init` first")
	}
	active := uctx.LatestAuthSet.Payload.Active
	if clear {
		if err := fdhome.SetAuthDefaultMethod(paths.Config, ""); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "✓ cleared default auth method")
		return nil
	}
	if method == "" {
		cfg, err := fdhome.LoadConfig(paths.Config)
		if err != nil {
			return err
		}
		current := strings.TrimSpace(cfg.Auth.DefaultMethod)
		if current == "" {
			fmt.Println("auth default: none")
			return nil
		}
		if m, err := pickUnlockMethod(active, current); err == nil {
			fmt.Printf("auth default: %s (type=%s, method_id=%s)\n", current, m.MethodType, m.MethodID)
		} else {
			fmt.Printf("auth default: %s (not enrolled)\n", current)
		}
		return nil
	}
	m, err := pickUnlockMethod(active, method)
	if err != nil {
		return fmt.Errorf("auth default %q: no enrolled method matches; use a type or method_id from `fd0 auth ls` (have %s)", method, summariseMethodSelectors(active))
	}
	if err := fdhome.SetAuthDefaultMethod(paths.Config, method); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ default auth method set to %s (type=%s, method_id=%s)\n", method, m.MethodType, m.MethodID)
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
	// The signed chain authorizes a wrap before the agent persists it. This
	// ordering cannot create a hidden credential: handleAddWrap rejects any
	// method that is absent from the canonical current auth.set.
	if err := chain.AppendUser(s.Paths.UserChain, ev); err != nil {
		return err
	}
	if err := s.Agent.AddWrap(s.Paths.Vault, newID, proto.AuthPassphrase, pp, newK); err != nil {
		if rollbackErr := rollbackAuthSet(s, ev, uctx.LatestAuthSet.Payload.Active); rollbackErr != nil {
			return fmt.Errorf("add auth wrap: %w; restore auth chain: %v", err, rollbackErr)
		}
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
	// Remove the physical wrap before publishing the reduced active set. If
	// the chain append fails, the chain may temporarily list an unusable
	// method, but the revoked credential cannot open the vault. Unlock also
	// checks the canonical current auth.set, so a retained stale wrap would
	// not remain authoritative after a successful chain append.
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

func rollbackAuthSet(s *Session, committed *proto.UserEvent, active []proto.AuthMethod) error {
	prefix, err := committed.PrevHashInput()
	if err != nil {
		return err
	}
	h := proto.HashPrefix(prefix)
	ev, err := chain.BuildUserAuthSet(
		AgentSigner{Agent: s.Agent},
		s.UserSuperPub,
		committed.Seq,
		h[:],
		append([]proto.AuthMethod(nil), active...),
	)
	if err != nil {
		return err
	}
	if err := chain.AppendUser(s.Paths.UserChain, ev); err != nil {
		return err
	}
	rollbackPrefix, err := ev.PrevHashInput()
	if err != nil {
		return err
	}
	rollbackHash := proto.HashPrefix(rollbackPrefix)
	s.Body.AuthTip = proto.ChainTip{Seq: ev.Seq, Hash: rollbackHash[:]}
	return s.ReSeal()
}
