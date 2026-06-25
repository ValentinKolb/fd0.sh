package cli

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// RunDoctor performs read-only health checks across the local fd0 home.
//
// Checks:
//  1. Vault is openable; agent is unlocked.
//  2. User chain replays cleanly; tip matches vault.AuthTip.
//  3. Each subscribed scope chain replays; tip matches vault.ChainTip;
//     current OEK is present in vault; member set contains us.
//  4. No orphaned chain files (file present but not in vault.Scopes).
//  5. _meta is present where labels exist (informational).
//  6. fd0's SSH-agent socket accepts Unix connections.
//
// Exits with status 1 if any HIGH-severity issue is found.
func RunDoctor(ctx context.Context) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	bad := 0
	warn := 0
	pr := func(level, msg string) {
		switch level {
		case "OK":
			fmt.Fprintf(os.Stderr, "  ✓ %s\n", msg)
		case "WARN":
			warn++
			fmt.Fprintf(os.Stderr, "  ! %s\n", msg)
		case "ERR":
			bad++
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", msg)
		}
	}

	fmt.Fprintln(os.Stderr, "agent")
	pr("OK", "running, unlocked")

	fmt.Fprintln(os.Stderr, "user chain")
	if s.UserState == nil {
		pr("ERR", "no events on user chain")
	} else {
		pr("OK", fmt.Sprintf("tip seq=%d", s.UserState.TipSeq))
		if mm := chain.CompareUserTip(s.Body.AuthTip, s.UserState); mm != nil {
			switch mm.Direction {
			case "ahead":
				pr("WARN", fmt.Sprintf("file ahead of vault (file=%d, vault=%d) — next ReSeal will catch up", mm.FileSeq, mm.VaultSeq))
			default:
				pr("ERR", "vault tip binding mismatch: "+mm.Error())
			}
		} else {
			pr("OK", "vault auth_tip matches")
		}
	}

	fmt.Fprintln(os.Stderr, "scopes")
	scopeIDs := make([]string, 0, len(s.Body.Scopes))
	for sid := range s.Body.Scopes {
		scopeIDs = append(scopeIDs, sid)
	}
	sort.Strings(scopeIDs)
	for _, sid := range scopeIDs {
		sd := s.Body.Scopes[sid]
		fmt.Fprintf(os.Stderr, "  %s\n", scopeName(s, sid))
		st, err := replayScopeViaAgent(s.Paths.ScopeChain(proto.MustParseScopeID(sid)), s.UserSuperPub, s.UserX25519Pub, s.Agent)
		if err != nil {
			pr("ERR", fmt.Sprintf("    replay failed: %v", err))
			continue
		}
		if st == nil {
			pr("ERR", "    empty chain")
			continue
		}
		if st.Left {
			pr("WARN", "    we left this scope (next sync will drop it)")
		}
		if mm := chain.CompareScopeTip(sid, sd.ChainTip, st); mm != nil {
			if mm.Direction == "ahead" {
				pr("WARN", fmt.Sprintf("    file ahead of vault (file=%d, vault=%d)", mm.FileSeq, mm.VaultSeq))
			} else {
				pr("ERR", "    "+mm.Error())
			}
		} else {
			pr("OK", fmt.Sprintf("    tip seq=%d hash matches", st.TipSeq))
		}
		if _, ok := st.OEKs[st.CurrentOEKVer]; !ok {
			pr("ERR", fmt.Sprintf("    current OEK v%d missing", st.CurrentOEKVer))
		} else {
			pr("OK", fmt.Sprintf("    current OEK v%d present", st.CurrentOEKVer))
		}
		isMember := false
		for _, m := range st.MemberSet {
			if bytesEq(m, s.UserSuperPub) {
				isMember = true
				break
			}
		}
		if !isMember && !st.Left {
			pr("ERR", "    we are not in member set")
		}
		visible := 0
		for id, cur := range st.SecretIndex {
			if cur.Record == nil || isMetaSecret(id, cur.Record.Name) {
				continue
			}
			visible++
		}
		pr("OK", fmt.Sprintf("    %d members, %d secrets", len(st.MemberSet), visible))
	}

	// Auth method consistency: every vault wrap must match an active
	// chain method, and every active chain method must have a vault
	// wrap. Mismatches arise from a crash mid-`auth add`/`auth rm`,
	// or a deliberately tampered vault. Both are HIGH-severity:
	//   - Orphan wrap (in vault, not in chain): the credential is
	//     functional even though the user removed it. Security
	//     regression.
	//   - Orphan chain method (in chain, not in vault): the user
	//     can't unlock with that credential; they think they have
	//     N methods but really have N-1.
	fmt.Fprintln(os.Stderr, "auth method consistency")
	if s.UserState != nil && s.UserState.LatestAuthSet != nil {
		v, verr := vault.Read(s.Paths.Vault)
		if verr != nil {
			pr("ERR", "  cannot read vault for cross-check: "+verr.Error())
		} else {
			activeIDs := map[string]string{} // method_id -> method_type
			for _, m := range s.UserState.LatestAuthSet.Payload.Active {
				activeIDs[m.MethodID] = m.MethodType
			}
			wrapIDs := map[string]string{}
			for _, w := range v.WrappedPayloadKeys {
				wrapIDs[w.MethodID] = w.MethodType
			}
			// Vault → chain.
			for mid, mt := range wrapIDs {
				if _, ok := activeIDs[mid]; !ok {
					pr("ERR", fmt.Sprintf("  orphan vault wrap: method_id=%s type=%s — recoverable: `fd0 auth rm %s`", mid, mt, mid))
				}
			}
			// Chain → vault.
			for mid, mt := range activeIDs {
				if _, ok := wrapIDs[mid]; !ok {
					pr("ERR", fmt.Sprintf("  orphan chain method: method_id=%s type=%s — credential listed but vault has no wrap", mid, mt))
				}
			}
			if len(wrapIDs) == len(activeIDs) {
				match := true
				for mid := range activeIDs {
					if _, ok := wrapIDs[mid]; !ok {
						match = false
						break
					}
				}
				if match {
					pr("OK", fmt.Sprintf("  %d method(s); chain ↔ vault wraps match", len(activeIDs)))
				}
			}

			// YubiKey-method content checks: each yubikey wrap MUST
			// carry a decodable YubikeyPublicParams with a 32-byte
			// X25519 pubkey AND a non-empty SealedKUnlock. A vault
			// that's been hand-edited or hit a corruption path
			// could keep the method_id list looking fine while the
			// embedded sealed-K_unlock is gone — that would surface
			// only at unlock time as a confusing AEAD error.
			//
			// Bound on what doctor can verify: it can read the
			// vault and check structure, but it CANNOT verify the
			// sealed_k_unlock decrypts correctly — that requires
			// the YubiKey itself + on-card ECDH. We're explicit
			// about that limit so a future caller doesn't read
			// "OK" as "this will unlock". A non-empty but corrupted
			// sealed_k_unlock passes our checks and only fails at
			// actual unlock — the right place is the unlock error
			// path, not the doctor.
			//
			// Sanity bound on SealedKUnlock length: libsodium
			// crypto_box_seal of a 32-byte K_unlock produces
			// exactly eph_pub(32) + Poly1305(16) + ct(32) = 80 B.
			// Our wrap layer always seals a 32-byte K_unlock, so
			// anything below 80 bytes is a corruption signal.
			const sealedKUnlockMinLen = 80
			for _, w := range v.WrappedPayloadKeys {
				if w.MethodType != proto.AuthYubikey {
					continue
				}
				var pp proto.YubikeyPublicParams
				if err := proto.Unmarshal(w.PublicParams, &pp); err != nil {
					pr("ERR", fmt.Sprintf("  yubikey wrap %s: public_params won't decode: %v", w.MethodID, err))
					continue
				}
				if len(pp.X25519Pub) != 32 {
					pr("ERR", fmt.Sprintf("  yubikey wrap %s: x25519_pub is %d bytes, want 32", w.MethodID, len(pp.X25519Pub)))
				}
				switch {
				case len(pp.SealedKUnlock) == 0:
					pr("ERR", fmt.Sprintf("  yubikey wrap %s: sealed_k_unlock is empty (unlock would fail)", w.MethodID))
				case len(pp.SealedKUnlock) < sealedKUnlockMinLen:
					pr("ERR", fmt.Sprintf("  yubikey wrap %s: sealed_k_unlock is %d bytes, < %d (truncated 32-B K_unlock seal; unlock would fail)", w.MethodID, len(pp.SealedKUnlock), sealedKUnlockMinLen))
				}
				if len(pp.X25519Pub) == 32 && len(pp.SealedKUnlock) >= sealedKUnlockMinLen {
					// Honest message: structural-only check, not a
					// guarantee the unlock will succeed.
					pr("OK", fmt.Sprintf("  yubikey wrap %s: structural check OK (sealed_k_unlock content verified only at unlock)", w.MethodID))
				}
			}
		}
	}

	// Orphan files: chain files present that aren't in vault.Scopes.
	fmt.Fprintln(os.Stderr, "files")
	entries, _ := os.ReadDir(s.Paths.Chains)
	for _, e := range entries {
		name := e.Name()
		if name == "user.cbor" {
			continue
		}
		if !hasSuffix(name, ".cbor") {
			continue
		}
		sid := name[:len(name)-len(".cbor")]
		if _, ok := s.Body.Scopes[sid]; !ok {
			pr("WARN", fmt.Sprintf("orphan chain file %s (no vault entry)", name))
		}
	}
	if bad+warn == 0 {
		pr("OK", "no orphans")
	}

	s.Close()

	fmt.Fprintln(os.Stderr, "ssh agent socket")
	sshSock := SSHSocketPathForRender()
	if err := checkSSHAgentSocket(sshSock); err != nil {
		pr("ERR", "  "+sshAgentSocketUnavailable(sshSock, err).Error())
	} else {
		pr("OK", fmt.Sprintf("  reachable at %s", sshSock))
	}

	fmt.Fprintln(os.Stderr)
	switch {
	case bad > 0:
		return fmt.Errorf("doctor: %d issue(s), %d warning(s)", bad, warn)
	case warn > 0:
		fmt.Fprintf(os.Stderr, "doctor: %d warning(s)\n", warn)
	default:
		fmt.Fprintln(os.Stderr, "doctor: all clear")
	}
	return nil
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}
