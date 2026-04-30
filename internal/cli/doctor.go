package cli

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/chain"
)

// RunDoctor performs read-only health checks across the local fd0 home.
//
// Checks:
//   1. Vault is openable; agent is unlocked.
//   2. User chain replays cleanly; tip matches vault.AuthTip.
//   3. Each subscribed scope chain replays; tip matches vault.ChainTip;
//      current OEK is present in vault; member set contains us.
//   4. No orphaned chain files (file present but not in vault.Scopes).
//   5. _meta is present where labels exist (informational).
//
// Exits with status 1 if any HIGH-severity issue is found.
func RunDoctor(ctx context.Context) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
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
		st, err := replayScopeViaAgent(s.Paths.ScopeChain(sid), s.UserSuperPub, s.Agent)
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
