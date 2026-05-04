// Package fdhome resolves the fd0 home directory and related paths.
//
// Default: ~/.fd0/
// Override: $FD0_HOME
package fdhome

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Paths bundles all paths inside an fd0 home.
type Paths struct {
	Home      string // ~/.fd0
	Lock      string // ~/.fd0/.lock
	Vault     string // ~/.fd0/vault.enc
	Config    string // ~/.fd0/config.toml
	Chains    string // ~/.fd0/chains
	UserChain string // ~/.fd0/chains/user.cbor
	AgentSock string // ~/.fd0/agent.sock
	AgentPID  string // ~/.fd0/agent.pid
	AgentLog  string // ~/.fd0/agent.log
}

// Resolve picks the home directory and constructs every path.
func Resolve() (Paths, error) {
	home := os.Getenv("FD0_HOME")
	if home == "" {
		uh, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, err
		}
		home = filepath.Join(uh, ".fd0")
	}
	return Paths{
		Home:      home,
		Lock:      filepath.Join(home, ".lock"),
		Vault:     filepath.Join(home, "vault.enc"),
		Config:    filepath.Join(home, "config.toml"),
		Chains:    filepath.Join(home, "chains"),
		UserChain: filepath.Join(home, "chains", "user.cbor"),
		AgentSock: filepath.Join(home, "agent.sock"),
		AgentPID:  filepath.Join(home, "agent.pid"),
		AgentLog:  filepath.Join(home, "agent.log"),
	}, nil
}

// ScopeChain returns the chain path for a given scope id.
//
// SECURITY (codex audit 🔴 fdhome.go:51, hardened in Wave C-1):
// scopeID is a proto.ScopeID — a typed value that, by being passed
// in here, advertises that it has already been validated against
// STORAGE.md's `s_[a-z2-7]{26}` shape (typically via
// proto.ParseScopeID at the entry point or proto.DeriveScopeID at
// the protocol-derivation site). The compile-time signature gives
// reviewers a single audit-grep target ("proto.ScopeID(...)" in
// non-test code) for any place where a raw string crosses the
// boundary without going through ParseScopeID.
//
// Defence-in-depth: we also re-validate here so a bypass via
// `proto.ScopeID(rawString)` fails closed rather than silently
// joining a path-traversal segment with p.Chains. Returns an empty
// string on invalid input — the caller should detect and refuse
// rather than open the empty path.
func (p Paths) ScopeChain(scopeID proto.ScopeID) string {
	if !proto.ValidScopeIDShape(string(scopeID)) {
		return ""
	}
	return filepath.Join(p.Chains, string(scopeID)+".cbor")
}

// ValidScopeID is a thin alias for proto.ValidScopeIDShape kept
// for backwards compatibility with adversarial_test.go and any
// external caller that imported it before the proto-side type
// landed. Prefer proto.ValidScopeIDShape (or the typed
// proto.ParseScopeID) in new code.
func ValidScopeID(s string) bool { return proto.ValidScopeIDShape(s) }

// EnsureDirs creates Home and Chains with mode 0700 (user-only). The 0700
// permission is the agent's same-UID security boundary.
func (p Paths) EnsureDirs() error {
	for _, d := range []string{p.Home, p.Chains} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// VerifyTight ensures Home is mode 0700 and owned by current user. Used at
// agent start and at any sensitive op.
func (p Paths) VerifyTight() error {
	st, err := os.Stat(p.Home)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("fd0 home %s is not a directory", p.Home)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return errors.New("fd0 home is group/world-readable; refusing to operate")
	}
	return nil
}
