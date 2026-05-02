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

// ScopeChain returns the chain path for a given scope_id.
//
// SECURITY (codex audit 🔴 fdhome.go:51): scopeID is validated
// against STORAGE.md's `s_[a-z2-7]{26}` pattern before being joined
// with the chain directory. Without this, a hostile peer (or a
// corrupted local index) could feed a path traversal segment like
// `../../etc/passwd` and ScopeChain would silently produce a path
// outside p.Chains. Returns an empty string on invalid input — the
// caller should detect and refuse rather than open the empty path.
func (p Paths) ScopeChain(scopeID string) string {
	if !ValidScopeID(scopeID) {
		return ""
	}
	return filepath.Join(p.Chains, scopeID+".cbor")
}

// ValidScopeID returns true iff s matches the spec's exact
// "scope id" shape: prefix `s_` then 26 chars from base32-Crockford
// (lower) without padding, no separators. Does NOT enforce a
// checksum — callers that need cryptographic identity bind via
// proto.ScopeID(genesis_event_id).
func ValidScopeID(s string) bool {
	if len(s) != 28 || s[0] != 's' || s[1] != '_' {
		return false
	}
	for i := 2; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '2' && c <= '7':
		default:
			return false
		}
	}
	return true
}

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
