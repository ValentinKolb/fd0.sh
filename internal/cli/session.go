// Package cli implements the fd0 command-line client. It is purely UX:
// argument parsing, terminal I/O, agent IPC, server HTTP, vault/chain file
// management. All cryptographic operations route through the agent.
package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// vaultRead aliases vault.Read so the secret.go file can stay decoupled from
// the import.
func vaultRead(path string) (*proto.VaultFile, error) { return vault.Read(path) }

// Session is one CLI invocation's open state. Acquire via Open; release via
// Close. Open holds the ~/.fd0/.lock flock, talks to the agent for an unlock
// (the agent must already be running), and replays chains.
type Session struct {
	Paths         fdhome.Paths
	Lock          *flock.Flock
	Agent         *agent.Client
	UserSuperPub  []byte
	UserX25519Pub []byte // ed25519 → curve25519, derived once at Open
	Body          *proto.VaultBody // body.SuperPriv is zeroed (held in agent)
	UserState     *chain.UserState
	Scopes        map[string]*ScopeRuntime
}

// ScopeRuntime is the per-scope replayed state plus the OEK we use for writes.
type ScopeRuntime struct {
	State   *chain.ScopeState
	CurOEK  []byte // 32 B; held in CLI process memory for the duration of the session
}

// Open acquires the lock, connects to the agent, asks for the redacted body,
// and replays every chain file the vault knows about. On rollback (file
// behind vault) it returns chain.ErrRollback.
//
// The lock is taken with TryLock immediately. If FD0_LOCK_WAIT is set in the
// env, Open retries acquisition every 100ms for up to that duration before
// giving up. The agent-spawned auto-sync sets FD0_LOCK_WAIT=60s so it queues
// politely behind interactive CLI calls.
func Open(ctx context.Context) (*Session, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return nil, err
	}
	if err := paths.EnsureDirs(); err != nil {
		return nil, err
	}
	cfg, _ := fdhome.LoadConfig(paths.Config) // missing/bad config → defaults
	lk := flock.New(paths.Lock)
	if err := acquireLock(ctx, lk, cfg.Client.LockWait); err != nil {
		return nil, err
	}
	cli := agent.NewClient(paths.AgentSock)
	if !cli.IsRunning() {
		lk.Unlock()
		return nil, ErrAgentNotRunning
	}
	gb, err := cli.GetBody()
	if err != nil {
		lk.Unlock()
		if errors.Is(err, agentLockedErr{}) || errStr(err) == "agent: locked" {
			return nil, ErrAgentLocked
		}
		return nil, fmt.Errorf("agent: %w", err)
	}
	var body proto.VaultBody
	if err := proto.Unmarshal(gb.RedactedBody, &body); err != nil {
		lk.Unlock()
		return nil, fmt.Errorf("decode body: %w", err)
	}
	xPub, err := crypto.EdPubToX25519(gb.UserSuperPub)
	if err != nil {
		lk.Unlock()
		return nil, fmt.Errorf("derive x25519 pub: %w", err)
	}
	s := &Session{
		Paths:         paths,
		Lock:          lk,
		Agent:         cli,
		UserSuperPub:  gb.UserSuperPub,
		UserX25519Pub: xPub,
		Body:          &body,
		Scopes:        map[string]*ScopeRuntime{},
	}
	// Replay user chain and verify tip binding.
	uctx, err := chain.ReplayUser(paths.UserChain)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("replay user chain: %w", err)
	}
	s.UserState = uctx
	if mm := chain.CompareUserTip(body.AuthTip, uctx); mm != nil {
		if mm.Direction == "behind" || mm.Direction == "diverged" {
			s.Close()
			return nil, fmt.Errorf("%w: %s", chain.ErrRollback, mm)
		}
		// "ahead" → vault is stale; CLI re-seal will catch it up after work.
	}
	return s, nil
}

type agentLockedErr struct{}

func (agentLockedErr) Error() string { return "agent: locked" }

func errStr(e error) string { return e.Error() }

// Close releases the lock and zeroizes ephemeral state.
func (s *Session) Close() {
	for _, sr := range s.Scopes {
		if sr.CurOEK != nil {
			crypto.Wipe(sr.CurOEK)
		}
	}
	if s.Lock != nil {
		_ = s.Lock.Unlock()
	}
}

// LoadScope replays one scope chain via the agent. It opens our key_delivery
// (sealed-box) using agent.OpenSeal, derives OEKs, and builds secret_index.
//
// X25519 derivation requires super_priv; instead of asking the agent for the
// scalar (which would expose it), we ask the agent.OpenSeal for every
// KeyDelivery, which uses the agent's held x25519 priv internally.
func (s *Session) LoadScope(scopeID string) (*ScopeRuntime, error) {
	if sr, ok := s.Scopes[scopeID]; ok {
		return sr, nil
	}
	path := s.Paths.ScopeChain(scopeID)
	st, err := replayScopeViaAgent(path, s.UserSuperPub, s.UserX25519Pub, s.Agent)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("scope %s: empty chain", scopeName(s, scopeID))
	}
	if st.Left {
		return nil, fmt.Errorf("scope %s: left", scopeName(s, scopeID))
	}
	if st.ScopeID != scopeID {
		return nil, fmt.Errorf("scope %s: derived id mismatch (%s)", scopeName(s, scopeID), st.ScopeID)
	}
	cur, ok := st.OEKs[st.CurrentOEKVer]
	if !ok {
		return nil, fmt.Errorf("scope %s: missing current OEK v%d", scopeName(s, scopeID), st.CurrentOEKVer)
	}
	sr := &ScopeRuntime{State: st, CurOEK: append([]byte(nil), cur...)}
	s.Scopes[scopeID] = sr
	return sr, nil
}

// AppendScopeEvent persists ev to the scope chain file and (eventually) syncs
// it. The CLI is responsible for keeping local and server tips in sync via
// the sync command.
func (s *Session) AppendScopeEvent(scopeID string, ev *proto.ScopeEvent) error {
	return chain.AppendScope(s.Paths.ScopeChain(scopeID), ev)
}

// AppendUserEvent persists ev to the user chain file.
func (s *Session) AppendUserEvent(ev *proto.UserEvent) error {
	return chain.AppendUser(s.Paths.UserChain, ev)
}

// ErrAgentNotRunning is returned when the user must run `fd0 unlock` first.
var ErrAgentNotRunning = errors.New("fd0 agent is not running — run `fd0 unlock` to start it")

// ErrAgentLocked is returned when the agent is up but no credential has been
// provided since the last lock.
var ErrAgentLocked = errors.New("fd0 agent is locked — run `fd0 unlock` to unlock the vault")

// AgentOpener is the production chain.Opener: it forwards Open over the
// agent's IPC, so super_priv (and the X25519 scalar derived from it)
// stays mlocked inside fd0-agent and never crosses the fd0 process.
//
// Pairs with chain.LocalOpener (in-process, raw priv) used by tests.
type AgentOpener struct{ Agent *agent.Client }

// Open implements chain.Opener.
func (o AgentOpener) Open(sealed []byte) ([]byte, error) {
	return o.Agent.OpenSeal(sealed)
}

// AgentSigner is the production chain.Signer: it forwards Sign over the
// agent's IPC, so super_priv stays mlocked inside fd0-agent.
//
// Pairs with chain.LocalSigner (in-process, raw Ed25519 priv) used by
// tests and by the brief init / recovery windows where super_priv is
// in-process before the agent has it.
type AgentSigner struct{ Agent *agent.Client }

// Sign implements chain.Signer.
func (s AgentSigner) Sign(payload []byte) ([]byte, error) {
	return s.Agent.Sign(payload)
}

// replayScopeViaAgent is the agent-routed entry into chain.ReplayScope.
// Kept as a thin wrapper at the cli layer so the four call sites
// (LoadScope, sync, doctor, replayAndCheckScope) stay short.
func replayScopeViaAgent(path string, ownSuperPub, ownX25519Pub []byte, ag *agent.Client) (*chain.ScopeState, error) {
	return chain.ReplayScope(path, ownSuperPub, ownX25519Pub, AgentOpener{Agent: ag})
}

// acquireLock takes the flock with optional retry. The retry budget is taken
// from FD0_LOCK_WAIT env (highest priority) or [client].lock_wait in config
// (fallback). Both are Go duration strings ("10s", "1m"); empty / zero means
// fail-fast on contention.
func acquireLock(ctx context.Context, lk *flock.Flock, configWait string) error {
	wait := os.Getenv("FD0_LOCK_WAIT")
	if wait == "" {
		wait = configWait
	}
	if wait == "" {
		ok, err := lk.TryLock()
		if err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		if !ok {
			return fmt.Errorf("another fd0 instance holds the lock at %s", lk.Path())
		}
		return nil
	}
	d, err := time.ParseDuration(wait)
	if err != nil {
		return fmt.Errorf("lock_wait %q: %w", wait, err)
	}
	deadline := time.Now().Add(d)
	for {
		ok, err := lk.TryLock()
		if err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("lock: timed out after %s", d)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// VaultExists returns true if ~/.fd0/vault.enc is present.
func VaultExists(p fdhome.Paths) bool {
	_, err := os.Stat(p.Vault)
	return err == nil
}

// readVaultHeader is a tiny shim around vault.Read used by activeWraps.
func readVaultHeader(path string) (*proto.VaultFile, error) {
	return vaultRead(path)
}

// ed25519PrivateKeySize is exported for tests/callers without importing the stdlib path.
const ed25519PrivateKeySize = ed25519.PrivateKeySize

// joinPath is a tiny convenience for path concat.
func joinPath(a, b string) string { return filepath.Join(a, b) }
