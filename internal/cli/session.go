// Package cli implements the fd0 command-line client. It is purely UX:
// argument parsing, terminal I/O, agent IPC, server HTTP, vault/chain file
// management. All cryptographic operations route through the agent.
package cli

import (
	"bytes"
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
	Paths        fdhome.Paths
	Lock         *flock.Flock
	Agent        *agent.Client
	UserSuperPub []byte
	Body         *proto.VaultBody // body.SuperPriv is zeroed (held in agent)
	UserState    *chain.UserState
	Scopes       map[string]*ScopeRuntime
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
	s := &Session{
		Paths:        paths,
		Lock:         lk,
		Agent:        cli,
		UserSuperPub: gb.UserSuperPub,
		Body:         &body,
		Scopes:       map[string]*ScopeRuntime{},
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
	st, err := replayScopeViaAgent(path, s.UserSuperPub, s.Agent)
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

// replayScopeViaAgent is a copy of chain.ReplayScope's per-event verification
// loop except sealed-box opens go through the agent (which holds x25519_priv).
//
// We can't reuse chain.ReplayScope directly because that signature wants raw
// X25519 keys. The agent variant routes OpenAnonymous calls over IPC.
func replayScopeViaAgent(path string, ownSuperPub []byte, ag *agent.Client) (*chain.ScopeState, error) {
	events, err := chain.ReadScopeEvents(path)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	st := &chain.ScopeState{
		OEKs:        make(map[uint64][]byte),
		SecretIndex: make(map[string]chain.ScopeSecret),
	}
	// STORAGE.md §5.4: compacted chains are non-contiguous in seq/prev_hash.
	// We compute `gap` per-event (not sticky), so contiguous events past a
	// historical gap still get the prev_hash check. We track `incomplete`
	// for the projection-poisoning skip: it is set on a gap and CLEARED
	// after a member.change that populates secret_index from its projection,
	// so later member.changes regain full integrity checking.
	var prevHash []byte
	incomplete := false
	for i, ev := range events {
		sp := &ev.SignedPrefix
		gap := false
		if i == 0 {
			if err := verifyScopeGenesis(ev, st); err != nil {
				return nil, fmt.Errorf("scope[0]: %w", err)
			}
		} else {
			if sp.Scope == nil || *sp.Scope != st.ScopeID {
				return nil, fmt.Errorf("scope[%d]: scope mismatch", i)
			}
			if sp.Seq != st.TipSeq+1 {
				gap = true
				incomplete = true
			}
			if !gap && !bytes.Equal(sp.PrevHash, prevHash) {
				return nil, fmt.Errorf("scope[%d]: prev_hash mismatch", i)
			}
			if !memberContains(st.MemberSet, sp.Author) {
				return nil, fmt.Errorf("scope[%d]: author not in member set", i)
			}
		}
		if !bytes.Equal(sp.Author, ev.Signature.SignerPubkey) {
			return nil, fmt.Errorf("scope[%d]: signer != author", i)
		}
		si, err := ev.SignedInput()
		if err != nil {
			return nil, err
		}
		if !crypto.Verify(sp.Author, si, ev.Signature.Signature) {
			return nil, fmt.Errorf("scope[%d]: bad signature", i)
		}
		switch sp.Kind {
		case proto.KindMemberChange:
			leave, err := applyMemberChangeAgent(st, ev, ownSuperPub, ag, incomplete)
			if err != nil {
				return nil, fmt.Errorf("scope[%d]: %w", i, err)
			}
			if leave {
				st.Left = true
			}
			// After a successful projection-populating apply, secret_index
			// is again the authoritative snapshot for the current OEK era.
			// Clear incomplete so subsequent member.changes get full checks.
			if !leave {
				incomplete = false
			}
		case proto.KindSecretSet:
			if err := applySecretSet(st, ev); err != nil {
				return nil, fmt.Errorf("scope[%d]: %w", i, err)
			}
		default:
			return nil, fmt.Errorf("scope[%d]: bad kind %q", i, sp.Kind)
		}
		hashIn, err := ev.PrevHashInput()
		if err != nil {
			return nil, err
		}
		h := proto.HashPrefix(hashIn)
		prevHash = h[:]
		st.TipSeq = sp.Seq
		st.TipHash = prevHash
		if st.Left {
			break
		}
	}
	return st, nil
}

// verifyScopeGenesis is the genesis-only checks of ReplayScope (extracted so
// the agent variant can call it).
func verifyScopeGenesis(ev *proto.ScopeEvent, st *chain.ScopeState) error {
	sp := &ev.SignedPrefix
	if sp.Kind != proto.KindMemberChange || sp.Payload.Op != proto.OpAdd {
		return errors.New("genesis must be member.change op=add")
	}
	if sp.Scope != nil {
		return errors.New("genesis scope must be nil")
	}
	if len(sp.PrevHash) != 0 || sp.Seq != 0 {
		return errors.New("bad genesis prev_hash/seq")
	}
	if !bytes.Equal(sp.Author, sp.Payload.Member) {
		return errors.New("genesis author must equal member")
	}
	prefix, err := ev.PrevHashInput()
	if err != nil {
		return err
	}
	st.ScopeID = proto.ScopeID(proto.EventID(prefix))
	return nil
}

// applyMemberChangeAgent is the agent-routed variant of chain.applyMemberChange.
//
// Three cases:
//   1. We are removed (op=remove, member==self): return leave=true.
//   2. We are not (yet) a recipient: envelope-only — advance member_set +
//      OEK version, skip projection decryption. This covers pre-admit events
//      a new member receives during a fresh-pull discovery.
//   3. We are a recipient: full processing — extract OEK, decrypt + verify
//      projection, install OEK, replace secret_index.
//
// compacted indicates this event sits past a seq gap in the local chain;
// projection-content integrity checks are skipped because the local state
// is by definition incomplete (STORAGE.md §5.4).
func applyMemberChangeAgent(st *chain.ScopeState, ev *proto.ScopeEvent, ownSuperPub []byte, ag *agent.Client, compacted bool) (bool, error) {
	sp := &ev.SignedPrefix
	pl := &sp.Payload
	if pl.Op != proto.OpAdd && pl.Op != proto.OpRemove {
		return false, fmt.Errorf("member.change: bad op %q", pl.Op)
	}
	want := postMutationSet(st.MemberSet, pl.Member, pl.Op)
	got := recipientSet(sp.KeyDeliveries)
	if !sameSet(want, got) {
		return false, errors.New("member.change: key_deliveries don't match post-mutation set")
	}
	if sp.OEKVersion != st.CurrentOEKVer+1 {
		return false, fmt.Errorf("member.change: bad oek_version=%d, expected %d", sp.OEKVersion, st.CurrentOEKVer+1)
	}
	// Case 1: we are being removed.
	if pl.Op == proto.OpRemove && bytes.Equal(pl.Member, ownSuperPub) {
		return true, nil
	}
	// Empty post-mutation set (last member removed → tombstone): just
	// advance state, no projection.
	if len(want) == 0 {
		st.MemberSet = want
		st.CurrentOEKVer = sp.OEKVersion
		return false, nil
	}
	// Look for our key_delivery.
	ownX, err := crypto.EdPubToX25519(ownSuperPub)
	if err != nil {
		return false, err
	}
	var oek []byte
	for _, kd := range sp.KeyDeliveries {
		if bytes.Equal(kd.RecipientPubkey, ownX) {
			plain, err := ag.OpenSeal(kd.Sealed)
			if err != nil {
				return false, fmt.Errorf("member.change: agent OpenSeal: %w", err)
			}
			if len(plain) != 32 {
				return false, errors.New("member.change: OEK length != 32")
			}
			oek = plain
			break
		}
	}
	// Case 2: not a recipient (pre-admit event during discovery).
	if oek == nil {
		st.MemberSet = want
		st.CurrentOEKVer = sp.OEKVersion
		return false, nil
	}
	if len(pl.EncProjection) < 12 {
		return false, errors.New("member.change: bad enc_projection")
	}
	aad, err := projectionAADAgent(ev)
	if err != nil {
		return false, err
	}
	plain, err := crypto.AEADOpen(oek, pl.EncProjection[:12], pl.EncProjection[12:], aad)
	if err != nil {
		return false, fmt.Errorf("member.change: decrypt projection: %w", err)
	}
	defer crypto.Wipe(plain)
	var proj proto.MemberProjection
	if err := proto.Unmarshal(plain, &proj); err != nil {
		return false, fmt.Errorf("member.change: decode projection: %w", err)
	}
	weAreNewMember := bytes.Equal(pl.Member, ownSuperPub) && pl.Op == proto.OpAdd
	if !weAreNewMember && !compacted {
		projIDs := map[string]*proto.SecretRecord{}
		for _, sec := range proj.Secrets {
			projIDs[sec.ID] = sec.Record
		}
		for id, cur := range st.SecretIndex {
			if cur.Record == nil {
				continue
			}
			pr, ok := projIDs[id]
			if !ok {
				return false, fmt.Errorf("projection missing id %s", id)
			}
			a, _ := proto.Marshal(cur.Record)
			b, _ := proto.Marshal(pr)
			if !bytes.Equal(a, b) {
				return false, fmt.Errorf("projection mismatch for id %s", id)
			}
		}
		for id, rec := range projIDs {
			if rec == nil {
				continue
			}
			if _, known := st.SecretIndex[id]; !known {
				return false, fmt.Errorf("projection injects unknown id %s", id)
			}
		}
	}
	st.OEKs[sp.OEKVersion] = append([]byte(nil), oek...)
	st.CurrentOEKVer = sp.OEKVersion
	st.MemberSet = want
	st.SecretIndex = make(map[string]chain.ScopeSecret, len(proj.Secrets))
	for _, sec := range proj.Secrets {
		st.SecretIndex[sec.ID] = chain.ScopeSecret{Record: sec.Record}
	}
	crypto.Wipe(oek)
	return false, nil
}

func applySecretSet(st *chain.ScopeState, ev *proto.ScopeEvent) error {
	sp := &ev.SignedPrefix
	if len(sp.KeyDeliveries) != 0 {
		return errors.New("secret.set: key_deliveries must be empty")
	}
	if sp.OEKVersion != st.CurrentOEKVer {
		return fmt.Errorf("secret.set: oek_version=%d, want %d", sp.OEKVersion, st.CurrentOEKVer)
	}
	oek, ok := st.OEKs[sp.OEKVersion]
	if !ok {
		// Pre-admit event during discovery: we don't hold this OEK era's
		// key. Skip — the projection in our admit event carries the
		// authoritative state.
		return nil
	}
	if len(sp.Payload.EncBody) < 12 {
		return errors.New("secret.set: bad enc_body")
	}
	aad, err := bodyAADAgent(ev)
	if err != nil {
		return err
	}
	plain, err := crypto.AEADOpen(oek, sp.Payload.EncBody[:12], sp.Payload.EncBody[12:], aad)
	if err != nil {
		return fmt.Errorf("secret.set: decrypt: %w", err)
	}
	defer crypto.Wipe(plain)
	var body proto.SecretBody
	if err := proto.Unmarshal(plain, &body); err != nil {
		return fmt.Errorf("secret.set: decode body: %w", err)
	}
	prefix, err := ev.PrevHashInput()
	if err != nil {
		return err
	}
	st.SecretIndex[body.ID] = chain.ScopeSecret{
		EventID: proto.EventID(prefix),
		Record:  body.Record,
	}
	return nil
}

// AAD helpers. Identical to chain.projectionAAD/bodyAAD; duplicated here to
// avoid exporting chain internals.

func projectionAADAgent(ev *proto.ScopeEvent) ([]byte, error) {
	sp := ev.SignedPrefix
	sp.Payload = proto.Payload{
		Op:     ev.SignedPrefix.Payload.Op,
		Member: ev.SignedPrefix.Payload.Member,
	}
	body, err := proto.Marshal(sp)
	if err != nil {
		return nil, err
	}
	return append([]byte(proto.DomainEvent), body...), nil
}

func bodyAADAgent(ev *proto.ScopeEvent) ([]byte, error) {
	sp := ev.SignedPrefix
	sp.Payload = proto.Payload{}
	body, err := proto.Marshal(sp)
	if err != nil {
		return nil, err
	}
	return append([]byte(proto.DomainEvent), body...), nil
}

// ---- set helpers (duplicated from chain to avoid exporting) ----

func memberContains(set [][]byte, key []byte) bool {
	for _, k := range set {
		if bytes.Equal(k, key) {
			return true
		}
	}
	return false
}

func postMutationSet(prior [][]byte, target []byte, op string) [][]byte {
	switch op {
	case proto.OpAdd:
		out := append([][]byte(nil), prior...)
		out = append(out, append([]byte(nil), target...))
		return sortBytes(out)
	case proto.OpRemove:
		out := make([][]byte, 0, len(prior))
		for _, k := range prior {
			if !bytes.Equal(k, target) {
				out = append(out, k)
			}
		}
		return sortBytes(out)
	}
	return prior
}

func recipientSet(kds []proto.KeyDelivery) [][]byte {
	out := make([][]byte, 0, len(kds))
	for _, kd := range kds {
		out = append(out, append([]byte(nil), kd.RecipientPubkey...))
	}
	return sortBytes(out)
}

func sameSet(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	aX := make([][]byte, 0, len(a))
	for _, p := range a {
		x, err := crypto.EdPubToX25519(p)
		if err != nil {
			return false
		}
		aX = append(aX, x)
	}
	aX = sortBytes(aX)
	for i := range aX {
		if !bytes.Equal(aX[i], b[i]) {
			return false
		}
	}
	return true
}

func sortBytes(s [][]byte) [][]byte {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && bytes.Compare(s[j-1], s[j]) > 0; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
	return s
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
