package cli

// Automatic migration of scope chains written by the retired v1 compactor.
//
// The compactor rewrote a scope chain to "genesis plus a recent window".
// ReplayScope rejects the resulting gap (chain.ErrScopeHistoryNonContiguous)
// and that rejection is correct — a gap is unverifiable from local state, so
// accepting one could hide a dropped event. The rejection stays. What this
// file adds is a way OUT of that state that does not require the user to
// know anything, and that does not require trusting the server.
//
// How it avoids trusting the server
// ---------------------------------
// The vault stores, per scope, a ChainTip{Seq,Hash} that this client sealed
// locally when it last replayed the full history. That tip is a local trust
// anchor: the server never got to choose it. Migration re-fetches the full
// history through fullPullScope (STH signature, per-page inclusion proofs,
// witness cross-check, pinned server key — all unchanged), cuts it at the
// vault-bound Seq, and requires that prefix to replay to exactly the
// vault-bound Hash. Because the chain is hash-linked, that equality can only
// hold if every event in the prefix is bit-for-bit the history this client
// already accepted. A server that substitutes, drops, reorders, or inserts
// anything at or below the bound tip produces a different hash and the
// migration refuses.
//
// This is the one thing reconcileAndRepush deliberately does NOT do: it
// overwrites the bound tip with whatever the server returned
// (sync_reconcile.go, applyReplayedScope). That is right for a genuine
// divergence — the server IS the ordering authority and local writes get
// rebased onto its tip — but it is wrong for a migration, where the whole
// point is that nothing about the accepted history may change.
//
// What it deliberately does not do
// --------------------------------
//   - It never adopts events beyond the bound tip. Anything the server has
//     past our tip is picked up by the ordinary cursor-based pull, with its
//     ordinary verification. Migration restores history, it does not advance
//     it.
//   - It never writes to the vault. A successful migration leaves vault.enc
//     byte-identical; only the chain file changes, atomically. There is no
//     window in which the tip binding and the chain file disagree.
//   - It never performs first-contact pinning. Pinning is a ceremony the
//     user consents to; doing it silently inside an unattended repair would
//     turn "open the app offline" into "trust whatever answered".
//   - It never rebuilds or re-pushes local-only events. If any local event
//     is absent from the candidate the migration declines and leaves the
//     file untouched, so those events survive on disk exactly as authored —
//     the same preservation guarantee reconcileAndRepush gives, reached by
//     refusing rather than rebasing. In practice the tip anchor already
//     rules this out (a missing local event breaks the hash chain), so the
//     check is a second, independent guard against ever losing a write.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

var (
	// ErrLegacyScopeHistoryNeedsServer means the vault needs the one-time
	// repair but the server side of it could not be reached or is not yet
	// trusted. Local state is untouched; retrying is always safe.
	ErrLegacyScopeHistoryNeedsServer = errors.New("legacy scope history repair needs the fd0 server")

	// ErrLegacyScopeHistoryUnverifiable means the server answered but the
	// history it returned does not replay to the tip this device already
	// sealed. That is a divergence, which `fd0 sync`'s reconcile path owns —
	// never something to adopt silently.
	ErrLegacyScopeHistoryUnverifiable = errors.New("legacy scope history repair could not be verified against the local trust anchor")
)

// legacyRepairAdvice is appended to every user-facing migration failure. The
// two facts a user needs are "this is an old vault" and "nothing broke".
const legacyRepairAdvice = "nothing on this device has been changed, so retrying is safe"

// HasLegacyCompactedScopes reports whether any subscribed scope's chain file
// carries the retired compactor's signature. Local-only and cheap: no
// network, no vault write. Callers use it to decide whether the (network-
// dependent) migration is worth attempting at all.
func (s *Session) HasLegacyCompactedScopes() bool {
	return len(s.legacyCompactedScopeIDs()) > 0
}

// legacyCompactedScopeIDs returns the sorted scope ids whose chain file is
// legacy-compacted.
//
// Scopes whose file cannot be read or classified are skipped, not reported:
// migration is strictly additive, and an unrelated unreadable chain must not
// turn "open the app" into "migration failed". The ordinary replay still
// surfaces the real error for that scope.
func (s *Session) legacyCompactedScopeIDs() []string {
	out := make([]string, 0, len(s.Body.Scopes))
	for scopeID := range s.Body.Scopes {
		cls, err := chain.ClassifyScopeChain(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)))
		if err != nil || cls.Shape != chain.ScopeShapeLegacyCompacted {
			continue
		}
		out = append(out, scopeID)
	}
	sort.Strings(out)
	return out
}

// MigrateLegacyScopeChains repairs every legacy-compacted scope chain in this
// vault. Safe to call from anywhere, idempotent, and a no-op (with no network
// traffic at all) when nothing needs migrating.
//
// On any failure the local chain files and the vault are left exactly as they
// were and the returned error wraps ErrLegacyScopeHistoryNeedsServer or
// ErrLegacyScopeHistoryUnverifiable so callers can render a specific message.
func (s *Session) MigrateLegacyScopeChains(ctx context.Context) error {
	pending := s.legacyCompactedScopeIDs()
	if len(pending) == 0 {
		return nil
	}
	server, wcc, err := s.legacyMigrationTransport()
	if err != nil {
		return err
	}
	for _, scopeID := range pending {
		if err := s.migrateLegacyScopeChain(ctx, wcc, server, scopeID); err != nil {
			return err
		}
	}
	return nil
}

// MigrateLegacyScopeChain repairs one scope. Same contract as
// MigrateLegacyScopeChains, narrowed to a single scope so the read path can
// repair exactly the chain a caller tripped over.
func (s *Session) MigrateLegacyScopeChain(ctx context.Context, scopeID string) error {
	path := s.Paths.ScopeChain(proto.MustParseScopeID(scopeID))
	cls, err := chain.ClassifyScopeChain(path)
	if err != nil || cls.Shape != chain.ScopeShapeLegacyCompacted {
		return nil
	}
	server, wcc, err := s.legacyMigrationTransport()
	if err != nil {
		return err
	}
	return s.migrateLegacyScopeChain(ctx, wcc, server, scopeID)
}

// legacyMigrationTransport resolves the primary server and witness client for
// a migration.
//
// The server MUST already be pinned. First-contact pinning is a consent
// ceremony (translog.go, EnsurePinnedServer) and an unattended background
// repair is the wrong place to perform it: an unpinned client has no way to
// tell the real server from whatever answered, and the whole value of this
// migration is that it needs no trust in the server at all.
func (s *Session) legacyMigrationTransport() (canon.URL, *WitnessCheckClient, error) {
	// Every message below leads with the same two facts, because they are the
	// two a user needs no matter which step failed: the vault is an old one,
	// and nothing has been broken by trying.
	const preamble = "this vault was written by an older version of fd0 and needs a one-time history repair from your fd0 server before it can be read"
	raw, err := ResolvePrimary("")
	if err != nil {
		return canon.URL{}, nil, fmt.Errorf("%w: %s, but no fd0 server is configured (%v) — set [sync].server in config.toml and run `fd0 sync`; %s",
			ErrLegacyScopeHistoryNeedsServer, preamble, err, legacyRepairAdvice)
	}
	server, err := canon.ParseURL(raw)
	if err != nil {
		return canon.URL{}, nil, fmt.Errorf("%w: %s, but the configured fd0 server address is invalid (%v) — fix [sync].server in config.toml and run `fd0 sync`; %s",
			ErrLegacyScopeHistoryNeedsServer, preamble, err, legacyRepairAdvice)
	}
	cfg, _ := fdhome.LoadConfig(s.Paths.Config)
	wcc, err := NewWitnessCheckClient(cfg)
	if err != nil {
		return canon.URL{}, nil, fmt.Errorf("%w: %s, but the [[witness]] configuration is invalid (%v) — fix it in config.toml and run `fd0 sync`; %s",
			ErrLegacyScopeHistoryNeedsServer, preamble, err, legacyRepairAdvice)
	}
	if _, err := s.PinnedServerPub(server); err != nil {
		return canon.URL{}, nil, fmt.Errorf(
			"%w: %s, but no server identity is pinned on this device yet — run `fd0 sync` once while online to verify and pin %s; %s",
			ErrLegacyScopeHistoryNeedsServer, preamble, server, legacyRepairAdvice)
	}
	return server, wcc, nil
}

// migrateLegacyScopeChain performs the migration for one scope against the
// pinned server.
func (s *Session) migrateLegacyScopeChain(ctx context.Context, wcc *WitnessCheckClient, server canon.URL, scopeID string) error {
	fetch := func() ([]proto.ScopeEvent, error) {
		events, _, err := s.fullPullScope(ctx, wcc, server, scopeID)
		return events, err
	}
	return s.migrateLegacyScopeChainFrom(scopeID, fetch, AgentOpener{Agent: s.Agent})
}

// migrateLegacyScopeChainFrom is the migration proper, with the two seams a
// test needs made explicit: where the verified history comes from, and which
// Opener replay uses. Production always passes fullPullScope (transparency
// log, inclusion proofs, witness cross-check, pinned key) and the
// agent-backed Opener; nothing in here relaxes either.
//
// Every check runs before anything is written; the write itself is atomic and
// is rolled back if the committed file fails a final re-verification.
func (s *Session) migrateLegacyScopeChainFrom(scopeID string, fetch func() ([]proto.ScopeEvent, error), opener chain.Opener) error {
	path := s.Paths.ScopeChain(proto.MustParseScopeID(scopeID))
	cls, err := chain.ClassifyScopeChain(path)
	if err != nil {
		return fmt.Errorf("scope %s: inspect local history: %w", shortScopeID(scopeID), err)
	}
	if cls.Shape != chain.ScopeShapeLegacyCompacted {
		// Idempotent: already migrated, or never was the compactor's output.
		return nil
	}
	sd, subscribed := s.Body.Scopes[scopeID]
	if !subscribed {
		return nil
	}
	vaultTip := sd.ChainTip
	if len(vaultTip.Hash) == 0 {
		return fmt.Errorf("%w: scope %s has no sealed chain tip to anchor the repair against — run `fd0 sync`; %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), legacyRepairAdvice)
	}
	// The compactor kept the final event verbatim, so the file's committed
	// tip must still be the bound tip. If it is not, this file has been
	// changed by something other than the compactor and the anchor argument
	// below does not apply.
	if !cls.HasTip || cls.Tip.Seq != vaultTip.Seq || !bytes.Equal(cls.Tip.Hash, vaultTip.Hash) {
		return fmt.Errorf("%w: scope %s ends at seq %d but the vault is sealed to seq %d — run `fd0 sync` to reconcile; %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), cls.Tip.Seq, vaultTip.Seq, legacyRepairAdvice)
	}

	// Fetch the full, transparency-verified history. fullPullScope checks the
	// STH signature against the pinned server key, every page's inclusion
	// proofs, and cross-checks with the configured witnesses. None of that is
	// relaxed here.
	serverEvents, err := fetch()
	if err != nil {
		if errors.Is(err, errScopePullDenied) {
			// The server no longer authorises us on this scope. Not a
			// migration problem; the next sync removes the subscription.
			return nil
		}
		return fmt.Errorf(
			"%w: this vault was written by an older version of fd0 and scope %s needs a one-time history repair from your fd0 server before it can be read, but fd0 could not fetch it (%v) — reconnect and run `fd0 sync`; %s",
			ErrLegacyScopeHistoryNeedsServer, shortScopeID(scopeID), err, legacyRepairAdvice)
	}

	// Cut at the bound tip. Everything past it is the ordinary pull's job.
	cut := -1
	for i := range serverEvents {
		if serverEvents[i].SignedPrefix.Seq == vaultTip.Seq {
			cut = i
			break
		}
	}
	if cut < 0 {
		return fmt.Errorf("%w: the server's history for scope %s does not reach seq %d, which this device has already sealed — run `fd0 sync` to reconcile; %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), vaultTip.Seq, legacyRepairAdvice)
	}
	candidate := serverEvents[:cut+1]

	// Contiguity BEFORE the commit. A server copy that is itself gapped must
	// be rejected here, not adopted and rejected on the next read.
	if err := chain.ValidateScopeEventContinuity(candidate); err != nil {
		return fmt.Errorf("%w: the history the server returned for scope %s is itself incomplete (%v) — run `fd0 sync`; %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), err, legacyRepairAdvice)
	}

	// THE anchor check. Replay the candidate in memory — full signature,
	// member-set, projection and AEAD verification, identical to the on-disk
	// replay — and require the resulting tip to equal the tip the vault
	// sealed. Nothing has been written at this point.
	candidatePtrs := make([]*proto.ScopeEvent, len(candidate))
	for i := range candidate {
		candidatePtrs[i] = &candidate[i]
	}
	st, err := chain.ReplayScopeEvents(candidatePtrs, s.UserSuperPub, s.UserX25519Pub, opener, nil)
	if err != nil {
		return fmt.Errorf("%w: the history the server returned for scope %s failed verification (%v) — run `fd0 sync`; %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), err, legacyRepairAdvice)
	}
	if st == nil {
		return fmt.Errorf("%w: the server returned an empty history for scope %s — run `fd0 sync`; %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), legacyRepairAdvice)
	}
	if st.TipSeq != vaultTip.Seq || !bytes.Equal(st.TipHash, vaultTip.Hash) {
		return fmt.Errorf("%w: the history the server returned for scope %s replays to seq %d hash %x, but this device is sealed to seq %d hash %x — that is a divergence, not an old-format vault; run `fd0 sync` to reconcile it; %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID),
			st.TipSeq, st.TipHash, vaultTip.Seq, vaultTip.Hash, legacyRepairAdvice)
	}

	// Second, independent guard against losing a local write. The anchor check
	// above already implies it — a local event the candidate lacks would break
	// the hash chain and change the replayed tip — so this should be
	// unreachable. A dropped local event is nevertheless the one failure this
	// code must never have, so it is also checked directly rather than left
	// resting on an inference. Refusing (instead of rebasing, which is what
	// reconcileAndRepush does for a real divergence) is what preserves them:
	// the file is not written, so every local event stays exactly as authored.
	localPtrs, err := chain.ReadScopeEvents(path)
	if err != nil {
		return fmt.Errorf("scope %s: read local history: %w", shortScopeID(scopeID), err)
	}
	localValues := make([]proto.ScopeEvent, len(localPtrs))
	for i, ev := range localPtrs {
		localValues[i] = *ev
	}
	if extra := chain.LocalOnlyEvents(localValues, candidate); len(extra) > 0 {
		return fmt.Errorf("%w: scope %s holds %d event(s) the server's history does not contain — refusing to replace it so nothing is lost; run `fd0 sync` to reconcile; %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), len(extra), legacyRepairAdvice)
	}

	// Commit. Transactional: snapshot first, restore on any failure.
	original, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("scope %s: snapshot local history: %w", shortScopeID(scopeID), err)
	}
	restore := func() {
		_ = os.WriteFile(path, original, 0o600)
	}
	raws := make([][]byte, 0, len(candidate))
	for i := range candidate {
		raw, mErr := proto.Marshal(&candidate[i])
		if mErr != nil {
			return fmt.Errorf("scope %s: encode repaired history: %w", shortScopeID(scopeID), mErr)
		}
		raws = append(raws, raw)
	}
	if err := chain.WriteAll(path, raws); err != nil {
		restore()
		return fmt.Errorf("scope %s: write repaired history: %w", shortScopeID(scopeID), err)
	}
	// Final re-verification of what actually landed on disk. Everything below
	// has already been proven about the in-memory candidate; re-proving it
	// against the file closes the gap between "what we validated" and "what
	// we wrote".
	after, err := chain.ClassifyScopeChain(path)
	switch {
	case err != nil:
		restore()
		return fmt.Errorf("scope %s: re-inspect repaired history: %w", shortScopeID(scopeID), err)
	case after.Shape != chain.ScopeShapeContiguous:
		restore()
		return fmt.Errorf("%w: repaired history for scope %s is still %s (%s) — %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), after.Shape, after.Reason, legacyRepairAdvice)
	case after.Tip.Seq != vaultTip.Seq || !bytes.Equal(after.Tip.Hash, vaultTip.Hash):
		restore()
		return fmt.Errorf("%w: repaired history for scope %s does not end at the sealed tip — %s",
			ErrLegacyScopeHistoryUnverifiable, shortScopeID(scopeID), legacyRepairAdvice)
	}
	return nil
}

// migrateLegacyScopeOnRead is the lazy hook: a read tripped over
// chain.ErrScopeHistoryNonContiguous, so try exactly once per session to
// migrate that scope and let the caller retry the read.
//
// Returns (true, nil) when the chain was migrated and the read should be
// retried, (false, nil) when this scope is not the compactor's output (the
// caller keeps the original replay error, which is the honest one), and
// (false, err) when the migration was needed but could not run — that error
// is the actionable one and replaces the raw "non-contiguous" text.
func (s *Session) migrateLegacyScopeOnRead(scopeID string) (bool, error) {
	if s.legacyMigrationTried == nil {
		s.legacyMigrationTried = map[string]bool{}
	}
	if s.legacyMigrationTried[scopeID] {
		return false, nil
	}
	s.legacyMigrationTried[scopeID] = true
	cls, err := chain.ClassifyScopeChain(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)))
	if err != nil || cls.Shape != chain.ScopeShapeLegacyCompacted {
		return false, nil
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.MigrateLegacyScopeChain(ctx, scopeID); err != nil {
		return false, err
	}
	return true, nil
}

// MigrateLegacyScopesAfterUnlock is the post-unlock hook. It opens a session
// of its own (the caller has just unlocked, so the agent is ready), migrates
// anything that needs it, and reports a user-facing error only when a
// migration was actually required and could not be completed.
//
// A failure to open the session is not reported: the very next command opens
// one too and will surface the real reason. Unlock itself must never fail
// because of this.
func MigrateLegacyScopesAfterUnlock(ctx context.Context) error {
	s, err := Open(ctx)
	if err != nil {
		return nil
	}
	defer s.Close()
	if !s.HasLegacyCompactedScopes() {
		return nil
	}
	fmt.Fprintln(os.Stderr, "  ↳ this vault was written by an older version of fd0 — running a one-time history repair from your fd0 server")
	if err := s.MigrateLegacyScopeChains(ctx); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "  ↳ history repair complete")
	return nil
}
