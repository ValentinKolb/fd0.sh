package chain

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

var ErrMalformedMemberKey = errors.New("chain: malformed member public key")

// Opener decrypts a libsodium sealed-box that was sealed to this principal's
// X25519 public key. Used by ReplayScope to open per-event key_deliveries
// without binding the replay logic to a specific source of the X25519 priv.
//
// Implementations:
//   - LocalOpener (this package): in-process, holds the raw X25519 keypair.
//     Used by chain unit tests and any offline tool that already holds
//     super_priv in plaintext.
//   - cli.AgentOpener: forwards Open over the agent IPC, so super_priv
//     stays mlocked inside fd0-agent and never crosses the fd0 process.
//
// One adapter would have meant a hypothetical seam; two real adapters means
// the seam is earning its keep.
type Opener interface {
	Open(sealed []byte) ([]byte, error)
}

// LocalOpener is the in-process Opener. Pub and Priv are 32-byte X25519
// keys; Priv is the sensitive material — callers should wipe it when done.
type LocalOpener struct {
	Pub  []byte
	Priv []byte
}

// Open implements Opener.
func (o LocalOpener) Open(sealed []byte) ([]byte, error) {
	plain, ok := crypto.OpenAnonymous(sealed, o.Pub, o.Priv)
	if !ok {
		return nil, errors.New("open_anonymous failed")
	}
	return plain, nil
}

// ScopeState is the post-replay state of one scope chain.
type ScopeState struct {
	ScopeID       proto.ScopeID
	MemberSet     [][]byte          // super_pubs, sorted by bytes
	OEKs          map[uint64][]byte // version → 32B key
	CurrentOEKVer uint64
	SecretIndex   map[string]ScopeSecret // secret_id → latest record
	TipSeq        uint64
	TipHash       []byte
	Left          bool // true if a remove-self event was observed
}

// ScopeSecret is one entry in secret_index.
type ScopeSecret struct {
	EventID string
	Record  *proto.SecretRecord // nil = tombstone
}

// ReplayScope verifies every event in path and returns the post-replay state.
//
// Parameters:
//   - path: scope chain file
//   - ownSuperPub: local user's Ed25519 public key (used for member-set
//     checks and to detect "we left this scope")
//   - ownX25519Pub: ownSuperPub mapped onto Curve25519 (used to find OUR
//     key_delivery on each member.change event)
//   - opener: decrypts the sealed-box from key_deliveries when we are a
//     recipient. The lookup is done here in replay (pure list scan); the
//     Open call is the only I/O the replay performs, so the rest of the
//     code path stays testable in isolation.
//
// Compacted-chain handling (STORAGE.md §5.4): if the chain has a gap in
// `seq` between two events, we set `incomplete` for the affected event.
// While `incomplete` is true, projection-content integrity checks are
// skipped — the local secret_index is by definition incomplete past a
// gap, so a content comparison would false-positive. `incomplete` clears
// on the next member.change that successfully populates secret_index.
//
// Pre-admit handling: if a member.change event has no key_delivery
// addressed to us (we joined later in the chain), we advance MemberSet
// and OEKVersion only; projection decryption is skipped. Our admit
// event's projection is the authoritative re-establishment.
//
// THREAT: T20 (bit-flipping of on-disk chain — every event signature
//
//	       checked here),
//	T27 (foreign-author event splice — author ∈ MemberSet check),
//	T29 (insider projection-poisoning for existing members),
//	T30 (no-op membership change rejection).
func ReplayScope(path string, ownSuperPub, ownX25519Pub []byte, opener Opener) (*ScopeState, error) {
	events, err := ReadScopeEvents(path)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	st := &ScopeState{
		OEKs:        make(map[uint64][]byte),
		SecretIndex: make(map[string]ScopeSecret),
	}
	var prevHash []byte
	incomplete := false
	for i, ev := range events {
		sp := &ev.SignedPrefix
		// Envelope checks.
		if i == 0 {
			if err := verifyScopeGenesis(ev, st); err != nil {
				return nil, fmt.Errorf("scope[0]: %w", err)
			}
		} else {
			if sp.Scope == nil || *sp.Scope != st.ScopeID.String() {
				return nil, fmt.Errorf("scope[%d]: scope mismatch", i)
			}
			// SECURITY (codex audit 🔴 scope.go:113): forward-only
			// monotonicity. The previous gap-tolerant code accepted
			// any sp.Seq != TipSeq+1 (incl. ==TipSeq or <TipSeq) as
			// "compaction gap" and skipped the prev_hash check. A
			// tampered local file could re-replay older signed
			// events out of order, then close with the real
			// vault-bound tip so CompareScopeTip still passes while
			// SecretIndex contains stale data. Only sp.Seq > TipSeq+1
			// is a legitimate compaction-induced forward gap.
			switch {
			case sp.Seq <= st.TipSeq:
				return nil, fmt.Errorf("scope[%d]: non-monotone seq=%d (tip=%d)", i, sp.Seq, st.TipSeq)
			case sp.Seq == st.TipSeq+1:
				if !bytes.Equal(sp.PrevHash, prevHash) {
					return nil, fmt.Errorf("scope[%d]: prev_hash mismatch", i)
				}
			default: // sp.Seq > TipSeq+1 — forward gap (compacted prefix)
				incomplete = true
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
		if !crypto.VerifyBytes(sp.Author, si, ev.Signature.Signature) {
			return nil, fmt.Errorf("scope[%d]: bad signature", i)
		}
		// Per-kind apply.
		switch sp.Kind {
		case proto.KindMemberChange:
			// Open OUR key_delivery if present. Replay does the I/O
			// (single Open call) so applyMemberChange stays pure
			// (testable with fixture OEKs, no Opener needed).
			sealed := findOurKeyDelivery(ev, ownX25519Pub)
			var oekPlain []byte
			if sealed != nil {
				p, err := opener.Open(sealed)
				if err != nil {
					return nil, fmt.Errorf("scope[%d]: open key_delivery: %w", i, err)
				}
				if len(p) != 32 {
					return nil, fmt.Errorf("scope[%d]: OEK length != 32", i)
				}
				oekPlain = p
			}
			leave, err := applyMemberChange(st, ev, ownSuperPub, oekPlain, incomplete)
			if err != nil {
				return nil, fmt.Errorf("scope[%d]: %w", i, err)
			}
			if leave {
				st.Left = true
			}
			// After a successful projection-populating apply,
			// secret_index is the authoritative snapshot for the
			// current OEK era again. Clear incomplete so subsequent
			// member.changes get full integrity checks.
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
		// Advance tip.
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

// verifyScopeGenesis runs the genesis-only checks of ReplayScope. Pulled
// out so the per-event loop is shorter.
func verifyScopeGenesis(ev *proto.ScopeEvent, st *ScopeState) error {
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
	st.ScopeID = proto.DeriveScopeID(proto.EventID(prefix))
	return nil
}

// findOurKeyDelivery returns the sealed-box from key_deliveries whose
// recipient_pubkey matches ownX25519Pub, or nil if none match. The lookup
// is a pure data scan — no I/O — so it stays in the replay loop alongside
// the per-event validation.
func findOurKeyDelivery(ev *proto.ScopeEvent, ownX25519Pub []byte) []byte {
	for _, kd := range ev.SignedPrefix.KeyDeliveries {
		if bytes.Equal(kd.RecipientPubkey, ownX25519Pub) {
			return kd.Sealed
		}
	}
	return nil
}

// applyMemberChange validates op/recipients, decrypts and verifies the
// projection if we are a recipient, and updates st in place. Pure: takes
// the pre-opened OEK plaintext (oekPlain) instead of an Opener.
//
// Cases handled:
//  1. We are removed (op=remove member=self) → return leave=true.
//  2. Empty post-mutation set (last member removed) → tombstone-advance,
//     no OEK installation.
//  3. We have no key_delivery (oekPlain == nil) → pre-admit event during
//     discovery; advance MemberSet+OEKVersion, skip projection.
//  4. Full processing: decrypt projection, verify content (unless we're
//     the new admit or the chain is past a gap), install OEK + new
//     secret_index.
//
// `compacted=true` skips the projection-content integrity check: the
// local secret_index is incomplete past a chain gap (STORAGE.md §5.4),
// so projection-vs-index comparison would false-positive.
func applyMemberChange(st *ScopeState, ev *proto.ScopeEvent, ownSuperPub, oekPlain []byte, compacted bool) (bool, error) {
	sp := &ev.SignedPrefix
	pl := &sp.Payload
	if len(st.MemberSet) > proto.MaxLegacyScopeMembers {
		return false, errors.New("member.change: prior member set exceeds protocol limit")
	}
	if len(sp.KeyDeliveries) > proto.MaxKeyDeliveries {
		return false, errors.New("member.change: too many key_deliveries")
	}
	if pl.Op != proto.OpAdd && pl.Op != proto.OpRemove {
		return false, fmt.Errorf("member.change: bad op %q", pl.Op)
	}
	if len(pl.Member) != ed25519.PublicKeySize {
		return false, fmt.Errorf(
			"%w: member.change target has %d bytes, want %d",
			ErrMalformedMemberKey,
			len(pl.Member),
			ed25519.PublicKeySize,
		)
	}
	// SECURITY (codex audit 🔴 scope.go:249): no-op membership
	// changes MUST be rejected. add of an existing member or
	// remove of a non-member are both protocol violations and the
	// previous code accepted them silently. The downstream
	// `weAreNewMember` check (which skips projection verification
	// for the new admit) would then fire for an EXISTING member
	// whose author re-added themselves, letting an insider bypass
	// projection-content integrity and inject arbitrary entries.
	isMember := memberContains(st.MemberSet, pl.Member)
	switch pl.Op {
	case proto.OpAdd:
		if isMember {
			return false, fmt.Errorf("member.change: redundant add of existing member %x", pl.Member[:8])
		}
		if len(st.MemberSet) >= proto.MaxScopeMembers {
			return false, errors.New("member.change: scope member limit reached")
		}
	case proto.OpRemove:
		if !isMember {
			return false, fmt.Errorf("member.change: remove of non-member %x", pl.Member[:8])
		}
	}
	want := postMutationSet(st.MemberSet, pl.Member, pl.Op)
	if len(sp.KeyDeliveries) != len(want) {
		return false, errors.New("member.change: key_deliveries don't match post-mutation set")
	}
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
	// Case 2: empty post-set (last member removed → tombstone scope).
	if len(want) == 0 {
		st.MemberSet = want
		st.CurrentOEKVer = sp.OEKVersion
		return false, nil
	}
	// Case 3: we have no key_delivery → pre-admit event during discovery.
	if oekPlain == nil {
		st.MemberSet = want
		st.CurrentOEKVer = sp.OEKVersion
		return false, nil
	}
	// Case 4: full processing.
	if len(pl.EncProjection) < 12 {
		return false, errors.New("member.change: bad enc_projection")
	}
	aad, err := ProjectionAAD(ev)
	if err != nil {
		return false, err
	}
	plain, err := crypto.AEADOpen(oekPlain, pl.EncProjection[:12], pl.EncProjection[12:], aad)
	if err != nil {
		return false, fmt.Errorf("member.change: decrypt projection: %w", err)
	}
	defer crypto.Wipe(plain)
	var proj proto.MemberProjection
	if err := proto.Unmarshal(plain, &proj); err != nil {
		return false, fmt.Errorf("member.change: decode projection: %w", err)
	}
	// Projection verification (PROTOCOL.md §4.5 steps 3–4): every
	// non-tombstone in our index must appear byte-identically in the
	// projection, and the projection must not inject unknown ids.
	// Skipped for our own admit event (no prior local state) and past
	// chain gaps (incomplete local state would false-positive).
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
	// Install OEK and replace state.
	//
	// SECURITY (subagent audit 🟡): the deferred crypto.Wipe(plain)
	// at the top of this function will zero `plain` after we
	// return. The decoded *SecretRecord objects in proj.Secrets
	// may share byte buffers with `plain` (CBOR decoders are
	// allowed to alias). Storing them directly into st.SecretIndex
	// would leave dangling pointers into a wiped buffer the moment
	// the function returns. We defensively re-marshal + re-decode
	// each record into a fresh, independently-allocated *Record
	// before installing.
	st.OEKs[sp.OEKVersion] = append([]byte(nil), oekPlain...)
	st.CurrentOEKVer = sp.OEKVersion
	st.MemberSet = want
	st.SecretIndex = make(map[string]ScopeSecret, len(proj.Secrets))
	for _, sec := range proj.Secrets {
		if sec.Record == nil {
			st.SecretIndex[sec.ID] = ScopeSecret{}
			continue
		}
		buf, mErr := proto.Marshal(sec.Record)
		if mErr != nil {
			return false, fmt.Errorf("member.change: re-marshal projection secret %s: %w", sec.ID, mErr)
		}
		var fresh proto.SecretRecord
		if uErr := proto.Unmarshal(buf, &fresh); uErr != nil {
			return false, fmt.Errorf("member.change: re-decode projection secret %s: %w", sec.ID, uErr)
		}
		st.SecretIndex[sec.ID] = ScopeSecret{Record: &fresh}
	}
	crypto.Wipe(oekPlain)
	return false, nil
}

// applySecretSet decrypts enc_body under the current OEK and updates the
// index. Silently no-ops when the OEK version isn't held locally —
// happens during discovery when we receive pre-admit events whose OEK
// era predates our admit. Our admit's projection is authoritative for
// those secrets.
func applySecretSet(st *ScopeState, ev *proto.ScopeEvent) error {
	sp := &ev.SignedPrefix
	if len(sp.KeyDeliveries) != 0 {
		return errors.New("secret.set: key_deliveries must be empty")
	}
	if sp.OEKVersion != st.CurrentOEKVer {
		return fmt.Errorf("secret.set: oek_version=%d, want %d", sp.OEKVersion, st.CurrentOEKVer)
	}
	oek, ok := st.OEKs[sp.OEKVersion]
	if !ok {
		// Pre-admit: skip silently, the admit event's projection covers it.
		return nil
	}
	if len(sp.Payload.EncBody) < 12 {
		return errors.New("secret.set: bad enc_body")
	}
	aad, err := BodyAAD(ev)
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
	st.SecretIndex[body.ID] = ScopeSecret{
		EventID: proto.EventID(prefix),
		Record:  body.Record,
	}
	return nil
}

// ProjectionAAD returns the AAD used for AEAD-sealing the member.change
// enc_projection: DomainEvent || cbor(SignedPrefix with payload reduced
// to {op, member}).
//
// Exported because the cli builds projections too (encryptProjection in
// cli/build.go). Sharing the AAD constructor enforces that writer and
// reader agree byte-for-byte on the AAD shape.
func ProjectionAAD(ev *proto.ScopeEvent) ([]byte, error) {
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

// BodyAAD returns the AAD used for AEAD-sealing the secret.set enc_body:
// DomainEvent || cbor(SignedPrefix with payload cleared).
//
// Exported for the cli's secret.set builder and decrypt helper. Same
// rationale as ProjectionAAD: one constructor, no chance of writer and
// reader drifting.
func BodyAAD(ev *proto.ScopeEvent) ([]byte, error) {
	sp := ev.SignedPrefix
	sp.Payload = proto.Payload{}
	body, err := proto.Marshal(sp)
	if err != nil {
		return nil, err
	}
	return append([]byte(proto.DomainEvent), body...), nil
}

// PostMutationSet returns the member set after applying op (add|remove)
// of target to prior. Exported because the cli's member.change builder
// needs the same computation when constructing key_deliveries.
//
// For op=add of an already-present member, returns prior unchanged
// (caller is expected to have pre-validated).
func PostMutationSet(prior [][]byte, target []byte, op string) [][]byte {
	return postMutationSet(prior, target, op)
}

// RebaseMemberChangeMeaningful answers "is a local-only member.change still
// worth re-emitting after the server's authoritative chain has been replayed
// onto the running member set?" Used by the sync reconcile path to decide
// whether to drop or rebuild a divergent member.change.
//
// Semantic rebase:
//
//	op=add,    target ∈ running → drop (someone else added them, or we did)
//	op=add,    target ∉ running → re-emit (legitimate add against new state)
//	op=remove, target ∈ running → re-emit (legitimate remove against new state)
//	op=remove, target ∉ running → drop (someone else removed them, or we did)
//
// Why no "removes win" priority for an add+remove conflict on the same
// target: with a peer-to-peer member set, "remove X" and "add X" by two
// members are independent acts. The post-replay running set already
// reflects whichever landed first; a rebased peer event simply applies on
// top — same semantics as a fresh `scope add-member` issued today.
func RebaseMemberChangeMeaningful(running [][]byte, op string, target []byte) bool {
	in := memberContains(running, target)
	switch op {
	case proto.OpAdd:
		return !in
	case proto.OpRemove:
		return in
	}
	return false
}

// ---- helpers for member sets (private) ----

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
		if memberContains(prior, target) {
			return prior // illegal but caller checks
		}
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

// sameSet compares the post-mutation member set (Ed25519 pubs) against
// the recipient set (X25519 pubs). The Ed25519 keys are mapped onto
// Curve25519 before comparison.
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
	sort.Slice(s, func(i, j int) bool { return bytes.Compare(s[i], s[j]) < 0 })
	return s
}

// LocalOnlyEvents returns the events present in `local` but not in
// `server`, identified by content-addressed event_id. The returned
// slice preserves local order.
//
// Pure: no I/O, no decryption. Used by sync's reconcile path to spot
// events that were authored locally and never reached the server (the
// classic divergence case: we wrote a secret while the server was
// being updated by another device, so our prev_hash doesn't match the
// new tip and the push is rejected). The cli wraps this with
// per-event author/kind/decrypt logic to recover the secret bodies.
//
// Compaction-aware: a slice-index diff would be wrong when local is
// compacted (non-contiguous) but server is full. Comparing event_ids
// is the only correct way; the chain's hash-prefix construction
// guarantees event_id uniquely identifies an event's payload.
func LocalOnlyEvents(local, server []proto.ScopeEvent) []proto.ScopeEvent {
	serverIDs := make(map[string]struct{}, len(server))
	for _, ev := range server {
		prefix, _ := ev.PrevHashInput()
		serverIDs[proto.EventID(prefix)] = struct{}{}
	}
	out := make([]proto.ScopeEvent, 0, len(local))
	for _, ev := range local {
		prefix, _ := ev.PrevHashInput()
		if _, onServer := serverIDs[proto.EventID(prefix)]; onServer {
			continue
		}
		out = append(out, ev)
	}
	return out
}
