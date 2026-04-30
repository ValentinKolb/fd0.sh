package chain

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// ScopeState is the post-replay state of one scope chain.
type ScopeState struct {
	ScopeID       string
	MemberSet     [][]byte                   // super_pubs, sorted by bytes
	OEKs          map[uint64][]byte          // version → 32B key
	CurrentOEKVer uint64
	SecretIndex   map[string]ScopeSecret     // secret_id → latest record
	TipSeq        uint64
	TipHash       []byte
	Left          bool                       // true if a remove-self event was observed
}

// ScopeSecret is one entry in secret_index.
type ScopeSecret struct {
	EventID string
	Record  *proto.SecretRecord // nil = tombstone
}

// ReplayScope verifies every event in path. ownSuperPub is the local user's
// Ed25519 public key; ownX25519Priv is its X25519 scalar (derived once from
// super_priv, kept in a Secret).
func ReplayScope(path string, ownSuperPub []byte, ownX25519Pub, ownX25519Priv []byte) (*ScopeState, error) {
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
	for i, ev := range events {
		sp := &ev.SignedPrefix
		// Envelope checks common to all events.
		if i == 0 {
			if sp.Kind != proto.KindMemberChange || sp.Payload.Op != proto.OpAdd {
				return nil, errors.New("scope[0]: genesis must be member.change op=add")
			}
			if sp.Scope != nil {
				return nil, errors.New("scope[0]: genesis scope must be nil")
			}
			if len(sp.PrevHash) != 0 || sp.Seq != 0 {
				return nil, errors.New("scope[0]: bad genesis prev_hash/seq")
			}
			if !bytes.Equal(sp.Author, sp.Payload.Member) {
				return nil, errors.New("scope[0]: genesis author must equal member")
			}
			// Derive scope_id from the genesis event_id (PROTOCOL.md §1.3).
			prefix, err := ev.PrevHashInput()
			if err != nil {
				return nil, err
			}
			st.ScopeID = proto.ScopeID(proto.EventID(prefix))
		} else {
			if sp.Scope == nil || *sp.Scope != st.ScopeID {
				return nil, fmt.Errorf("scope[%d]: scope mismatch", i)
			}
			if sp.Seq != st.TipSeq+1 {
				return nil, fmt.Errorf("scope[%d]: seq=%d, expected %d", i, sp.Seq, st.TipSeq+1)
			}
			if !bytes.Equal(sp.PrevHash, prevHash) {
				return nil, fmt.Errorf("scope[%d]: prev_hash mismatch", i)
			}
			if !memberContains(st.MemberSet, sp.Author) {
				return nil, fmt.Errorf("scope[%d]: author not in member set", i)
			}
		}
		// Author == signer.
		if !bytes.Equal(sp.Author, ev.Signature.SignerPubkey) {
			return nil, fmt.Errorf("scope[%d]: signer != author", i)
		}
		// Signature verifies.
		si, err := ev.SignedInput()
		if err != nil {
			return nil, err
		}
		if !crypto.Verify(sp.Author, si, ev.Signature.Signature) {
			return nil, fmt.Errorf("scope[%d]: bad signature", i)
		}
		// Per-kind apply.
		switch sp.Kind {
		case proto.KindMemberChange:
			leave, err := applyMemberChange(st, ev, ownSuperPub, ownX25519Pub, ownX25519Priv)
			if err != nil {
				return nil, fmt.Errorf("scope[%d]: %w", i, err)
			}
			if leave {
				st.Left = true
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

// applyMemberChange validates op/recipients, decrypts our key_delivery if we
// were a recipient, and decrypts/verifies the projection.
//
// Returns leave=true if this event removes us from the scope.
func applyMemberChange(st *ScopeState, ev *proto.ScopeEvent, ownSuperPub, ownX25519Pub, ownX25519Priv []byte) (bool, error) {
	sp := &ev.SignedPrefix
	pl := &sp.Payload
	if pl.Op != proto.OpAdd && pl.Op != proto.OpRemove {
		return false, fmt.Errorf("member.change: bad op %q", pl.Op)
	}
	// Validate post-mutation member set vs. recipients.
	want := postMutationSet(st.MemberSet, pl.Member, pl.Op)
	got := recipientSet(sp.KeyDeliveries)
	if !sameSet(want, got) {
		return false, errors.New("member.change: key_deliveries don't match post-mutation set")
	}
	// OEK version monotonic by exactly +1.
	if sp.OEKVersion != st.CurrentOEKVer+1 {
		return false, fmt.Errorf("member.change: bad oek_version=%d, expected %d", sp.OEKVersion, st.CurrentOEKVer+1)
	}
	// If this is op=remove of self: short-circuit, no decrypt needed.
	if pl.Op == proto.OpRemove && bytes.Equal(pl.Member, ownSuperPub) {
		return true, nil
	}
	// Find our key_delivery (recipient_pubkey is X25519, so compare by it).
	if len(want) == 0 {
		// Last member removed: tombstone scope; no OEK to install.
		st.MemberSet = want
		st.CurrentOEKVer = sp.OEKVersion
		return false, nil
	}
	var oek []byte
	for _, kd := range sp.KeyDeliveries {
		if bytes.Equal(kd.RecipientPubkey, ownX25519Pub) {
			plain, ok := crypto.OpenAnonymous(kd.Sealed, ownX25519Pub, ownX25519Priv)
			if !ok {
				return false, errors.New("member.change: cannot open our key_delivery")
			}
			if len(plain) != 32 {
				return false, errors.New("member.change: OEK length != 32")
			}
			oek = plain
			break
		}
	}
	if oek == nil {
		// We are not a recipient. Either we are not a member at this point
		// (server bug — author would have been rejected) or we just left.
		// Treat as fatal.
		return false, errors.New("member.change: not a recipient")
	}
	// Decrypt enc_projection.
	if len(pl.EncProjection) < 12 {
		return false, errors.New("member.change: bad enc_projection")
	}
	aad, err := projectionAAD(ev)
	if err != nil {
		return false, err
	}
	plain, err := crypto.AEADOpen(oek, pl.EncProjection[:12], pl.EncProjection[12:], aad)
	if err != nil {
		return false, fmt.Errorf("member.change: decrypt projection: %w", err)
	}
	var proj proto.MemberProjection
	if err := proto.Unmarshal(plain, &proj); err != nil {
		return false, fmt.Errorf("member.change: decode projection: %w", err)
	}
	// Projection verification (PROTOCOL.md §4.5 steps 3–4). Skipped on first
	// admit of self (no prior local state to compare against).
	weAreNewMember := bytes.Equal(pl.Member, ownSuperPub) && pl.Op == proto.OpAdd
	if !weAreNewMember {
		projIDs := map[string]*proto.SecretRecord{}
		for _, s := range proj.Secrets {
			projIDs[s.ID] = s.Record
		}
		// Every non-tombstone in our index must be in the projection with
		// byte-identical record bytes.
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
		// Reject IDs that appear in the projection but not in our index
		// (would let an inviter inject extra secrets). Tombstones in the
		// projection (Record=nil) are allowed.
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
	keyCopy := append([]byte(nil), oek...)
	st.OEKs[sp.OEKVersion] = keyCopy
	st.CurrentOEKVer = sp.OEKVersion
	st.MemberSet = want
	st.SecretIndex = make(map[string]ScopeSecret, len(proj.Secrets))
	for _, s := range proj.Secrets {
		st.SecretIndex[s.ID] = ScopeSecret{Record: s.Record}
	}
	crypto.Wipe(oek)
	crypto.Wipe(plain)
	return false, nil
}

// applySecretSet decrypts enc_body under the current OEK and updates the index.
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
		return fmt.Errorf("secret.set: missing OEK v%d", sp.OEKVersion)
	}
	if len(sp.Payload.EncBody) < 12 {
		return errors.New("secret.set: bad enc_body")
	}
	aad, err := bodyAAD(ev)
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
	// Compute event_id for index reference (debug/observability).
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

// projectionAAD = DomainEvent || cbor(SignedPrefix without payload.enc_projection).
// PROTOCOL.md §1.1 mandates a domain string on every AEAD AAD; we use the
// same DomainEvent the signature carries.
func projectionAAD(ev *proto.ScopeEvent) ([]byte, error) {
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

// bodyAAD = DomainEvent || cbor(SignedPrefix without payload.enc_body).
func bodyAAD(ev *proto.ScopeEvent) ([]byte, error) {
	sp := ev.SignedPrefix
	sp.Payload = proto.Payload{}
	body, err := proto.Marshal(sp)
	if err != nil {
		return nil, err
	}
	return append([]byte(proto.DomainEvent), body...), nil
}

// ---- helpers for member sets ----

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

// sameSet compares two sorted sets of pubkeys. Note: postMutationSet contains
// Ed25519 pubs; recipientSet contains X25519 pubs. They are NOT directly
// comparable. The caller (applyMemberChange) maps Ed25519→X25519 before the
// compare.
func sameSet(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	// a is sorted Ed25519 pubs; map each to X25519 then compare.
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
	// Insertion sort — set sizes are small (≤1000 by spec, typically <10).
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && bytes.Compare(s[j-1], s[j]) > 0; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
	return s
}
