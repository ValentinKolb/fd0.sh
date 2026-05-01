package chain

import (
	"crypto/ed25519"
	"errors"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// BuildUserAuthSet constructs a signed UserEvent (kind=auth.set).
//
//	prevHash == nil  → genesis (seq=0)
//	otherwise        → seq=prevSeq+1, prev_hash=prevHash
func BuildUserAuthSet(superPriv ed25519.PrivateKey, userSuperPub []byte, prevSeq uint64, prevHash []byte, active []proto.AuthMethod) (*proto.UserEvent, error) {
	ev := &proto.UserEvent{
		Kind:         proto.KindAuthSet,
		UserSuperPub: append([]byte(nil), userSuperPub...),
		Payload:      proto.AuthSetPayload{Active: active},
	}
	if prevHash == nil {
		ev.Seq = 0
		ev.PrevHash = nil
	} else {
		ev.Seq = prevSeq + 1
		ev.PrevHash = append([]byte(nil), prevHash...)
	}
	si, err := ev.SignedInput()
	if err != nil {
		return nil, err
	}
	ev.Signature = crypto.Sign(superPriv, si)
	return ev, nil
}

// BuildScopeGenesis constructs the genesis member.change of a new scope.
// Returns the event, the new OEK (32 bytes) and the derived scope_id.
//
// Per PROTOCOL.md §4.1 the genesis Scope field is nil, prev_hash is nil, and
// the sole key_delivery is to the author's own X25519 pub.
func BuildScopeGenesis(superPriv ed25519.PrivateKey, superPub []byte) (*proto.ScopeEvent, []byte, string, error) {
	oek, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, nil, "", err
	}
	ownX25519Pub, err := crypto.EdPubToX25519(superPub)
	if err != nil {
		return nil, nil, "", err
	}
	sealed, err := crypto.SealAnonymous(oek, ownX25519Pub)
	if err != nil {
		return nil, nil, "", err
	}
	prefix := proto.SignedPrefix{
		Kind:       proto.KindMemberChange,
		OEKVersion: 1,
		Author:     append([]byte(nil), superPub...),
		KeyDeliveries: []proto.KeyDelivery{
			{RecipientPubkey: ownX25519Pub, Sealed: sealed},
		},
		Payload: proto.Payload{Op: proto.OpAdd, Member: append([]byte(nil), superPub...)},
	}
	_, encProj, err := encryptProjection(oek, &proto.MemberProjection{}, &prefix)
	if err != nil {
		return nil, nil, "", err
	}
	prefix.Payload.EncProjection = encProj
	ev := &proto.ScopeEvent{SignedPrefix: prefix}
	if err := signScope(ev, superPriv); err != nil {
		return nil, nil, "", err
	}
	preb, err := ev.PrevHashInput()
	if err != nil {
		return nil, nil, "", err
	}
	scopeID := proto.ScopeID(proto.EventID(preb))
	return ev, oek, scopeID, nil
}

// BuildSecretSet constructs a secret.set event.
func BuildSecretSet(superPriv ed25519.PrivateKey, superPub []byte, scopeID string, prevSeq uint64, prevHash []byte, oek []byte, oekVersion uint64, body *proto.SecretBody) (*proto.ScopeEvent, error) {
	if len(oek) != 32 {
		return nil, errors.New("BuildSecretSet: bad OEK")
	}
	plain, err := proto.Marshal(body)
	if err != nil {
		return nil, err
	}
	nonce, err := crypto.Nonce12()
	if err != nil {
		return nil, err
	}
	ev := &proto.ScopeEvent{
		SignedPrefix: proto.SignedPrefix{
			Kind:       proto.KindSecretSet,
			Scope:      proto.ScopePtr(scopeID),
			PrevHash:   append([]byte(nil), prevHash...),
			Author:     append([]byte(nil), superPub...),
			Seq:        prevSeq + 1,
			OEKVersion: oekVersion,
		},
	}
	aad, err := BodyAAD(ev)
	if err != nil {
		return nil, err
	}
	ct, err := crypto.AEADSeal(oek, nonce, plain, aad)
	if err != nil {
		return nil, err
	}
	ev.SignedPrefix.Payload.EncBody = append(nonce, ct...)
	if err := signScope(ev, superPriv); err != nil {
		return nil, err
	}
	return ev, nil
}

// BuildMemberChange constructs an add/remove member.change. priorMembers is
// the current member set (Ed25519 pubs); priorOEK is the OEK before this
// rotation; projection contains every active SecretInProjection at this seq.
func BuildMemberChange(
	superPriv ed25519.PrivateKey, superPub []byte,
	scopeID string, prevSeq uint64, prevHash []byte,
	priorOEKVersion uint64,
	op string, target []byte,
	priorMembers [][]byte,
	projection *proto.MemberProjection,
) (*proto.ScopeEvent, []byte /* new OEK */, error) {
	newOEK, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, nil, err
	}
	// Build post-mutation member set.
	post := postMutationSet(priorMembers, target, op)
	// key_deliveries: one sealed-box per post member's X25519 pub.
	kds := make([]proto.KeyDelivery, 0, len(post))
	for _, m := range post {
		x, err := crypto.EdPubToX25519(m)
		if err != nil {
			return nil, nil, err
		}
		sealed, err := crypto.SealAnonymous(newOEK, x)
		if err != nil {
			return nil, nil, err
		}
		kds = append(kds, proto.KeyDelivery{RecipientPubkey: x, Sealed: sealed})
	}
	ev := &proto.ScopeEvent{
		SignedPrefix: proto.SignedPrefix{
			Kind:          proto.KindMemberChange,
			Scope:         proto.ScopePtr(scopeID),
			PrevHash:      append([]byte(nil), prevHash...),
			Author:        append([]byte(nil), superPub...),
			Seq:           prevSeq + 1,
			OEKVersion:    priorOEKVersion + 1,
			KeyDeliveries: kds,
			Payload: proto.Payload{
				Op:     op,
				Member: append([]byte(nil), target...),
			},
		},
	}
	// Encrypt projection under the new OEK with AAD = signed prefix sans EncProjection.
	if len(post) > 0 || (op == proto.OpRemove && len(post) == 0) {
		// For remove-self of last member, post is empty; skip projection.
		if !(op == proto.OpRemove && len(post) == 0) {
			_, encProj, err := encryptProjection(newOEK, projection, &ev.SignedPrefix)
			if err != nil {
				return nil, nil, err
			}
			ev.SignedPrefix.Payload.EncProjection = encProj
		}
	}
	if err := signScope(ev, superPriv); err != nil {
		return nil, nil, err
	}
	return ev, newOEK, nil
}

// signScope sets ev.Signature using superPriv.
func signScope(ev *proto.ScopeEvent, superPriv ed25519.PrivateKey) error {
	si, err := ev.SignedInput()
	if err != nil {
		return err
	}
	ev.Signature = proto.Signature{
		SignerPubkey: append([]byte(nil), ev.SignedPrefix.Author...),
		Signature:    crypto.Sign(superPriv, si),
	}
	return nil
}

// encryptProjection encrypts proj under oek with AAD =
// DomainEvent || cbor(prefix without payload.enc_projection).
func encryptProjection(oek []byte, proj *proto.MemberProjection, prefix *proto.SignedPrefix) ([]byte, []byte, error) {
	plain, err := proto.Marshal(proj)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := crypto.Nonce12()
	if err != nil {
		return nil, nil, err
	}
	aadPrefix := *prefix
	aadPrefix.Payload = proto.Payload{Op: prefix.Payload.Op, Member: prefix.Payload.Member}
	body, err := proto.Marshal(aadPrefix)
	if err != nil {
		return nil, nil, err
	}
	aad := append([]byte(proto.DomainEvent), body...)
	ct, err := crypto.AEADSeal(oek, nonce, plain, aad)
	if err != nil {
		return nil, nil, err
	}
	return aad, append(nonce, ct...), nil
}
