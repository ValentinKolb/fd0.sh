package cli

import (
	"errors"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// buildScopeGenesisAgent is the agent-routed equivalent of
// chain.BuildScopeGenesis. The signature is requested from the agent (which
// holds super_priv); everything else is identical.
func buildScopeGenesisAgent(ag *agent.Client, superPub []byte) (*proto.ScopeEvent, []byte, string, error) {
	oek, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, nil, "", err
	}
	ownX, err := crypto.EdPubToX25519(superPub)
	if err != nil {
		return nil, nil, "", err
	}
	sealed, err := crypto.SealAnonymous(oek, ownX)
	if err != nil {
		return nil, nil, "", err
	}
	prefix := proto.SignedPrefix{
		Kind:       proto.KindMemberChange,
		OEKVersion: 1,
		Author:     append([]byte(nil), superPub...),
		KeyDeliveries: []proto.KeyDelivery{
			{RecipientPubkey: ownX, Sealed: sealed},
		},
		Payload: proto.Payload{Op: proto.OpAdd, Member: append([]byte(nil), superPub...)},
	}
	encProj, err := encryptProjectionAgent(oek, &proto.MemberProjection{}, &prefix)
	if err != nil {
		return nil, nil, "", err
	}
	prefix.Payload.EncProjection = encProj
	ev := &proto.ScopeEvent{SignedPrefix: prefix}
	if err := signScopeAgent(ev, ag); err != nil {
		return nil, nil, "", err
	}
	preb, err := ev.PrevHashInput()
	if err != nil {
		return nil, nil, "", err
	}
	return ev, oek, proto.ScopeID(proto.EventID(preb)), nil
}

// buildSecretSetAgent constructs and signs a secret.set event using the agent
// for signing.
func buildSecretSetAgent(ag *agent.Client, superPub []byte, scopeID string, prevSeq uint64, prevHash []byte, oek []byte, oekVersion uint64, body *proto.SecretBody) (*proto.ScopeEvent, error) {
	if len(oek) != 32 {
		return nil, errors.New("buildSecretSetAgent: bad OEK")
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
	aad, err := chain.BodyAAD(ev)
	if err != nil {
		return nil, err
	}
	ct, err := crypto.AEADSeal(oek, nonce, plain, aad)
	if err != nil {
		return nil, err
	}
	ev.SignedPrefix.Payload.EncBody = append(nonce, ct...)
	if err := signScopeAgent(ev, ag); err != nil {
		return nil, err
	}
	return ev, nil
}

// buildUserAuthSetAgent constructs and signs an auth.set event with active
// as the new active set. Genesis (prevHash nil) for first-time setup;
// successor (prevHash non-nil) for credential rotation.
func buildUserAuthSetAgent(ag *agent.Client, userSuperPub []byte, prevSeq uint64, prevHash []byte, active []proto.AuthMethod) (*proto.UserEvent, error) {
	ev := &proto.UserEvent{
		Kind:         proto.KindAuthSet,
		UserSuperPub: append([]byte(nil), userSuperPub...),
		Payload:      proto.AuthSetPayload{Active: active},
	}
	if prevHash == nil {
		ev.Seq = 0
	} else {
		ev.Seq = prevSeq + 1
		ev.PrevHash = append([]byte(nil), prevHash...)
	}
	si, err := ev.SignedInput()
	if err != nil {
		return nil, err
	}
	sig, err := ag.Sign(si)
	if err != nil {
		return nil, err
	}
	ev.Signature = sig
	return ev, nil
}

// signScopeAgent fills ev.Signature using the agent.
func signScopeAgent(ev *proto.ScopeEvent, ag *agent.Client) error {
	si, err := ev.SignedInput()
	if err != nil {
		return err
	}
	sig, err := ag.Sign(si)
	if err != nil {
		return err
	}
	ev.Signature = proto.Signature{
		SignerPubkey: append([]byte(nil), ev.SignedPrefix.Author...),
		Signature:    sig,
	}
	return nil
}

// buildMemberChangeAgent constructs an add/remove member.change event using
// the agent for signing. Returns the event and the new OEK (32 B).
func buildMemberChangeAgent(
	ag *agent.Client, superPub []byte,
	scopeID string, prevSeq uint64, prevHash []byte,
	priorOEKVersion uint64,
	op string, target []byte,
	priorMembers [][]byte,
	projection *proto.MemberProjection,
) (*proto.ScopeEvent, []byte, error) {
	newOEK, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, nil, err
	}
	post := chain.PostMutationSet(priorMembers, target, op)
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
	if !(op == proto.OpRemove && len(post) == 0) {
		encProj, err := encryptProjectionAgent(newOEK, projection, &ev.SignedPrefix)
		if err != nil {
			return nil, nil, err
		}
		ev.SignedPrefix.Payload.EncProjection = encProj
	}
	if err := signScopeAgent(ev, ag); err != nil {
		return nil, nil, err
	}
	return ev, newOEK, nil
}

// encryptProjectionAgent mirrors chain.encryptProjection but lives here to
// avoid widening the chain package's API surface.
func encryptProjectionAgent(oek []byte, proj *proto.MemberProjection, prefix *proto.SignedPrefix) ([]byte, error) {
	plain, err := proto.Marshal(proj)
	if err != nil {
		return nil, err
	}
	nonce, err := crypto.Nonce12()
	if err != nil {
		return nil, err
	}
	aadPrefix := *prefix
	aadPrefix.Payload = proto.Payload{Op: prefix.Payload.Op, Member: prefix.Payload.Member}
	body, err := proto.Marshal(aadPrefix)
	if err != nil {
		return nil, err
	}
	aad := append([]byte(proto.DomainEvent), body...)
	ct, err := crypto.AEADSeal(oek, nonce, plain, aad)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}
