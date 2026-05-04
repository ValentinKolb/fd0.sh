package chain

import (
	"crypto/ed25519"
	"errors"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Signer signs a payload (the SignedInput of an event) and returns the raw
// 64-byte Ed25519 signature. The seam where signing is injected — pairs
// with chain.Opener for sealed-box decryption.
//
// Implementations:
//   - chain.LocalSigner: in-process, uses raw super_priv (offline tools,
//     init / recovery before the agent has the key, tests).
//   - cli.AgentSigner: forwards Sign over the agent IPC, so super_priv
//     stays mlocked inside fd0-agent and never crosses the fd0 process
//     for normal operations.
//
// Two real adapters: the seam earns its keep.
type Signer interface {
	Sign(payload []byte) ([]byte, error)
}

// LocalSigner is the in-process Signer. Holds an Ed25519 private key in
// plain memory; appropriate for the brief windows around init and
// recovery import where super_priv is decrypted before the agent
// receives it, and for unit tests.
type LocalSigner struct{ Priv ed25519.PrivateKey }

// Sign implements Signer.
func (s LocalSigner) Sign(payload []byte) ([]byte, error) {
	return crypto.Sign(s.Priv, payload), nil
}

// BuildUserAuthSet constructs a signed UserEvent (kind=auth.set).
//
//	prevHash == nil  → genesis (seq=0)
//	otherwise        → seq=prevSeq+1, prev_hash=prevHash
func BuildUserAuthSet(signer Signer, userSuperPub []byte, prevSeq uint64, prevHash []byte, active []proto.AuthMethod) (*proto.UserEvent, error) {
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
	sig, err := signer.Sign(si)
	if err != nil {
		return nil, err
	}
	ev.Signature = sig
	return ev, nil
}

// BuildScopeGenesis constructs the genesis member.change of a new scope.
// Returns the event, the new OEK (32 bytes) and the derived scope_id
// (typed proto.ScopeID — by construction it satisfies the canonical
// shape, callers receive a value they need not re-validate).
//
// Per PROTOCOL.md §4.1 the genesis Scope field is nil, prev_hash is nil, and
// the sole key_delivery is to the author's own X25519 pub.
func BuildScopeGenesis(signer Signer, superPub []byte) (*proto.ScopeEvent, []byte, proto.ScopeID, error) {
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
	encProj, err := encryptProjection(oek, &proto.MemberProjection{}, &prefix)
	if err != nil {
		return nil, nil, "", err
	}
	prefix.Payload.EncProjection = encProj
	ev := &proto.ScopeEvent{SignedPrefix: prefix}
	if err := signScope(ev, signer); err != nil {
		return nil, nil, "", err
	}
	preb, err := ev.PrevHashInput()
	if err != nil {
		return nil, nil, "", err
	}
	scopeID := proto.DeriveScopeID(proto.EventID(preb))
	return ev, oek, scopeID, nil
}

// BuildSecretSet constructs a secret.set event. scopeID is the
// validated typed identifier — symmetric with BuildScopeGenesis's
// return type so that tests and CLI callers chain the value through
// without round-tripping to a raw string. The wire form (signed
// prefix's Scope field) remains a *string for CBOR compatibility
// (PROTOCOL.md §1.3 — encoded as a text string).
func BuildSecretSet(signer Signer, superPub []byte, scopeID proto.ScopeID, prevSeq uint64, prevHash []byte, oek []byte, oekVersion uint64, body *proto.SecretBody) (*proto.ScopeEvent, error) {
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
	if err := signScope(ev, signer); err != nil {
		return nil, err
	}
	return ev, nil
}

// BuildMemberChange constructs an add/remove member.change. priorMembers is
// the current member set (Ed25519 pubs); priorOEKVersion is the OEK era
// being rotated past; projection is every active SecretInProjection at
// this seq (encrypted under the new OEK). Returns the signed event and the
// new OEK (32 B) so the caller can install it in the local vault.
func BuildMemberChange(
	signer Signer, superPub []byte,
	scopeID proto.ScopeID, prevSeq uint64, prevHash []byte,
	priorOEKVersion uint64,
	op string, target []byte,
	priorMembers [][]byte,
	projection *proto.MemberProjection,
) (*proto.ScopeEvent, []byte /* new OEK */, error) {
	newOEK, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, nil, err
	}
	post := postMutationSet(priorMembers, target, op)
	// key_deliveries: one sealed-box per post-mutation member's X25519 pub.
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
	// For remove-self of last member, post is empty → no projection to
	// encrypt (no recipient anyway).
	if op != proto.OpRemove || len(post) != 0 {
		encProj, err := encryptProjection(newOEK, projection, &ev.SignedPrefix)
		if err != nil {
			return nil, nil, err
		}
		ev.SignedPrefix.Payload.EncProjection = encProj
	}
	if err := signScope(ev, signer); err != nil {
		return nil, nil, err
	}
	return ev, newOEK, nil
}

// signScope fills ev.Signature via signer. Wraps Signer.Sign in the
// proto.Signature struct (signer pubkey alongside the raw signature
// so verifiers can match).
func signScope(ev *proto.ScopeEvent, signer Signer) error {
	si, err := ev.SignedInput()
	if err != nil {
		return err
	}
	sig, err := signer.Sign(si)
	if err != nil {
		return err
	}
	ev.Signature = proto.Signature{
		SignerPubkey: append([]byte(nil), ev.SignedPrefix.Author...),
		Signature:    sig,
	}
	return nil
}

// encryptProjection encrypts proj under oek with AAD =
// DomainEvent || cbor(prefix without payload.enc_projection). Returns
// the nonce-prefixed ciphertext ready to land in payload.EncProjection.
func encryptProjection(oek []byte, proj *proto.MemberProjection, prefix *proto.SignedPrefix) ([]byte, error) {
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
