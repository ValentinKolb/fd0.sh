package chain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	fdcrypto "github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestApplyMemberChangeRejectsDeliveryOverflowBeforeRecipientWork(t *testing.T) {
	ev := &proto.ScopeEvent{SignedPrefix: proto.SignedPrefix{
		Kind:       proto.KindMemberChange,
		OEKVersion: 2,
		Payload: proto.Payload{
			Op:     proto.OpRemove,
			Member: replayMemberKey(0),
		},
		KeyDeliveries: make([]proto.KeyDelivery, proto.MaxKeyDeliveries+1),
	}}
	_, err := applyMemberChange(&ScopeState{
		MemberSet:     [][]byte{replayMemberKey(0)},
		CurrentOEKVer: 1,
	}, ev, replayMemberKey(1), nil, false)
	if err == nil || !strings.Contains(err.Error(), "too many key_deliveries") {
		t.Fatalf("expected delivery limit error, got %v", err)
	}
}

func TestApplyMemberChangeRejectsAddAtMemberLimit(t *testing.T) {
	members := make([][]byte, proto.MaxScopeMembers)
	for i := range members {
		members[i] = replayMemberKey(i)
	}
	ev := &proto.ScopeEvent{SignedPrefix: proto.SignedPrefix{
		Kind:       proto.KindMemberChange,
		OEKVersion: 2,
		Payload: proto.Payload{
			Op:     proto.OpAdd,
			Member: replayMemberKey(proto.MaxScopeMembers),
		},
	}}
	_, err := applyMemberChange(&ScopeState{
		MemberSet:     members,
		CurrentOEKVer: 1,
	}, ev, replayMemberKey(0), nil, false)
	if err == nil || !strings.Contains(err.Error(), "scope member limit reached") {
		t.Fatalf("expected member limit error, got %v", err)
	}
}

func TestApplyMemberChangeAllowsLegacyScopeToShrink(t *testing.T) {
	members := replayValidMemberKeys(t, proto.MaxScopeMembers+1)
	deliveries := make([]proto.KeyDelivery, 0, proto.MaxScopeMembers)
	for _, member := range members[:proto.MaxScopeMembers] {
		recipient, err := fdcrypto.EdPubToX25519(member)
		if err != nil {
			t.Fatal(err)
		}
		deliveries = append(deliveries, proto.KeyDelivery{RecipientPubkey: recipient})
	}
	ev := &proto.ScopeEvent{SignedPrefix: proto.SignedPrefix{
		Kind:          proto.KindMemberChange,
		OEKVersion:    2,
		KeyDeliveries: deliveries,
		Payload: proto.Payload{
			Op:     proto.OpRemove,
			Member: members[proto.MaxScopeMembers],
		},
	}}
	state := &ScopeState{MemberSet: members, CurrentOEKVer: 1}
	left, err := applyMemberChange(state, ev, members[0], nil, false)
	if err != nil {
		t.Fatalf("legacy removal rejected: %v", err)
	}
	if left || len(state.MemberSet) != proto.MaxScopeMembers {
		t.Fatalf("legacy removal result left=%v members=%d", left, len(state.MemberSet))
	}
}

func replayMemberKey(i int) []byte {
	sum := sha256.Sum256([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
	return sum[:]
}

func replayValidMemberKeys(t *testing.T, count int) [][]byte {
	t.Helper()
	out := make([][]byte, count)
	for i := range out {
		seed := sha256.Sum256([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		priv := ed25519.NewKeyFromSeed(seed[:])
		out[i] = append([]byte(nil), priv.Public().(ed25519.PublicKey)...)
	}
	return out
}
