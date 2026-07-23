package validate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	fdcrypto "github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestValidateMemberChangeRejectsDeliveryOverflowBeforeRecipientWork(t *testing.T) {
	sp := &proto.SignedPrefix{
		Kind:       proto.KindMemberChange,
		OEKVersion: 2,
		Payload: proto.Payload{
			Op:     proto.OpRemove,
			Member: memberKey(0),
		},
		KeyDeliveries: make([]proto.KeyDelivery, proto.MaxKeyDeliveries+1),
	}
	_, err := validateMemberChange(sp, &ScopeMeta{
		OEKVersionMax: 1,
		Members:       [][]byte{memberKey(0)},
	})
	if err == nil || !strings.Contains(err.Error(), "too many key_deliveries") {
		t.Fatalf("expected delivery limit error, got %v", err)
	}
}

func TestValidateMemberChangeRejectsAddAtMemberLimit(t *testing.T) {
	members := make([][]byte, proto.MaxScopeMembers)
	for i := range members {
		members[i] = memberKey(i)
	}
	sp := &proto.SignedPrefix{
		Kind:       proto.KindMemberChange,
		OEKVersion: 2,
		Payload: proto.Payload{
			Op:     proto.OpAdd,
			Member: memberKey(proto.MaxScopeMembers),
		},
	}
	_, err := validateMemberChange(sp, &ScopeMeta{
		OEKVersionMax: 1,
		Members:       members,
	})
	if err == nil || !strings.Contains(err.Error(), "scope member limit reached") {
		t.Fatalf("expected member limit error, got %v", err)
	}
}

func TestValidateMemberChangeAllowsLegacyScopeToShrink(t *testing.T) {
	members := validMemberKeys(t, proto.MaxScopeMembers+1)
	deliveries := make([]proto.KeyDelivery, 0, proto.MaxScopeMembers)
	for _, member := range members[:proto.MaxScopeMembers] {
		recipient, err := fdcrypto.EdPubToX25519(member)
		if err != nil {
			t.Fatal(err)
		}
		deliveries = append(deliveries, proto.KeyDelivery{RecipientPubkey: recipient})
	}
	sp := &proto.SignedPrefix{
		Kind:          proto.KindMemberChange,
		OEKVersion:    2,
		KeyDeliveries: deliveries,
		Payload: proto.Payload{
			Op:     proto.OpRemove,
			Member: members[proto.MaxScopeMembers],
		},
	}
	got, err := validateMemberChange(sp, &ScopeMeta{
		OEKVersionMax: 1,
		Members:       members,
	})
	if err != nil {
		t.Fatalf("legacy removal rejected: %v", err)
	}
	if len(got.Members) != proto.MaxScopeMembers {
		t.Fatalf("legacy removal left %d members, want %d", len(got.Members), proto.MaxScopeMembers)
	}
}

func memberKey(i int) []byte {
	sum := sha256.Sum256([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
	return sum[:]
}

func validMemberKeys(t *testing.T, count int) [][]byte {
	t.Helper()
	out := make([][]byte, count)
	for i := range out {
		seed := sha256.Sum256([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		priv := ed25519.NewKeyFromSeed(seed[:])
		out[i] = append([]byte(nil), priv.Public().(ed25519.PublicKey)...)
	}
	return out
}
