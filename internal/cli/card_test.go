package cli

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestInspectIdentityCardReturnsVerifiedMetadata(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Wipe()
	now := time.Now().Truncate(time.Second)
	card := &proto.IdentityCard{
		Version:   1,
		ShortID:   "alice123",
		SuperPub:  pub.Bytes(),
		IssuedAt:  uint64(now.Unix()),
		ExpiresAt: uint64(now.Add(time.Hour).Unix()),
	}
	signedInput, err := card.SignedInput()
	if err != nil {
		t.Fatal(err)
	}
	card.Signature, err = crypto.Sign(priv, signedInput)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	url := cardURLPrefix + base64.RawURLEncoding.EncodeToString(encoded)

	info, err := InspectIdentityCard(url)
	if err != nil {
		t.Fatal(err)
	}
	if info.URL != url || info.ShortID != card.ShortID || !info.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("info=%+v", info)
	}
	if len(info.SuperPub) != 32 || len(strings.Fields(info.SafetyNumber)) != 12 {
		t.Fatalf("invalid card metadata: pub=%d safety=%q", len(info.SuperPub), info.SafetyNumber)
	}
}

func TestInspectIdentityCardRejectsExpiredCard(t *testing.T) {
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Wipe()
	now := time.Now()
	card := &proto.IdentityCard{
		Version:   1,
		ShortID:   "expired1",
		SuperPub:  pub.Bytes(),
		IssuedAt:  uint64(now.Add(-2 * time.Hour).Unix()),
		ExpiresAt: uint64(now.Add(-time.Hour).Unix()),
	}
	signedInput, err := card.SignedInput()
	if err != nil {
		t.Fatal(err)
	}
	card.Signature, err = crypto.Sign(priv, signedInput)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(card)
	if err != nil {
		t.Fatal(err)
	}
	_, err = InspectIdentityCard(cardURLPrefix + base64.RawURLEncoding.EncodeToString(encoded))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err=%v", err)
	}
}
