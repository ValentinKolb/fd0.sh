package chain

import (
	"bytes"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestScopeAADBindsContextAndSeparatesPayloadKinds(t *testing.T) {
	newEvent := func() *proto.ScopeEvent {
		scope := "s_abcdefghijklmnopqrstuvwxyy"
		return &proto.ScopeEvent{SignedPrefix: proto.SignedPrefix{
			Kind:       proto.KindMemberChange,
			Scope:      &scope,
			PrevHash:   bytes.Repeat([]byte{0x11}, 32),
			Author:     bytes.Repeat([]byte{0x22}, 32),
			Seq:        7,
			OEKVersion: 3,
			KeyDeliveries: []proto.KeyDelivery{{
				RecipientPubkey: bytes.Repeat([]byte{0x33}, 32),
				Sealed:          bytes.Repeat([]byte{0x44}, 80),
			}},
			Payload: proto.Payload{
				Op:            proto.OpAdd,
				Member:        bytes.Repeat([]byte{0x55}, 32),
				EncProjection: []byte("projection-ciphertext"),
			},
		}}
	}

	baseProjection, err := ProjectionAAD(newEvent())
	if err != nil {
		t.Fatal(err)
	}
	baseBody, err := BodyAAD(newEvent())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(baseProjection, baseBody) {
		t.Fatal("projection and secret-body AAD contexts collided")
	}

	mutations := []struct {
		name   string
		mutate func(*proto.ScopeEvent)
	}{
		{"kind", func(ev *proto.ScopeEvent) { ev.SignedPrefix.Kind = proto.KindSecretSet }},
		{"scope", func(ev *proto.ScopeEvent) {
			scope := "s_zyxwvutsrqponmlkjihgfedcbb"
			ev.SignedPrefix.Scope = &scope
		}},
		{"prev hash", func(ev *proto.ScopeEvent) { ev.SignedPrefix.PrevHash[0] ^= 1 }},
		{"author", func(ev *proto.ScopeEvent) { ev.SignedPrefix.Author[0] ^= 1 }},
		{"sequence", func(ev *proto.ScopeEvent) { ev.SignedPrefix.Seq++ }},
		{"OEK version", func(ev *proto.ScopeEvent) { ev.SignedPrefix.OEKVersion++ }},
		{"key-delivery recipient", func(ev *proto.ScopeEvent) {
			ev.SignedPrefix.KeyDeliveries[0].RecipientPubkey[0] ^= 1
		}},
		{"key-delivery ciphertext", func(ev *proto.ScopeEvent) {
			ev.SignedPrefix.KeyDeliveries[0].Sealed[0] ^= 1
		}},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			ev := newEvent()
			tt.mutate(ev)
			projectionAAD, err := ProjectionAAD(ev)
			if err != nil {
				t.Fatal(err)
			}
			bodyAAD, err := BodyAAD(ev)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(projectionAAD, baseProjection) {
				t.Errorf("projection AAD did not bind %s", tt.name)
			}
			if bytes.Equal(bodyAAD, baseBody) {
				t.Errorf("body AAD did not bind %s", tt.name)
			}
		})
	}

	projectionCiphertextChanged := newEvent()
	projectionCiphertextChanged.SignedPrefix.Payload.EncProjection = []byte("different")
	gotProjection, err := ProjectionAAD(projectionCiphertextChanged)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotProjection, baseProjection) {
		t.Fatal("projection AAD included its own ciphertext")
	}

	for _, tt := range []struct {
		name   string
		mutate func(*proto.ScopeEvent)
	}{
		{"operation", func(ev *proto.ScopeEvent) { ev.SignedPrefix.Payload.Op = proto.OpRemove }},
		{"member", func(ev *proto.ScopeEvent) { ev.SignedPrefix.Payload.Member[0] ^= 1 }},
	} {
		ev := newEvent()
		tt.mutate(ev)
		gotProjection, err = ProjectionAAD(ev)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(gotProjection, baseProjection) {
			t.Fatalf("projection AAD did not bind member-change %s", tt.name)
		}
	}

	key := bytes.Repeat([]byte{0x66}, 32)
	nonce := bytes.Repeat([]byte{0x77}, 12)
	ciphertext, err := crypto.AEADSeal(key, nonce, []byte("payload"), baseBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := crypto.AEADOpen(key, nonce, ciphertext, baseProjection); err == nil {
		t.Fatal("secret-body ciphertext opened in projection context")
	}
}
