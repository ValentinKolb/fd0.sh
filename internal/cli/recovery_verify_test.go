package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestVerifyRecoveryWithPassphrase(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	nonce := []byte("0123456789ab")
	key, err := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Wipe(key)
	aad := append([]byte(proto.DomainRecoveryKey), pub...)
	encrypted, err := crypto.AEADSeal(key, nonce, priv, aad)
	if err != nil {
		t.Fatal(err)
	}
	data, err := proto.Marshal(&proto.RecoveryFile{
		Magic:        proto.RecoveryMagic,
		Version:      1,
		UserSuperPub: pub,
		Salt:         salt,
		Argon2Params: proto.Argon2Params{
			M: crypto.DefaultArgon2.M,
			T: crypto.DefaultArgon2.T,
			P: crypto.DefaultArgon2.P,
		},
		Nonce:              nonce,
		EncryptedSuperPriv: encrypted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRecoveryWithPassphrase(data, pass, pub); err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0x80
	if err := VerifyRecoveryWithPassphrase(data, pass, pub); err == nil {
		t.Fatal("tampered recovery file verified")
	}
}
