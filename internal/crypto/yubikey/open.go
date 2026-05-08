package yubikey

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
)

// OpenSealedBox opens a libsodium crypto_box_seal blob using a Card.
//
// The hardware-vs-software split:
//
//	ParseSealed                                     pure software (crypto.ParseSealed)
//	card.SharedSecret(ephPub)                       hardware (or MockCard for tests)
//	crypto.OpenSealedFromSharedErr(eph, pub, ct, s) pure software
//
// Production callers (agent unlock path, future YubiKey resolver) hit
// this function through any Card implementation; the only thing that
// changes between MockCard and pivWrapper is who runs the ECDH.
//
// On success returns the plaintext. On any failure returns a non-nil
// error from the underlying layer (parse / pubkey fetch / ECDH /
// AEAD); callers should NOT log the input ciphertext on error.
func OpenSealedBox(card Card, sealed []byte) ([]byte, error) {
	if card == nil || isTypedNil(card) {
		return nil, errors.New("yubikey: OpenSealedBox: card is nil")
	}
	eph, ct, err := crypto.ParseSealed(sealed)
	if err != nil {
		return nil, fmt.Errorf("yubikey: OpenSealedBox: parse: %w", err)
	}
	pub, err := card.PublicX25519()
	if err != nil {
		return nil, fmt.Errorf("yubikey: OpenSealedBox: card pubkey: %w", err)
	}
	if len(pub) != 32 {
		return nil, fmt.Errorf("yubikey: OpenSealedBox: card pubkey is %d bytes, want 32", len(pub))
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	shared, err := card.SharedSecret(eph[:])
	if err != nil {
		return nil, fmt.Errorf("yubikey: OpenSealedBox: shared secret: %w", err)
	}
	// Wipe our copy of the shared secret on every return path. The
	// open path takes its own copy internally; once that's done with
	// it, this slice has no more callers.
	defer crypto.Wipe(shared)
	plain, err := crypto.OpenSealedFromSharedErr(eph, pubArr, ct, shared)
	if err != nil {
		return nil, fmt.Errorf("yubikey: OpenSealedBox: open: %w", err)
	}
	return plain, nil
}

// isTypedNil catches the classic Go gotcha: a nil pointer wrapped in
// a non-nil interface. `var c Card = (*pivWrapper)(nil)` makes
// `card == nil` false but every method call panics. We detect that
// here so OpenSealedBox returns a clean error instead of a SIGSEGV.
func isTypedNil(c Card) bool {
	v := reflect.ValueOf(c)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func, reflect.Interface:
		return v.IsNil()
	}
	return false
}
