//go:build yubikey

package main

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/crypto/yubikey"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// ErrWrongCard signals that the connected YubiKey's slot 9d pubkey
// does not match the pubkey enrolled in the vault. Surfaced as a
// distinct sentinel so the CLI can produce a "you have a different
// YubiKey plugged in" message rather than a generic auth error.
var ErrWrongCard = errors.New("yubikey: connected card has a different slot pubkey than the vault expects (wrong YubiKey plugged in?)")

// newYubikeyResolverFactory returns a factory the agent calls per
// unlock attempt. The factory captures the user-supplied PIN (which
// may be empty for touch-only slots) and produces a vault resolver
// whose OpenSealed callback talks to the connected YubiKey.
//
// Each Unlock call produces a fresh Card session: yubikey.Open returns
// a handle that we Close as soon as the sealed-box open returns. PCSC
// allows only one session per card at a time, so leaking a handle
// would prevent the next unlock.
//
// The OpenSealed callback verifies that the connected card's slot
// pubkey matches the expectedPub recorded in the vault wrap before
// doing the ECDH. Without this, a different YubiKey plugged in would
// drive an ECDH whose only effect is an AEAD failure further down,
// producing a confusing error instead of a clear "wrong card" signal.
func newYubikeyResolverFactory() func(pin []byte) vault.MethodResolver {
	return func(pin []byte) vault.MethodResolver {
		return vault.YubikeyResolver{
			OpenSealed: func(expectedPub, sealed []byte) ([]byte, error) {
				card, err := yubikey.Open(yubikey.OpenOptions{
					Slot: yubikey.SlotKeyManagement,
					PIN:  pin,
				})
				if err != nil {
					return nil, fmt.Errorf("yubikey unlock: open card: %w", err)
				}
				defer card.Close()

				// Verify card identity before any ECDH. Constant-time
				// compare keeps timing oracles out of the wrong-card
				// signal, even though the pubkey itself is not secret.
				gotPub, err := card.PublicX25519()
				if err != nil {
					return nil, fmt.Errorf("yubikey unlock: read slot pub: %w", err)
				}
				if subtle.ConstantTimeCompare(gotPub, expectedPub) != 1 {
					return nil, ErrWrongCard
				}

				k, err := yubikey.OpenSealedBox(card, sealed)
				if err != nil {
					return nil, fmt.Errorf("yubikey unlock: open sealed-box: %w", err)
				}
				return k, nil
			},
		}
	}
}
