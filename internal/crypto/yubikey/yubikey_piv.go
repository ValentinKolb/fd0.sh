//go:build yubikey

package yubikey

import (
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

// PIV-tagged scaffold. Compiles against go-piv + libpcsclite but the
// implementation is intentionally INCOMPLETE — finishing it requires
// hands-on testing against real hardware (firmware quirks, slot policies,
// PIN/touch UX). Tracked items:
//
//   - Slot pub-key retrieval via Attest() (Metadata returns settings only).
//   - PrivateKey ECDH path: must pass the slot's public key.
//   - sealed-box completion: ECDH shared secret → libsodium HKDF (BLAKE2b
//     over eph_pub||recipient_pub) → XSalsa20-Poly1305 open.
//
// The user-facing scaffold returns a clear pending-error so we don't ship a
// half-working YubiKey path. List/Open succeed enough to surface "card
// detected" diagnostics.

// List returns the smartcard names currently visible to PCSC.
func List() ([]string, error) { return piv.Cards() }

// Open finds the first YubiKey on the bus and returns a wrapper. Caller
// must Close. PIN verification is deferred to per-operation calls in the
// full implementation; for now Open is mostly a stub.
func Open(opts OpenOptions) (PivKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("yubikey: no smartcards detected")
	}
	yk, err := piv.Open(cards[0])
	if err != nil {
		return nil, fmt.Errorf("yubikey: open %q: %w", cards[0], err)
	}
	if opts.PIN != "" {
		if err := yk.VerifyPIN(opts.PIN); err != nil {
			yk.Close()
			return nil, fmt.Errorf("yubikey: verify PIN: %w", err)
		}
	}
	return &pivWrapper{yk: yk}, nil
}

// Initialize is the on-card key-generation entry point. NOT YET IMPLEMENTED.
// The real flow:
//  1. Verify management key (default or user-supplied).
//  2. yk.GenerateKey(slot, piv.Key{Algorithm: AlgorithmX25519, ...}) —
//     returns the new public key.
//  3. Marshal pub as 32-byte X25519 raw form.
func Initialize(slot SlotID, pin string, touch TouchPolicy, pinPolicy PinPolicy) ([]byte, error) {
	return nil, errors.New("yubikey: Initialize pending hardware-day integration")
}

// ---- pivWrapper ----

type pivWrapper struct {
	yk *piv.YubiKey
}

func (p *pivWrapper) PublicX25519() ([]byte, error) {
	return nil, errors.New("yubikey: PublicX25519 pending hardware-day integration")
}

// OpenSealedBox opens a libsodium sealed-box on-card.
//
// NOTE: the current return value is a placeholder. Real impl will:
//   1. parse sealed[:32] as ephemeral X25519 pub.
//   2. ECDH against the slot's private key (yk.PrivateKey + ECDH).
//   3. derive nonce + symmetric key per libsodium's BLAKE2b construction.
//   4. open the XSalsa20-Poly1305 ciphertext.
func (p *pivWrapper) OpenSealedBox(sealed []byte) ([]byte, error) {
	return nil, errors.New("yubikey: OpenSealedBox pending hardware-day integration")
}

func (p *pivWrapper) Close() error { return p.yk.Close() }
