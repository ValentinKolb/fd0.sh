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
// PIN/touch UX). Hardware-day TODOs:
//
//   - Slot pub-key retrieval via Attest() (Metadata returns settings only).
//   - SharedSecret: ECDH against the slot's PrivateKey.
//
// All other steps in the sealed-box open path (ParseSealed +
// OpenSealedFromShared in package crypto) are pure software and already
// unit-tested. The user-facing scaffold returns a clear pending-error so
// we don't ship a half-working YubiKey path; List/Open succeed enough to
// surface "card detected" diagnostics.

// List returns the smartcard names currently visible to PCSC.
func List() ([]string, error) { return piv.Cards() }

// Open finds the first YubiKey on the bus and returns a wrapper. Caller
// must Close. PIN verification is deferred to per-operation calls in the
// full implementation; for now Open is mostly a stub.
func Open(opts OpenOptions) (Card, error) {
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
	slot := opts.Slot
	if slot == 0 {
		slot = SlotKeyManagement
	}
	return &pivWrapper{yk: yk, slot: slot, pin: opts.PIN}, nil
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

// Enroll generates the slot key, applies PIN and touch policies, and
// returns the slot's X25519 public key for upstream use (sealed-box of
// K_unlock + storage in AuthMethod.PublicParams).
//
// Provisional: pending hardware-day integration of the PIV X25519 path
// (yk.GenerateKey, Metadata, slot policies). For now the call surfaces
// a clear error so the CLI can route the user back to the passphrase
// flow rather than half-enrolling and locking them out.
func Enroll(opts EnrollOptions) (*EnrollResult, error) {
	return nil, errors.New("yubikey: Enroll pending hardware-day integration (slot generation, PIN/touch policy plumbing). Use --tags=yubikey only on a build that has completed the hardware-day path; see TODO.md.")
}

// ---- pivWrapper ----

// pivWrapper holds everything SharedSecret needs to talk to the slot:
//   - yk:   the open card handle (Close releases it).
//   - slot: which PIV slot was selected at Open time. Stored normalized
//           (SlotKeyManagement default) so SharedSecret has no zero-
//           value branch.
//   - pin:  the verified PIN, kept so per-operation re-verification
//           works under PinAlways (re-prompt the user for some
//           policies; carry the PIN for others). Hardware-day will
//           decide which.
type pivWrapper struct {
	yk   *piv.YubiKey
	slot SlotID
	pin  string
}

// PublicX25519 returns the slot's X25519 public key.
//
// Hardware-day TODO: replace with `yk.Attest(slot)` (firmware ≥ 5.7) or
// equivalent metadata read; marshal the result as raw 32-byte X25519
// pub. The pubkey is then cached in EnrollResult so subsequent
// SharedSecret calls do not re-hit the card.
func (p *pivWrapper) PublicX25519() ([]byte, error) {
	return nil, errors.New("yubikey: PublicX25519 pending hardware-day integration")
}

// SharedSecret runs X25519 ECDH between the slot's private key and the
// supplied ephemeral pubkey, returning the 32-byte shared secret. This
// is the ONLY step in the sealed-box open path that touches hardware.
//
// Hardware-day TODO: get a *piv.PrivateKey via `yk.PrivateKey(slot,
// pubKey, piv.KeyAuth{...})`, type-assert to the ECDH-capable interface,
// and call its X25519 ECDH method against ephPub. Validate that the
// result is exactly 32 bytes and not all-zero (RFC 7748 §6.1 small-
// subgroup check).
func (p *pivWrapper) SharedSecret(ephPub []byte) ([]byte, error) {
	if len(ephPub) != 32 {
		return nil, errors.New("yubikey: SharedSecret: ephPub must be 32 bytes")
	}
	return nil, errors.New("yubikey: SharedSecret pending hardware-day integration: yk.PrivateKey(slot).ECDH(ephPub)")
}

func (p *pivWrapper) Close() error { return p.yk.Close() }
