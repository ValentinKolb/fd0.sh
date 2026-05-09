//go:build yubikey

package yubikey

import (
	"crypto/ecdh"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

// PIV-tagged YubiKey support. The pure-software half of the open path
// (ParseSealed + OpenSealedFromShared in package crypto) is unit-tested
// independently; this file is the thin shim that talks to a real card.
//
// All hardware operations are wrapped here so call sites elsewhere stay
// hardware-agnostic — they receive a yubikey.Card whose only
// hardware-bound methods are PublicX25519 and SharedSecret.

// List returns the smartcard names currently visible to PCSC.
func List() ([]string, error) { return piv.Cards() }

// Open finds the first YubiKey on the bus, verifies the PIN if one was
// supplied, reads the slot's metadata so PublicX25519 / SharedSecret
// have everything they need without re-hitting the card on every call,
// and returns a Card. The caller MUST Close.
//
// If the slot is empty, Open still succeeds and returns a Card whose
// SharedSecret / PublicX25519 surface a helpful error pointing at
// Enroll. This lets the caller diagnose "card present, slot empty"
// without a separate is-provisioned probe.
func Open(opts OpenOptions) (Card, error) {
	// Validate the slot BEFORE any card I/O so a typo in the caller's
	// SlotID doesn't burn a PIN-retry on the YubiKey when VerifyPIN
	// would have run next.
	slot := opts.Slot
	if slot == 0 {
		slot = SlotKeyManagement
	}
	pivSlot, ok := mapSlot(slot)
	if !ok {
		return nil, fmt.Errorf("yubikey: unsupported slot 0x%02x", byte(slot))
	}

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

	w := &pivWrapper{yk: yk, slot: slot, pivSlot: pivSlot, pin: opts.PIN}

	// Load the slot's metadata so PublicX25519 / SharedSecret answer
	// without an extra round trip per call. Three outcomes:
	//   - success: slot has a key, populate cache.
	//   - piv.ErrNotFound: slot is empty (legitimate; Enroll is next).
	//   - any other error: PCSC fault, parse error, or unknown card
	//     state. We close the handle and return the error rather than
	//     pretending the slot is empty — that would surface as
	//     "run Enroll" later when the real cause is hardware-level.
	info, err := yk.KeyInfo(pivSlot)
	switch {
	case err == nil:
		if info.Algorithm != piv.AlgorithmX25519 {
			yk.Close()
			return nil, fmt.Errorf("yubikey: slot 0x%02x has algorithm %v, want X25519 (firmware ≥ 5.7 required)", byte(slot), info.Algorithm)
		}
		ecdhPub, ok := info.PublicKey.(*ecdh.PublicKey)
		if !ok || ecdhPub.Curve() != ecdh.X25519() {
			yk.Close()
			return nil, fmt.Errorf("yubikey: slot 0x%02x KeyInfo did not return an X25519 public key", byte(slot))
		}
		w.slotPub = ecdhPub
		w.pinPolicy = info.PINPolicy
		w.touchPolicy = info.TouchPolicy
	case errors.Is(err, piv.ErrNotFound):
		// Slot has not been provisioned. Leave slotPub nil; Enroll
		// populates it on the next session.
	default:
		yk.Close()
		return nil, fmt.Errorf("yubikey: slot 0x%02x KeyInfo: %w", byte(slot), err)
	}

	return w, nil
}

// Initialize is intentionally unimplemented; users go through Enroll.
// Keeping the symbol so the package's API surface is stable across
// versions even after the no-op deprecation.
func Initialize(slot SlotID, pin string, touch TouchPolicy, pinPolicy PinPolicy) ([]byte, error) {
	return nil, errors.New("yubikey: Initialize is not implemented; use Enroll instead")
}

// Enroll generates a fresh X25519 key on `opts.Slot`, sets the requested
// PIN/touch policies, and returns the slot's 32-byte X25519 public key
// for upstream use.
//
// Preconditions:
//   - The PIV PIN passed in opts.PIN must already be set on the device
//     (a fresh YubiKey ships with the well-known default "123456" — set
//     a real PIN via `ykman piv access change-pin` before deploying).
//   - The management key in opts.ManagementKey must authenticate the
//     device. An empty value falls back to piv.DefaultManagementKey.
//
// Effect:
//   - Slot is created with Algorithm=X25519, PINPolicy = (Once if PIN
//     non-empty else Never), TouchPolicy = opts.TouchPolicy (default
//     TouchAlways).
//   - Existing keys in that slot are overwritten. The caller is
//     responsible for confirming this is intended.
func Enroll(opts EnrollOptions) (*EnrollResult, error) {
	if opts.PIN != "" {
		if err := ValidatePIN(opts.PIN); err != nil {
			return nil, err
		}
	}
	slot := opts.Slot
	if slot == 0 {
		slot = SlotKeyManagement
	}
	pivSlot, ok := mapSlot(slot)
	if !ok {
		return nil, fmt.Errorf("yubikey: unsupported slot 0x%02x", byte(slot))
	}

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
	defer yk.Close()

	mgmtKey := opts.ManagementKey
	if len(mgmtKey) == 0 {
		mgmtKey = piv.DefaultManagementKey
	}

	pinPolicy := piv.PINPolicyNever
	if opts.PIN != "" {
		pinPolicy = piv.PINPolicyOnce
	}
	touchPolicy := mapTouchPolicy(opts.TouchPolicy)

	pubKey, err := yk.GenerateKey(mgmtKey, pivSlot, piv.Key{
		Algorithm:   piv.AlgorithmX25519,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("yubikey: GenerateKey on slot 0x%02x: %w", byte(slot), err)
	}
	ecdhPub, ok := pubKey.(*ecdh.PublicKey)
	if !ok || ecdhPub.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("yubikey: GenerateKey returned %T, want *ecdh.PublicKey on X25519 curve", pubKey)
	}
	raw := ecdhPub.Bytes()
	if len(raw) != 32 {
		return nil, fmt.Errorf("yubikey: slot pub is %d bytes, want 32", len(raw))
	}
	out := make([]byte, 32)
	copy(out, raw)

	return &EnrollResult{
		Slot:      slot,
		X25519Pub: out,
		HasPIN:    opts.PIN != "",
	}, nil
}

// ---- pivWrapper ----

// pivWrapper is the runtime view of an open YubiKey. It caches the
// slot's pubkey + policies at Open so PublicX25519 and SharedSecret
// don't re-fetch metadata on every call.
//
// Concurrency: pivWrapper is NOT safe for concurrent use. Each Card
// instance is single-owner.
type pivWrapper struct {
	yk          *piv.YubiKey
	slot        SlotID
	pivSlot     piv.Slot
	pin         string
	slotPub     *ecdh.PublicKey // nil iff slot has not been provisioned
	pinPolicy   piv.PINPolicy   // populated alongside slotPub
	touchPolicy piv.TouchPolicy // populated alongside slotPub
}

// PublicX25519 returns a fresh 32-byte copy of the slot's pubkey.
//
// Returns an error if the slot has not been provisioned (Enroll was
// never called, or the slot was wiped after Open).
func (p *pivWrapper) PublicX25519() ([]byte, error) {
	if p.slotPub == nil {
		return nil, fmt.Errorf("yubikey: slot 0x%02x has no key (run Enroll first)", byte(p.slot))
	}
	raw := p.slotPub.Bytes()
	if len(raw) != 32 {
		return nil, fmt.Errorf("yubikey: cached pub is %d bytes, want 32", len(raw))
	}
	out := make([]byte, 32)
	copy(out, raw)
	return out, nil
}

// SharedSecret runs an X25519 ECDH between the slot's private key and
// `ephPub`, returning the 32-byte result. This is the only path that
// actually exercises the YubiKey's secure element during normal
// operation.
//
// The function:
//   - validates ephPub length (32 bytes);
//   - constructs an *ecdh.PublicKey peer — note that
//     ecdh.X25519().NewPublicKey only verifies length and does NOT
//     reject low-order points; that responsibility is split between
//     the curve25519 ECDH path inside go-piv (which catches the zero
//     output) and the post-ECDH zero-check below;
//   - obtains an *piv.X25519PrivateKey via yk.PrivateKey, with KeyAuth
//     pre-loaded with the verified PIN;
//   - calls ECDH on-card;
//   - re-checks the result is 32 bytes and not all-zero (defence in
//     depth required by the yubikey.Card contract).
func (p *pivWrapper) SharedSecret(ephPub []byte) ([]byte, error) {
	if p.slotPub == nil {
		return nil, fmt.Errorf("yubikey: slot 0x%02x has no key (run Enroll first)", byte(p.slot))
	}
	if len(ephPub) != 32 {
		return nil, fmt.Errorf("yubikey: slot 0x%02x SharedSecret: ephPub must be 32 bytes, got %d", byte(p.slot), len(ephPub))
	}

	peer, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, fmt.Errorf("yubikey: slot 0x%02x SharedSecret: parse ephPub: %w", byte(p.slot), err)
	}

	priv, err := p.yk.PrivateKey(p.pivSlot, p.slotPub, piv.KeyAuth{
		PIN:       p.pin,
		PINPolicy: p.pinPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("yubikey: slot 0x%02x PrivateKey handle: %w", byte(p.slot), err)
	}
	x25519Priv, ok := priv.(*piv.X25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("yubikey: slot 0x%02x PrivateKey returned %T, want *piv.X25519PrivateKey", byte(p.slot), priv)
	}

	shared, err := x25519Priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("yubikey: slot 0x%02x on-card ECDH: %w", byte(p.slot), err)
	}
	if len(shared) != 32 {
		return nil, fmt.Errorf("yubikey: slot 0x%02x ECDH returned %d bytes, want 32", byte(p.slot), len(shared))
	}
	// Constant-time all-zero check. RFC 7748 §6.1: a zero shared
	// secret signals a small-subgroup ephemeral and MUST NOT be used
	// as keying material. The go-piv X25519 ECDH path already returns
	// an error in that case, but the Card contract requires every
	// implementer to enforce this independently.
	var zero [32]byte
	if subtle.ConstantTimeCompare(shared, zero[:]) == 1 {
		return nil, fmt.Errorf("yubikey: slot 0x%02x ECDH produced all-zero shared secret (RFC 7748 §6.1)", byte(p.slot))
	}
	return shared, nil
}

// Close releases the smartcard handle.
func (p *pivWrapper) Close() error { return p.yk.Close() }

// ---- helpers ----

// mapSlot translates our SlotID into go-piv's typed Slot. Only
// SlotKeyManagement is supported in v1.
func mapSlot(s SlotID) (piv.Slot, bool) {
	switch s {
	case SlotKeyManagement:
		return piv.SlotKeyManagement, true
	default:
		return piv.Slot{}, false
	}
}

// mapTouchPolicy translates our TouchPolicy enum into go-piv's. The
// zero value (TouchAlways) maps to piv.TouchPolicyAlways — secure by
// default.
func mapTouchPolicy(t TouchPolicy) piv.TouchPolicy {
	switch t {
	case TouchNever:
		return piv.TouchPolicyNever
	case TouchCached:
		return piv.TouchPolicyCached
	default:
		// TouchAlways and any unexpected value land here.
		return piv.TouchPolicyAlways
	}
}
