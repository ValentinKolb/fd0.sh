// Package yubikey is the YubiKey-PIV-backed unlock resolver.
//
// fd0 supports two unlock methods:
//
//   - passphrase  (always available, pure-Go, see internal/vault.PassphraseResolver)
//   - yubikey     (this package, requires cgo + libpcsc, behind build tag)
//
// Build with `-tags=yubikey` to include the real PIV implementation. Without
// the tag, every entry point in this package returns ErrNotEnabled, so the
// rest of fd0 stays pure-Go and statically linkable.
//
// Spec reference: PROTOCOL.md §3.1 (yubikey method).
//
//	K_unlock derivation:
//	  yubikey: ECDH-derived key from a sealed-box opened by the on-card key.
//	  public_params: yubikey_x25519_pub(32)
//
// Implementation notes:
//   - Slot 9d (Key Management) is the conventional ECDH slot.
//   - X25519 is required (YubiKey firmware 5.7+); older firmware is rejected.
//   - PIN policy is chosen at enrollment: a non-empty PIN sets PINPolicyOnce
//     (one PIN entry per session); an empty PIN sets PINPolicyNever
//     (touch-only mode).
//   - Touch policy defaults to TouchAlways; tests can override to
//     TouchNever.
package yubikey

import "errors"

// ErrNotEnabled is returned by every API in this package when fd0 was built
// without the `yubikey` tag.
var ErrNotEnabled = errors.New("yubikey: build fd0 with -tags=yubikey to enable PIV support")

// SlotID identifies a PIV slot. v1 only uses Key Management.
type SlotID uint8

const (
	SlotKeyManagement SlotID = 0x9d // PIV Key Management — recommended for ECDH
)

// TouchPolicy mirrors the on-card setting.
//
// The zero value is TouchAlways — secure-by-default for any caller that
// allocates an EnrollOptions without explicitly choosing a policy.
type TouchPolicy uint8

const (
	TouchAlways TouchPolicy = iota // every operation requires touch (default).
	TouchNever                     // no touch; PIN-only.
	TouchCached                    // touch valid for 15s after the prompt.
)

// PinPolicy mirrors the on-card setting.
type PinPolicy uint8

const (
	PinAlways PinPolicy = iota // PIN required for every operation.
	PinOnce                    // PIN required once per session.
)

// Card is the abstract YubiKey-PIV view used by fd0.
//
// The interface deliberately exposes only the steps that depend on
// hardware: producing the slot's public X25519 key, and running ECDH
// against the slot's private key. Everything else in the sealed-box
// open path (parsing, libsodium key derivation, XSalsa20-Poly1305
// open) is pure software and lives in package crypto, where it is
// independently unit-tested.
//
// Real impl in yubikey_piv.go (build tag `yubikey`); software MockCard
// in mockcard.go for tests; stub in yubikey_stub.go for builds without
// the tag.
type Card interface {
	// PublicX25519 returns a fresh 32-byte copy of the slot's X25519
	// public key. Implementations MUST NOT alias internal state — the
	// caller owns the returned slice and may overwrite it freely.
	PublicX25519() ([]byte, error)
	// SharedSecret performs an X25519 ECDH between the slot's private
	// key and the supplied ephemeral pubkey. The 32-byte output is the
	// libsodium crypto_box_seal "shared" input, fed into the
	// HSalsa20 / XSalsa20-Poly1305 open path on the host side.
	//
	// Implementations MUST:
	//   - reject ephPub whose length is not exactly 32 bytes;
	//   - return a fresh, caller-owned 32-byte slice on success;
	//   - return a non-nil error if the resulting shared secret is
	//     all-zero (RFC 7748 §6.1 — small-subgroup ephemerals produce
	//     a degenerate zero output and MUST NOT be used as keying
	//     material). The pure-software curve25519.X25519 already
	//     enforces this; hardware implementations MUST replicate the
	//     check after the on-card ECDH.
	SharedSecret(ephPub []byte) ([]byte, error)
	// PINRetries returns the number of PIN-verify attempts remaining
	// before the PIV PIN blocks (typical YubiKey: starts at 3,
	// successful verify resets to 3, blocked at 0). Used by callers
	// to refuse "wrong PIN" tests when the card is one wrong attempt
	// away from blocking. Software MockCard reports a fixed 3.
	PINRetries() (int, error)
	// Close releases the smartcard handle (no-op for software cards).
	Close() error
}

// OpenOptions controls how Open finds and connects to the YubiKey.
type OpenOptions struct {
	// PIN, when non-empty, is verified before any operation. We hold
	// the PIN as []byte so callers can wipe their copy after Open
	// returns; the implementation forwards it to go-piv (which only
	// accepts string) at the single call boundary, with no long-lived
	// retention.
	PIN []byte
	// Slot is the PIV slot to use. Default SlotKeyManagement.
	Slot SlotID
}

// Default returns the default OpenOptions.
func Default() OpenOptions {
	return OpenOptions{Slot: SlotKeyManagement}
}

// EnrollOptions captures the user's choices at `fd0 auth add --yubikey`.
//
// PIN, when non-empty, is the PIV PIN that already authenticates the
// device (set out of band — on a fresh YubiKey it is "123456"). Enroll
// uses it (a) to authenticate the slot operation if the management key
// requires PIN-then-mgmt mode, and (b) to set the slot's PIN policy:
// non-empty PIN ⇒ PINPolicyOnce on the new slot, empty ⇒ PINPolicyNever.
// Stored as []byte so callers can wipe their buffer after Enroll
// returns.
//
// Touch is configurable; the default is TouchAlways for production
// (without it, same-UID malware with USB access could silently exercise
// the slot once an unlocked session exists). Test runs can override to
// TouchNever to avoid the per-operation tap.
//
// ManagementKey is required to authorise the slot key generation. An
// empty value falls back to piv's published default. A real deployment
// should change the management key before enrolling and pass it here.
type EnrollOptions struct {
	Slot          SlotID
	PIN           []byte
	ManagementKey []byte
	// TouchPolicy controls whether the on-card key requires a physical
	// touch on each operation. Default (zero value) maps to TouchAlways.
	// Set explicitly to TouchNever for unattended test runs.
	TouchPolicy TouchPolicy
}

// EnrollResult bundles what the agent needs after a successful enrollment.
type EnrollResult struct {
	Slot      SlotID
	X25519Pub []byte // 32-byte slot pubkey, post-generation
	HasPIN    bool   // mirrors EnrollOptions.PIN != ""
}

// ValidatePIN performs the input-validation a CLI prompt should apply
// before invoking Enroll. Yubico PIV PINs must be 6–8 ASCII characters.
//
// Pulled out of Enroll so unit tests can hit it without hardware.
// Accepts []byte so callers don't need to convert to string (which
// would prevent the buffer from being wiped).
func ValidatePIN(pin []byte) error {
	if len(pin) < 6 {
		return errPINTooShort
	}
	if len(pin) > 8 {
		return errPINTooLong
	}
	for _, r := range pin {
		if r < 0x20 || r > 0x7e {
			return errPINBadChar
		}
	}
	return nil
}

var (
	errPINTooShort = errors.New("yubikey PIN: must be at least 6 characters")
	errPINTooLong  = errors.New("yubikey PIN: must be at most 8 characters")
	errPINBadChar  = errors.New("yubikey PIN: only printable ASCII allowed (Yubico PIV constraint)")
)
