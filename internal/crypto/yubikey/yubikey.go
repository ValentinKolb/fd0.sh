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
//   - PIN is required for use; touch policy is configurable at init.
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
type TouchPolicy uint8

const (
	TouchNever  TouchPolicy = iota // PIN-only, no touch.
	TouchAlways                    // every operation requires touch.
	TouchCached                    // touch valid for 15s after the prompt.
)

// PinPolicy mirrors the on-card setting.
type PinPolicy uint8

const (
	PinAlways PinPolicy = iota // PIN required for every operation.
	PinOnce                    // PIN required once per session.
)

// PivKey is the implementer's view of a connected YubiKey. Real impl in
// yubikey_piv.go; stub in yubikey_stub.go.
type PivKey interface {
	// PublicX25519 returns the slot's X25519 public key (32 B).
	PublicX25519() ([]byte, error)
	// OpenSealedBox runs sealed-box decryption on-card. The ephemeral pub
	// embedded in the sealed blob produces an ECDH against the slot's key;
	// the libsodium HKDF-then-AEAD step happens in software.
	OpenSealedBox(sealed []byte) ([]byte, error)
	// Close releases the smartcard handle.
	Close() error
}

// OpenOptions controls how Open finds and connects to the YubiKey.
type OpenOptions struct {
	// PIN, when non-empty, is verified before any operation.
	PIN string
	// Slot is the PIV slot to use. Default SlotKeyManagement.
	Slot SlotID
}

// Default returns the default OpenOptions.
func Default() OpenOptions {
	return OpenOptions{Slot: SlotKeyManagement}
}

// EnrollOptions captures the user's choices at `fd0 auth add --yubikey`.
//
// PIN, when non-empty, is set on the slot at provisioning time: subsequent
// unlocks will require the PIN AND a touch. An empty PIN provisions the
// slot with pin_policy=never, so unlock requires only a touch.
//
// Touch is always required regardless of PIN choice — that is the minimum
// safety bar (without it, malware with USB access could silently exercise
// the slot).
type EnrollOptions struct {
	Slot             SlotID
	PIN              string // empty = touch-only, no PIN
	ManagementKey    []byte // empty = use go-piv default management key
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
func ValidatePIN(pin string) error {
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
