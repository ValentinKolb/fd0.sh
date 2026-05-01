package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/crypto/yubikey"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// RunAuthAddYubikey enrolls a YubiKey as an additional auth method.
//
// Flow:
//  1. Confirm a YubiKey is reachable.
//  2. Prompt the user to choose touch-only vs PIN+touch protection.
//  3. If PIN: prompt twice, validate per Yubico rules (6–8 ASCII chars).
//  4. Provision the slot (`yubikey.Enroll`) → returns slot pubkey + meta.
//  5. Generate a fresh 32-byte K_unlock, sealed-box-encrypt it to the
//     slot's pubkey, and store the sealed blob in `public_params`.
//  6. Encrypt super_priv under K_unlock (via the agent), append a new
//     auth.set, add a vault wrap.
//
// Until the hardware-day integration of the yubikey package is complete,
// step 4 returns ErrNotEnabled (or "pending hardware-day integration").
// We surface that error verbatim so the user sees what's blocked, but we
// do NOT half-enroll: the user-chain stays untouched on any failure.
func RunAuthAddYubikey(ctx context.Context) error {
	// Detect a YubiKey early. List() is cheap and gives a friendlier error
	// than letting Enroll fail downstream.
	cards, err := yubikey.List()
	if err != nil {
		return fmt.Errorf("yubikey: %w", err)
	}
	if len(cards) == 0 {
		return errors.New("yubikey: no smartcard detected — insert your YubiKey and retry")
	}
	fmt.Fprintf(os.Stderr, "✓ YubiKey detected: %s\n", cards[0])

	// PIN choice prompt. Default to touch-only (`n`) since most users
	// expect a hardware key to be one-factor.
	//
	// Returns []byte so the deferred Wipe actually clears the source
	// memory; converting to string would copy into immutable memory
	// where Wipe has no effect.
	pin, err := promptYubikeyPIN(os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	defer crypto.Wipe(pin)

	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	uctx, err := chain.ReplayUser(s.Paths.UserChain)
	if err != nil {
		return err
	}
	if uctx == nil || uctx.LatestAuthSet == nil {
		return errors.New("no auth methods on user chain")
	}

	// Provision the slot. This is the step still pending hardware-day
	// completion — surfacing the underlying error verbatim helps the user
	// distinguish "no card" from "card but driver unfinished".
	slotPub, err := enrollYubikeySlot(pin)
	if err != nil {
		return err
	}
	if len(slotPub) != 32 {
		return fmt.Errorf("yubikey: slot pubkey length %d != 32", len(slotPub))
	}

	// Generate a fresh 32-byte K_unlock and seal it to the slot pub.
	kUnlock, err := crypto.RandomBytes(32)
	if err != nil {
		return err
	}
	defer crypto.Wipe(kUnlock)
	sealed, err := crypto.SealAnonymous(kUnlock, slotPub)
	if err != nil {
		return fmt.Errorf("yubikey: seal K_unlock: %w", err)
	}

	pp, err := proto.Marshal(proto.YubikeyPublicParams{
		X25519Pub:     slotPub,
		SealedKUnlock: sealed,
		Slot:          uint8(yubikey.SlotKeyManagement),
	})
	if err != nil {
		return err
	}

	newID := "am_" + ulid.Make().String()
	encSP, err := s.Agent.EncryptSuperPriv(kUnlock, newID)
	if err != nil {
		return err
	}

	newActive := append([]proto.AuthMethod{}, uctx.LatestAuthSet.Payload.Active...)
	newActive = append(newActive, proto.AuthMethod{
		MethodID:           newID,
		MethodType:         proto.AuthYubikey,
		PublicParams:       pp,
		EncryptedSuperPriv: encSP,
	})
	ev, err := buildUserAuthSetAgent(s.Agent, s.UserSuperPub, uctx.TipSeq, uctx.TipHash, newActive)
	if err != nil {
		return err
	}
	// Atomicity ordering: same as the passphrase path in `auth.go`.
	// Vault wrap FIRST so that on chain-append failure the worst case is
	// an orphan wrap (detected by doctor) rather than a chain advertising
	// a method that cannot unlock.
	if err := s.Agent.AddWrap(s.Paths.Vault, newID, proto.AuthYubikey, pp, kUnlock); err != nil {
		return err
	}
	if err := chain.AppendUser(s.Paths.UserChain, ev); err != nil {
		_ = s.Agent.RemoveWrap(s.Paths.Vault, newID)
		return err
	}
	prefix, _ := ev.PrevHashInput()
	h := proto.HashPrefix(prefix)
	s.Body.AuthTip = proto.ChainTip{Seq: ev.Seq, Hash: h[:]}
	if err := s.ReSeal(); err != nil {
		return err
	}

	policy := "touch-only"
	if len(pin) > 0 {
		policy = "PIN+touch"
	}
	fmt.Fprintf(os.Stderr, "✓ added YubiKey auth method %s (policy: %s)\n", newID, policy)
	if len(pin) == 0 {
		fmt.Fprintln(os.Stderr, "  Touch the YubiKey on every fd0 unlock.")
	} else {
		fmt.Fprintln(os.Stderr, "  Enter the PIN AND touch the YubiKey on every fd0 unlock.")
		fmt.Fprintln(os.Stderr, "  Three wrong PINs lock the slot — only the YubiKey PUK can recover it.")
	}
	return nil
}

// enrollYubikeySlot calls the yubikey package and returns the slot's pubkey.
// Pulled out so the CLI flow has a single failure point to map to the
// user-facing message.
//
// We accept []byte (not string) for the PIN so the source memory is the
// caller's wipeable buffer. The conversion to string happens once, here,
// inline at the call boundary; the resulting immutable copy lives only
// for the duration of the Enroll call (the yubikey package is the
// stable boundary at which PIN must be a string per its API contract).
func enrollYubikeySlot(pin []byte) ([]byte, error) {
	res, err := yubikey.Enroll(yubikey.EnrollOptions{
		Slot: yubikey.SlotKeyManagement,
		PIN:  string(pin),
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("yubikey: Enroll returned nil result")
	}
	return res.X25519Pub, nil
}

// promptYubikeyPIN walks the user through the touch-only-vs-PIN choice
// and (if PIN) collects+validates+confirms it. Returns []byte (not
// string) so the caller can `crypto.Wipe` the source memory; converting
// to string would copy into immutable memory where Wipe has no effect.
//
// A nil/empty return value means "user chose touch-only".
//
// Pulled into its own function so unit tests can exercise the input
// parser without spawning a real terminal.
func promptYubikeyPIN(stdin *os.File, stderr *os.File) ([]byte, error) {
	fmt.Fprintln(stderr, "Choose YubiKey protection:")
	fmt.Fprintln(stderr, "  [n] Touch only       — only physical touch (1FA hardware)")
	fmt.Fprintln(stderr, "  [y] PIN + touch      — additionally a PIN at every unlock")
	fmt.Fprint(stderr, "Set a PIN? [y/N]: ")

	r := sharedStdin()
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return nil, err
	}
	choice := strings.ToLower(strings.TrimSpace(line))
	switch choice {
	case "", "n", "no":
		return nil, nil
	case "y", "yes":
		// fall through to PIN prompt
	default:
		return nil, fmt.Errorf("unrecognized choice %q (expected y/n)", choice)
	}

	pinBytes, err := ReadPassphraseConfirm(
		"Enter PIN (6-8 ASCII chars): ",
		"Confirm PIN: ",
	)
	if err != nil {
		return nil, err
	}
	// ValidatePIN takes a string per the yubikey package's API. The
	// string conversion here lives only for the duration of this call;
	// the original wipeable byte buffer is what we return.
	if err := yubikey.ValidatePIN(string(pinBytes)); err != nil {
		crypto.Wipe(pinBytes)
		return nil, err
	}
	return pinBytes, nil
}

// _ keeps ed25519 imported in case future hardware-day work needs it for
// slot attestation cross-checks. Drop when wiring lands.
var _ = ed25519.PublicKeySize
