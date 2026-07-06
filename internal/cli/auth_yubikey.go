package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/buildinfo"
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
// touchPolicy is one of "" (default = always), "always", "never",
// "cached"; anything else is rejected.
//
// force, when true, suppresses the overwrite-confirmation prompt that
// fires when slot 9d already holds a key. Default false: enrollment
// asks the user to confirm before destroying an existing slot-key,
// because that is irreversible (any vault wrap that depends on the
// old slot-pub is permanently locked out).
func RunAuthAddYubikey(ctx context.Context, touchPolicy string, force bool) error {
	if !buildinfo.YubikeyEnabled {
		return yubikeyUnavailableError()
	}
	// Detect a YubiKey early. List() is cheap and gives a friendlier error
	// than letting Enroll fail downstream.
	cards, err := yubikey.List()
	if err != nil {
		if errors.Is(err, yubikey.ErrNotEnabled) {
			return yubikeyUnavailableError()
		}
		return fmt.Errorf("yubikey: %w", err)
	}
	if len(cards) == 0 {
		return errors.New("yubikey: no smartcard detected — insert your YubiKey and retry")
	}
	fmt.Fprintf(os.Stderr, "✓ YubiKey detected: %s\n", cards[0])

	// SECURITY: enrollment overwrites slot 0x9d unconditionally on the
	// card. If the slot already has a key, that key is GONE. Any prior
	// vault that bound K_unlock to the OLD slot pub is permanently
	// unrecoverable from this card. Probe + confirm before destroying.
	if err := confirmSlotOverwrite(force); err != nil {
		return err
	}

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

	tp, err := parseTouchPolicy(touchPolicy)
	if err != nil {
		return err
	}

	// Provision the slot.
	slotPub, err := enrollYubikeySlot(pin, tp)
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
	ev, err := chain.BuildUserAuthSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub, uctx.TipSeq, uctx.TipHash, newActive)
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

	pinPart := "PIN+"
	pinHint := "Enter the PIN AND "
	if len(pin) == 0 {
		pinPart = ""
		pinHint = ""
	}
	touchPart := touchPolicySuffix(tp)
	touchHint := touchHintLine(tp)
	policy := pinPart + touchPart
	if policy == "" {
		policy = "(none — neither PIN nor touch required)"
	}
	fmt.Fprintf(os.Stderr, "✓ added YubiKey auth method %s (policy: %s)\n", newID, policy)
	if pinHint != "" || touchHint != "" {
		fmt.Fprintf(os.Stderr, "  %s%s on every fd0 unlock.\n", pinHint, touchHint)
	}
	if len(pin) > 0 {
		fmt.Fprintln(os.Stderr, "  Three wrong PINs lock the slot — only the YubiKey PUK can recover it.")
	}
	return nil
}

func yubikeyUnavailableError() error {
	fd0Path, _ := os.Executable()
	agentPath, _ := exec.LookPath("fd0-agent")
	if agentPath == "" {
		agentPath = "(fd0-agent not found in PATH)"
	}
	return fmt.Errorf(`this fd0 binary was installed as the standard flavor, without YubiKey/PIV support

Install the YubiKey flavor:
  fd0 update --flavor=yubikey

Or install it fresh:
  curl -fsSL https://fd0.sh/install | sh -s -- --yubikey

Both fd0 and fd0-agent must use the yubikey flavor.
Current fd0 path: %s
Current fd0-agent path: %s
After installing, run:
  fd0 agent restart`, fd0Path, agentPath)
}

func touchPolicySuffix(tp yubikey.TouchPolicy) string {
	switch tp {
	case yubikey.TouchAlways:
		return "touch (always)"
	case yubikey.TouchCached:
		return "touch (cached 15s)"
	case yubikey.TouchNever:
		return ""
	default:
		return "touch"
	}
}

func touchHintLine(tp yubikey.TouchPolicy) string {
	switch tp {
	case yubikey.TouchAlways:
		return "touch the YubiKey"
	case yubikey.TouchCached:
		return "touch the YubiKey (then cached 15s)"
	case yubikey.TouchNever:
		return ""
	default:
		return "touch the YubiKey"
	}
}

// enrollYubikeySlot calls the yubikey package and returns the slot's pubkey.
// Pulled out so the CLI flow has a single failure point to map to the
// user-facing message.
//
// PIN is forwarded as []byte through the yubikey package; the only
// string conversion happens at the go-piv VerifyPIN boundary inside
// the package, with no long-lived retention.
func enrollYubikeySlot(pin []byte, tp yubikey.TouchPolicy) ([]byte, error) {
	res, err := yubikey.Enroll(yubikey.EnrollOptions{
		Slot:        yubikey.SlotKeyManagement,
		PIN:         pin,
		TouchPolicy: tp,
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("yubikey: Enroll returned nil result")
	}
	return res.X25519Pub, nil
}

// confirmSlotOverwrite probes slot 0x9d for an existing X25519 key.
// Fail-closed semantics: the probe MUST observe the slot's actual
// state. If the probe can't open the card (PCSC contention, no
// reader, transient hardware error), we refuse rather than risk
// silently overwriting an existing key — unless --force is given.
//
// Outcomes:
//   - probe success + slot empty:    proceed (no prompt)
//   - probe success + slot populated: TTY 'yes' confirm OR --force
//   - probe failure:                  refuse OR --force
//
// The probe opens the card without a PIN — KeyInfo only needs read
// access — so this does not consume a PIN-retry attempt.
func confirmSlotOverwrite(force bool) error {
	card, err := yubikey.Open(yubikey.OpenOptions{Slot: yubikey.SlotKeyManagement})
	if err != nil {
		if force {
			fmt.Fprintf(os.Stderr, "! slot probe failed (%v); --force given, proceeding.\n", err)
			return nil
		}
		return fmt.Errorf("yubikey: cannot probe slot 0x9d before enrollment (%w); pass --force to skip the probe (DANGEROUS — may overwrite an existing key)", err)
	}
	defer card.Close()
	pub, err := card.PublicX25519()
	if err != nil {
		// PublicX25519 fails when the slot is empty (the cached pub
		// in pivWrapper is nil). Typed sentinel — string-matching
		// the message would be brittle if the wrapped text ever
		// moves. errors.Is decouples the policy from the prose.
		if errors.Is(err, yubikey.ErrSlotEmpty) {
			return nil
		}
		if force {
			fmt.Fprintf(os.Stderr, "! slot probe inconclusive (%v); --force given, proceeding.\n", err)
			return nil
		}
		return fmt.Errorf("yubikey: cannot read slot 0x9d pubkey before enrollment (%w); pass --force to skip the probe (DANGEROUS — may overwrite an existing key)", err)
	}
	if force {
		fmt.Fprintf(os.Stderr, "! slot 0x9d has an existing X25519 key (pub %x); --force given, overwriting.\n", pub[:8])
		return nil
	}
	fmt.Fprintf(os.Stderr, "! slot 0x9d already has an X25519 key (pub %x).\n", pub[:8])
	fmt.Fprintln(os.Stderr, "! Enrolling a new method OVERWRITES this key. Any vault still bound to the old key will be permanently locked out of THIS card.")
	if !IsTTY(os.Stdin) {
		return errors.New("yubikey: slot 0x9d already provisioned; pass --force to overwrite (refusing to do so silently from a non-interactive stdin)")
	}
	fmt.Fprint(os.Stderr, "Type 'yes' to overwrite, anything else to abort: ")
	r := sharedStdin()
	line, _ := r.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "yes" {
		return errors.New("yubikey: overwrite aborted by user")
	}
	return nil
}

// parseTouchPolicy maps the --touch flag value to a TouchPolicy.
// Empty string defaults to TouchAlways (secure default for production
// enrollments). Tests opt into TouchNever explicitly.
func parseTouchPolicy(s string) (yubikey.TouchPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "always":
		return yubikey.TouchAlways, nil
	case "never":
		return yubikey.TouchNever, nil
	case "cached":
		return yubikey.TouchCached, nil
	default:
		return 0, fmt.Errorf("--touch=%q: must be 'always', 'never', or 'cached'", s)
	}
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
	// ValidatePIN takes []byte directly so no immutable string copy is
	// created — the wipeable byte buffer flows all the way through.
	if err := yubikey.ValidatePIN(pinBytes); err != nil {
		crypto.Wipe(pinBytes)
		return nil, err
	}
	return pinBytes, nil
}

// _ keeps ed25519 imported in case future hardware-day work needs it for
// slot attestation cross-checks. Drop when wiring lands.
var _ = ed25519.PublicKeySize
