package cli

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Card wire format: `fd0://card/<base64url(cbor(IdentityCard))>`.
const cardURLPrefix = "fd0://card/"

// Default expiry for an exported card.
const cardDefaultLifetime = 24 * time.Hour

// shortIDFromPub returns a shortId stand-in derived from super_pub. v1 has no
// server-assigned shortId until first sync; we use the first 8 base32-lower
// chars of the super_pub for determinism. Spec §2.2 calls shortId
// "semi-private" — this stand-in is no less private than super_pub itself.
func shortIDFromPub(pub []byte) string {
	enc := base64.RawStdEncoding.EncodeToString(pub)
	enc = strings.ToLower(strings.NewReplacer("+", "x", "/", "y", "=", "z").Replace(enc))
	if len(enc) >= 8 {
		return enc[:8]
	}
	return enc
}

// RunCardExport prints a signed IdentityCard URL. Replaces the v0 raw-pubkey
// shortcut: from now on, members are added by card URL.
func RunCardExport(ctx context.Context) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	now := time.Now()
	card := &proto.IdentityCard{
		Version:   1,
		ShortID:   shortIDFromPub(s.UserSuperPub),
		SuperPub:  append([]byte(nil), s.UserSuperPub...),
		IssuedAt:  uint64(now.Unix()),
		ExpiresAt: uint64(now.Add(cardDefaultLifetime).Unix()),
	}
	si, err := card.SignedInput()
	if err != nil {
		return err
	}
	sig, err := s.Agent.Sign(si)
	if err != nil {
		return err
	}
	card.Signature = sig
	cb, err := proto.Marshal(card)
	if err != nil {
		return err
	}
	fmt.Println(cardURLPrefix + base64.RawURLEncoding.EncodeToString(cb))
	// Hint with safety number on stderr so the holder can recite it OOB.
	sn, _ := SafetyNumber(card.ShortID, card.SuperPub)
	fmt.Fprintf(os.Stderr, "\nSafety number (verify out-of-band):\n%s\n", indent(sn, "  "))
	fmt.Fprintf(os.Stderr, "Expires: %s\n", time.Unix(int64(card.ExpiresAt), 0).Format(time.RFC3339))
	return nil
}

// RunCardImport decodes a card URL, verifies its signature and expiry,
// displays the safety number, and on user confirmation pins the (super_pub,
// label) into vault.PinnedIdentities.
func RunCardImport(ctx context.Context, cardInput, label string, yes bool) error {
	card, err := parseCardURL(cardInput)
	if err != nil {
		return err
	}
	if err := verifyCard(card); err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if label == "" {
		label = card.ShortID
	}
	// Refuse to silently rebind: error if label points to a different pub.
	if existing, ok := s.Body.PinnedIdentities[label]; ok {
		if !bytesEq(existing.SuperPub, card.SuperPub) {
			return fmt.Errorf("label %q already pins a different identity (%s…)", label, b64sub(existing.SuperPub))
		}
		fmt.Fprintf(os.Stderr, "✓ %s already pinned (no-op)\n", label)
		return nil
	}
	sn, _ := SafetyNumber(card.ShortID, card.SuperPub)
	fmt.Fprintf(os.Stderr, "Importing identity card:\n")
	fmt.Fprintf(os.Stderr, "  shortId : %s\n", card.ShortID)
	fmt.Fprintf(os.Stderr, "  pub     : %s…\n", b64sub(card.SuperPub))
	fmt.Fprintf(os.Stderr, "  expires : %s\n", time.Unix(int64(card.ExpiresAt), 0).Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "\nSafety number (compare out-of-band):\n%s\n\n", indent(sn, "  "))
	if !yes {
		if !IsTTY(os.Stdin) {
			return errors.New("non-interactive: pass --yes to confirm")
		}
		fmt.Fprintf(os.Stderr, "Pin as '%s'? [y/N] ", label)
		r := bufio.NewReader(os.Stdin)
		ans, _ := r.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ans)), "y") {
			return errors.New("aborted")
		}
	}
	if s.Body.PinnedIdentities == nil {
		s.Body.PinnedIdentities = map[string]proto.PinnedIdentity{}
	}
	s.Body.PinnedIdentities[label] = proto.PinnedIdentity{
		SuperPub: append([]byte(nil), card.SuperPub...),
		Label:    label,
	}
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ pinned %s\n", label)
	return nil
}

// RunCardList prints all pinned identities.
func RunCardList(ctx context.Context) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if len(s.Body.PinnedIdentities) == 0 {
		fmt.Println("(no pinned identities)")
		return nil
	}
	labels := make([]string, 0, len(s.Body.PinnedIdentities))
	for l := range s.Body.PinnedIdentities {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		p := s.Body.PinnedIdentities[l]
		fmt.Printf("%-20s  %s…\n", l, b64sub(p.SuperPub))
	}
	return nil
}

// RunCardRemove unpins a label.
func RunCardRemove(ctx context.Context, label string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, ok := s.Body.PinnedIdentities[label]; !ok {
		return fmt.Errorf("no pinned identity %q", label)
	}
	delete(s.Body.PinnedIdentities, label)
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ unpinned %s\n", label)
	return nil
}

// parseCardURL accepts the canonical `fd0://card/<base64url(cbor(card))>`
// form.
func parseCardURL(input string) (*proto.IdentityCard, error) {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, cardURLPrefix) {
		return nil, fmt.Errorf("not a card URL (must start with %s)", cardURLPrefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(input[len(cardURLPrefix):])
	if err != nil {
		return nil, fmt.Errorf("card: bad base64url: %w", err)
	}
	var card proto.IdentityCard
	if err := proto.Unmarshal(b, &card); err != nil {
		return nil, fmt.Errorf("card: bad CBOR: %w", err)
	}
	return &card, nil
}

// verifyCard checks signature, version, and expiry per PROTOCOL.md §2.3.
func verifyCard(card *proto.IdentityCard) error {
	if card.Version != 1 {
		return fmt.Errorf("card: unsupported version %d", card.Version)
	}
	if len(card.SuperPub) != 32 {
		return errors.New("card: bad super_pub length")
	}
	if len(card.Signature) != 64 {
		return errors.New("card: bad signature length")
	}
	if uint64(time.Now().Unix()) >= card.ExpiresAt {
		return fmt.Errorf("card: expired at %s", time.Unix(int64(card.ExpiresAt), 0).Format(time.RFC3339))
	}
	si, err := card.SignedInput()
	if err != nil {
		return err
	}
	if !crypto.Verify(card.SuperPub, si, card.Signature) {
		return errors.New("card: bad signature")
	}
	return nil
}

// resolveMember accepts: a card URL, a pinned-identity label, or rejects.
// Returns the member's super_pub (32 B). Hard switch: raw base64 super_pub
// is no longer accepted.
func (s *Session) resolveMember(input string) ([]byte, error) {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, cardURLPrefix) {
		card, err := parseCardURL(input)
		if err != nil {
			return nil, err
		}
		if err := verifyCard(card); err != nil {
			return nil, err
		}
		return card.SuperPub, nil
	}
	if p, ok := s.Body.PinnedIdentities[input]; ok {
		return append([]byte(nil), p.SuperPub...), nil
	}
	return nil, fmt.Errorf("not a card URL or pinned label: %q (run `fd0 card import <url>` first, or `fd0 trust ls`)", input)
}

// indent returns s with each line prefixed by p.
func indent(s, p string) string {
	out := strings.Split(s, "\n")
	for i := range out {
		out[i] = p + out[i]
	}
	return strings.Join(out, "\n")
}
