package desktopbridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"sort"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

type TrustedContact struct {
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint"`
	Shared      bool   `json:"shared,omitempty"`
}

type ScopeMember struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint"`
	Self        bool   `json:"self,omitempty"`
	Trusted     bool   `json:"trusted,omitempty"`
}

type IdentityCardInfoResult struct {
	URL          string `json:"url,omitempty"`
	ShortID      string `json:"shortId"`
	Fingerprint  string `json:"fingerprint"`
	SafetyNumber string `json:"safetyNumber"`
	ExpiresAt    string `json:"expiresAt"`
}

type ScopeShareInfoResult struct {
	ScopeLabel string           `json:"scopeLabel"`
	Contacts   []TrustedContact `json:"contacts"`
	Members    []ScopeMember    `json:"members"`
}

func (s *Service) scopeShareInfo(ctx context.Context, scopeID string) (ScopeShareInfoResult, error) {
	if _, err := proto.ParseScopeID(scopeID); err != nil {
		return ScopeShareInfoResult{}, fail("validation", "That vault reference is invalid.", "", false)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return ScopeShareInfoResult{}, mapDomainError(err)
	}
	defer session.Close()
	scope, ok := session.Body.Scopes[scopeID]
	if !ok || scope.Leaving {
		return ScopeShareInfoResult{}, fail("not_found", "That vault is no longer available.", "Refresh the vault list.", false)
	}
	scopeLabel := strings.TrimSpace(scope.Label)
	if scopeLabel == "" {
		scopeLabel = "Unnamed vault"
	}
	state, err := chain.ReplayScope(
		session.Paths.ScopeChain(proto.MustParseScopeID(scopeID)),
		session.UserSuperPub,
		session.UserX25519Pub,
		cli.AgentOpener{Agent: session.Agent},
	)
	if err != nil {
		return ScopeShareInfoResult{}, mapDomainError(err)
	}
	if state == nil {
		return ScopeShareInfoResult{}, fail("integrity_check_failed", "fd0 could not read this vault's membership history.", "Open Support before sharing it.", false)
	}
	return ScopeShareInfoResult{
		ScopeLabel: boundedInventoryText(scopeLabel),
		Contacts:   trustedContacts(session.Body.PinnedIdentities, state.MemberSet),
		Members:    scopeMembers(session.Body.PinnedIdentities, state.MemberSet, session.UserSuperPub),
	}, nil
}

func (s *Service) addScopeMember(ctx context.Context, scopeID, label string) (map[string]bool, error) {
	if _, err := proto.ParseScopeID(scopeID); err != nil {
		return nil, fail("validation", "That vault reference is invalid.", "", false)
	}
	label = strings.TrimSpace(label)
	if label == "" || strings.ContainsAny(label, "\r\n\x00") {
		return nil, fail("validation", "Choose a trusted contact.", "", false)
	}
	if err := cli.RunScopeAddMember(ctx, scopeID, label); err != nil {
		return nil, mapDomainError(err)
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Service) removeScopeMember(ctx context.Context, scopeID, memberID string) (map[string]bool, error) {
	if _, err := proto.ParseScopeID(scopeID); err != nil {
		return nil, fail("validation", "That vault reference is invalid.", "", false)
	}
	memberPub, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(memberID))
	if err != nil || len(memberPub) != 32 {
		return nil, fail("validation", "That vault member reference is invalid.", "Refresh the access list.", false)
	}
	if err := cli.RunScopeRemoveMemberByPublicKey(ctx, scopeID, memberPub); err != nil {
		return nil, mapDomainError(err)
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Service) exportIdentityCard(ctx context.Context) (IdentityCardInfoResult, error) {
	info, err := cli.ExportIdentityCard(ctx)
	if err != nil {
		return IdentityCardInfoResult{}, mapDomainError(err)
	}
	return identityCardResult(info, true), nil
}

func (s *Service) inspectIdentityCard(cardURL string) (IdentityCardInfoResult, error) {
	cardURL = strings.TrimSpace(cardURL)
	if cardURL == "" || len(cardURL) > 16*1024 {
		return IdentityCardInfoResult{}, fail("validation", "Paste a valid fd0 identity card URL.", "", false)
	}
	info, err := cli.InspectIdentityCard(cardURL)
	if err != nil {
		if strings.Contains(err.Error(), "expired at") {
			return IdentityCardInfoResult{}, fail("expired_card", "This identity card has expired.", "Ask the contact to export a fresh card, then verify its safety number.", false)
		}
		return IdentityCardInfoResult{}, fail("invalid_card", "This identity card is invalid.", "Ask the contact to export it again, then verify its safety number.", false)
	}
	return identityCardResult(info, false), nil
}

func (s *Service) importIdentityCard(ctx context.Context, cardURL, label string) (map[string]bool, error) {
	cardURL = strings.TrimSpace(cardURL)
	label = strings.TrimSpace(label)
	if cardURL == "" || len(cardURL) > 16*1024 {
		return nil, fail("validation", "Paste a valid fd0 identity card URL.", "", false)
	}
	if label == "" || len(label) > 80 || strings.ContainsAny(label, "\r\n\x00") {
		return nil, fail("validation", "Choose a contact name between 1 and 80 characters.", "", false)
	}
	if err := cli.RunCardImport(ctx, cardURL, label, true); err != nil {
		return nil, mapDomainError(err)
	}
	return map[string]bool{"ok": true}, nil
}

func identityCardResult(info *cli.IdentityCardInfo, includeURL bool) IdentityCardInfoResult {
	result := IdentityCardInfoResult{
		ShortID:      info.ShortID,
		Fingerprint:  shortFingerprint(info.SuperPub),
		SafetyNumber: info.SafetyNumber,
		ExpiresAt:    info.ExpiresAt.Format(time.RFC3339),
	}
	if includeURL {
		result.URL = info.URL
	}
	return result
}

func trustedContacts(pinned map[string]proto.PinnedIdentity, members [][]byte) []TrustedContact {
	contacts := make([]TrustedContact, 0, len(pinned))
	for label, identity := range pinned {
		if strings.TrimSpace(label) == "" || len(identity.SuperPub) != 32 {
			continue
		}
		shared := false
		for _, member := range members {
			if bytes.Equal(identity.SuperPub, member) {
				shared = true
				break
			}
		}
		contacts = append(contacts, TrustedContact{Label: label, Fingerprint: shortFingerprint(identity.SuperPub), Shared: shared})
	}
	sort.Slice(contacts, func(i, j int) bool {
		return strings.ToLower(contacts[i].Label) < strings.ToLower(contacts[j].Label)
	})
	return contacts
}

func scopeMembers(pinned map[string]proto.PinnedIdentity, members [][]byte, self []byte) []ScopeMember {
	labels := make([]string, 0, len(pinned))
	for label := range pinned {
		labels = append(labels, label)
	}
	sort.Slice(labels, func(i, j int) bool { return strings.ToLower(labels[i]) < strings.ToLower(labels[j]) })
	trusted := make(map[string]string, len(labels))
	for _, label := range labels {
		identity := pinned[label]
		if strings.TrimSpace(label) != "" && len(identity.SuperPub) == 32 {
			key := string(identity.SuperPub)
			if _, exists := trusted[key]; !exists {
				trusted[key] = label
			}
		}
	}

	result := make([]ScopeMember, 0, len(members))
	for _, member := range members {
		if len(member) != 32 {
			continue
		}
		isSelf := bytes.Equal(member, self)
		label, isTrusted := trusted[string(member)]
		if isSelf {
			label = "You"
		} else if !isTrusted {
			label = "Unknown member"
		}
		result = append(result, ScopeMember{
			ID:          base64.RawURLEncoding.EncodeToString(member),
			Label:       label,
			Fingerprint: shortFingerprint(member),
			Self:        isSelf,
			Trusted:     isTrusted,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Self != result[j].Self {
			return result[i].Self
		}
		left, right := strings.ToLower(result[i].Label), strings.ToLower(result[j].Label)
		if left != right {
			return left < right
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func shortFingerprint(publicKey []byte) string {
	fingerprint := base64.RawStdEncoding.EncodeToString(publicKey)
	if len(fingerprint) > 12 {
		fingerprint = fingerprint[:12]
	}
	return fingerprint
}
