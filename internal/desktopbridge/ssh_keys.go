package desktopbridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
)

type SSHKeySummary struct {
	ScopeID     string `json:"scopeId"`
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment,omitempty"`
}

type SaveSSHKeyParams struct {
	ScopeID string `json:"scopeId"`
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
}

func validateSSHKeyMetadata(name, comment string) error {
	if name == "" {
		return fail("validation", "SSH key name is required.", "", false)
	}
	if strings.ContainsAny(name, "\r\n") {
		return fail("validation", "An SSH key name must stay on one line.", "", false)
	}
	if strings.ContainsAny(comment, "\r\n") {
		return fail("validation", "An SSH key comment must stay on one line.", "", false)
	}
	return nil
}

func isSSHKeyType(recordType string) bool {
	switch recordType {
	case string(sshkey.TypeEd25519), string(sshkey.TypeRSA), string(sshkey.TypeECDSA):
		return true
	default:
		return false
	}
}

func decodeSSHKey(record cli.TypedRecord) (*sshkey.Key, error) {
	if !isSSHKeyType(record.Type) {
		return nil, fail("type_conflict", "That item is not an SSH key.", "Refresh the vault and choose another key.", false)
	}
	raw, err := record.PayloadJSON()
	if err != nil {
		return nil, err
	}
	var wire sshkey.JSON
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, err
	}
	key, err := sshkey.Unmarshal(wire)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func sshKeySummary(record cli.TypedRecord) (SSHKeySummary, error) {
	key, err := decodeSSHKey(record)
	if err != nil {
		return SSHKeySummary{}, err
	}
	defer crypto.Wipe(key.Private)
	return SSHKeySummary{
		ScopeID:     record.ScopeID,
		Name:        strings.TrimPrefix(record.Name, "ssh:"),
		Algorithm:   string(key.Type),
		Fingerprint: key.Fingerprint(),
		Comment:     key.Comment,
	}, nil
}

func (s *Service) listSSHKeys(ctx context.Context, scopeID string) ([]SSHKeySummary, error) {
	if _, err := proto.ParseScopeID(scopeID); err != nil {
		return nil, fail("validation", "That vault reference is invalid.", "", false)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	records, err := session.ListTypedSecrets(scopeID, "")
	if err != nil {
		return nil, mapDomainError(err)
	}
	keys := make([]SSHKeySummary, 0)
	for _, record := range records {
		if !isSSHKeyType(record.Type) {
			continue
		}
		summary, err := sshKeySummary(record)
		if err != nil {
			continue
		}
		keys = append(keys, summary)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i].Name) < strings.ToLower(keys[j].Name)
	})
	return keys, nil
}

func requireSSHKeyReference(session *cli.Session, scopeID, name string) error {
	if name == "" {
		return nil
	}
	record, err := session.GetTypedSecret(scopeID, "ssh:"+name)
	if err != nil {
		if errors.Is(err, cli.ErrTypedSecretNotFound) {
			return fail(
				"ssh_key_missing",
				fmt.Sprintf("SSH key %q is not in this vault.", name),
				"Choose another key or use no fd0 key for this server.",
				false,
			)
		}
		return mapDomainError(err)
	}
	key, err := decodeSSHKey(*record)
	if err != nil {
		return err
	}
	crypto.Wipe(key.Private)
	return nil
}

func (s *Service) sshKeyEditData(ctx context.Context, ref RecordRef) (SaveSSHKeyParams, error) {
	if err := ref.Validate(); err != nil {
		return SaveSSHKeyParams{}, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return SaveSSHKeyParams{}, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(ref.ScopeID, ref.Name)
	if err != nil {
		return SaveSSHKeyParams{}, mapDomainError(err)
	}
	key, err := decodeSSHKey(*record)
	if err != nil {
		return SaveSSHKeyParams{}, err
	}
	defer crypto.Wipe(key.Private)
	return SaveSSHKeyParams{
		ScopeID: ref.ScopeID,
		Name:    strings.TrimPrefix(ref.Name, "ssh:"),
		Comment: key.Comment,
	}, nil
}

func (s *Service) saveSSHKey(ctx context.Context, params SaveSSHKeyParams) (map[string]bool, error) {
	params.Name = strings.TrimSpace(params.Name)
	params.Comment = strings.TrimSpace(params.Comment)
	if err := validateSSHKeyMetadata(params.Name, params.Comment); err != nil {
		return nil, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(params.ScopeID, "ssh:"+params.Name)
	if err != nil {
		return nil, mapDomainError(err)
	}
	key, err := decodeSSHKey(*record)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(key.Private)
	key.Comment = params.Comment
	if err := session.UpdateTypedSecret(
		ctx,
		params.ScopeID,
		record.Name,
		record.Type,
		string(key.Type),
		key.Marshal(),
	); err != nil {
		return nil, mapDomainError(err)
	}
	return map[string]bool{"ok": true}, nil
}

func sshKeyUsages(session *cli.Session, scopeID, keyName string) ([]ItemSummary, error) {
	records, err := session.ListTypedSecrets(scopeID, sshhost.TypeHost)
	if err != nil {
		return nil, err
	}
	items := make([]ItemSummary, 0)
	for _, record := range records {
		raw, err := record.PayloadJSON()
		if err != nil {
			continue
		}
		var wire sshhost.JSON
		if err := json.Unmarshal(raw, &wire); err != nil {
			continue
		}
		host, err := sshhost.Unmarshal(wire)
		if err != nil || host.KeyName != keyName {
			continue
		}
		summary, err := summarizeRecord(session, record)
		if err == nil {
			items = append(items, summary)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Title) < strings.ToLower(items[j].Title)
	})
	return items, nil
}
