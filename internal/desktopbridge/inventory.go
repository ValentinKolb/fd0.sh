package desktopbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

type ScopeSummary struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type InventoryResult struct {
	Scopes    []ScopeSummary `json:"scopes"`
	Items     []ItemSummary  `json:"items"`
	Counts    map[string]int `json:"counts"`
	Truncated bool           `json:"truncated,omitempty"`
}

const (
	inventoryResponseBudget = MaxFrameBytes * 3 / 4
	maxInventoryRecordName  = 512
	maxInventoryTextRunes   = 256
)

type ItemSummary struct {
	ID         string `json:"id"`
	ScopeID    string `json:"scopeId"`
	RecordName string `json:"recordName"`
	Kind       string `json:"kind"`
	Title      string `json:"title"`
	Subtitle   string `json:"subtitle,omitempty"`
	Vault      string `json:"vault"`
	Badge      string `json:"badge"`
	UpdatedAt  string `json:"updatedAt,omitempty"`
	Favorite   bool   `json:"favorite,omitempty"`
}

type RecordRef struct {
	ScopeID string `json:"scopeId"`
	Name    string `json:"name"`
	Raw     bool   `json:"raw,omitempty"`
}

func (r RecordRef) Validate() error {
	if _, err := proto.ParseScopeID(r.ScopeID); err != nil {
		return fail("validation", "That vault reference is invalid.", "", false)
	}
	if strings.TrimSpace(r.Name) == "" || strings.ContainsAny(r.Name, "\r\n\x00") {
		return fail("validation", "That item reference is invalid.", "", false)
	}
	return nil
}

type ItemDetail struct {
	Item   ItemSummary `json:"item"`
	Fields []FieldView `json:"fields"`
}

type FieldView struct {
	Name      string      `json:"name"`
	Path      string      `json:"path"`
	Type      string      `json:"type"`
	Section   string      `json:"section,omitempty"`
	Value     string      `json:"value,omitempty"`
	Sensitive bool        `json:"sensitive,omitempty"`
	Copyable  bool        `json:"copyable,omitempty"`
	Remaining int         `json:"remaining,omitempty"`
	File      *FileView   `json:"file,omitempty"`
	Children  []FieldView `json:"children,omitempty"`
}

type FileView struct {
	Name string `json:"name"`
	MIME string `json:"mime,omitempty"`
	Size int    `json:"size"`
}

type FieldValueParams struct {
	RecordRef
	Path string `json:"path"`
}

type FieldValueResult struct {
	Value     string `json:"value"`
	Remaining int    `json:"remaining,omitempty"`
}

type FieldAttachmentResult struct {
	Name string `json:"name"`
	MIME string `json:"mime,omitempty"`
	Data []byte `json:"data"`
}

func (r *FieldAttachmentResult) Wipe() {
	if r != nil {
		crypto.Wipe(r.Data)
	}
}

func (s *Service) listInventory(ctx context.Context) (InventoryResult, error) {
	session, err := cli.Open(ctx)
	if err != nil {
		return InventoryResult{}, mapDomainError(err)
	}
	defer session.Close()

	result := InventoryResult{
		Counts: map[string]int{"all": 0, "password": 0, "ssh": 0, "kubernetes": 0, "talos": 0, "secret": 0, "favorite": 0},
	}
	used := 1024
	for id, scope := range session.Body.Scopes {
		if scope.Leaving {
			continue
		}
		label := boundedInventoryText(strings.TrimSpace(scope.Label))
		if label == "" {
			label = "Unnamed vault"
		}
		candidate := ScopeSummary{ID: id, Label: label}
		size := encodedSize(candidate)
		if used+size > inventoryResponseBudget {
			result.Truncated = true
			continue
		}
		result.Scopes = append(result.Scopes, candidate)
		used += size
	}
	sort.Slice(result.Scopes, func(i, j int) bool {
		return strings.ToLower(result.Scopes[i].Label) < strings.ToLower(result.Scopes[j].Label)
	})

	records, err := session.ListTypedSecrets("", "")
	if err != nil {
		return InventoryResult{}, mapDomainError(err)
	}
	for _, record := range records {
		if !safeInventoryRecordName(record.Name) {
			result.Truncated = true
			continue
		}
		summary, err := summarizeRecord(session, record)
		if err != nil {
			continue
		}
		result.Counts["all"]++
		result.Counts[summary.Kind]++
		if summary.Favorite {
			result.Counts["favorite"]++
		}
		summary = boundItemSummary(summary)
		size := encodedSize(summary)
		if used+size > inventoryResponseBudget {
			result.Truncated = true
			continue
		}
		result.Items = append(result.Items, summary)
		used += size
	}
	sort.Slice(result.Items, func(i, j int) bool {
		left, right := strings.ToLower(result.Items[i].Title), strings.ToLower(result.Items[j].Title)
		if left == right {
			return result.Items[i].ID < result.Items[j].ID
		}
		return left < right
	})
	return result, nil
}

func safeInventoryRecordName(name string) bool {
	if len(name) == 0 || len(name) > maxInventoryRecordName {
		return false
	}
	return !strings.ContainsAny(name, "\r\n\x00")
}

func boundItemSummary(summary ItemSummary) ItemSummary {
	summary.Title = boundedInventoryText(summary.Title)
	summary.Subtitle = boundedInventoryText(summary.Subtitle)
	summary.Vault = boundedInventoryText(summary.Vault)
	summary.Badge = boundedInventoryText(summary.Badge)
	summary.UpdatedAt = boundedInventoryText(summary.UpdatedAt)
	return summary
}

func boundedInventoryText(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > maxInventoryTextRunes {
		return string(runes[:maxInventoryTextRunes])
	}
	return value
}

func encodedSize(value any) int {
	raw, err := json.Marshal(value)
	if err != nil {
		return inventoryResponseBudget
	}
	return len(raw)
}

func summarizeRecord(session *cli.Session, record cli.TypedRecord) (ItemSummary, error) {
	raw, err := record.PayloadJSON()
	if err != nil {
		return ItemSummary{}, err
	}
	vault := scopeLabel(session, record.ScopeID)
	summary := ItemSummary{
		ID:         recordID(record.ScopeID, record.Name),
		ScopeID:    record.ScopeID,
		RecordName: record.Name,
		Kind:       "secret",
		Title:      record.Name,
		Subtitle:   "General secret",
		Vault:      vault,
		Badge:      "SECRET",
	}
	switch record.Type {
	case passitem.TypePassItem:
		item, err := passitem.Decode(raw)
		if err != nil {
			return ItemSummary{}, err
		}
		summary.Kind = "password"
		summary.Title = item.Title
		summary.RecordName = record.Name
		summary.Subtitle = ""
		summary.Badge = "PASSWORD"
		if len(item.URLs) > 0 {
			summary.Subtitle = displayHost(item.URLs[0])
		}
		if username := passTextField(item.Fields, []string{"username", "email", "login", "user"}); username != "" {
			summary.Subtitle = username
		}
		summary.UpdatedAt = metaString(item.Meta, "updated_at")
		summary.Favorite = metaBool(item.Meta, "favorite")
	case sshhost.TypeHost:
		var wire sshhost.JSON
		if err := json.Unmarshal(raw, &wire); err != nil {
			return ItemSummary{}, err
		}
		host, err := sshhost.Unmarshal(wire)
		if err != nil {
			return ItemSummary{}, err
		}
		summary.Kind = "ssh"
		summary.Title = host.Alias
		summary.Subtitle = host.Hostname
		if host.User != "" {
			summary.Subtitle = host.User + "@" + host.Hostname
		}
		summary.Badge = "SSH HOST"
	case string(sshkey.TypeEd25519), string(sshkey.TypeRSA), string(sshkey.TypeECDSA):
		var wire sshkey.JSON
		if err := json.Unmarshal(raw, &wire); err != nil {
			return ItemSummary{}, err
		}
		summary.Kind = "ssh"
		summary.Title = strings.TrimPrefix(record.Name, "ssh:")
		summary.Subtitle = wire.Comment
		summary.Badge = "SSH KEY"
	case kubeconfig.TypeKubeconfig:
		entry, err := kubeconfig.Unmarshal(raw)
		if err != nil {
			return ItemSummary{}, err
		}
		summary.Kind = "kubernetes"
		summary.Title = entry.Name
		summary.Subtitle = entry.Server
		summary.Badge = "KUBE"
	case talosctx.TypeTalosContext:
		entry, err := talosctx.Unmarshal(raw)
		if err != nil {
			return ItemSummary{}, err
		}
		summary.Kind = "talos"
		summary.Title = entry.Name
		summary.Subtitle = strings.Join(entry.Endpoints, ", ")
		summary.Badge = "TALOS"
	}
	return summary, nil
}

func (s *Service) itemDetail(ctx context.Context, ref RecordRef) (ItemDetail, error) {
	if err := ref.Validate(); err != nil {
		return ItemDetail{}, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return ItemDetail{}, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(ref.ScopeID, ref.Name)
	if err != nil {
		return ItemDetail{}, mapDomainError(err)
	}
	summary, err := summarizeRecord(session, *record)
	if err != nil {
		return ItemDetail{}, err
	}
	fields, err := detailFields(*record, ref.Raw)
	if err != nil {
		return ItemDetail{}, err
	}
	return ItemDetail{Item: summary, Fields: fields}, nil
}

func detailFields(record cli.TypedRecord, rawMode bool) ([]FieldView, error) {
	raw, err := record.PayloadJSON()
	if err != nil {
		return nil, err
	}
	if rawMode {
		return []FieldView{{Name: "Raw decrypted value", Path: "$raw", Type: "raw", Sensitive: true, Copyable: true}}, nil
	}
	switch record.Type {
	case passitem.TypePassItem:
		item, err := passitem.Decode(raw)
		if err != nil {
			return nil, err
		}
		fields := make([]FieldView, 0, len(item.Fields)+1)
		if len(item.URLs) > 0 {
			fields = append(fields, FieldView{Name: "Website", Path: "$url", Type: "url", Value: item.URLs[0], Copyable: true, Section: "Login"})
		}
		fields = append(fields, passFieldViews(item.Fields, "", "Login")...)
		return fields, nil
	case sshhost.TypeHost:
		var wire sshhost.JSON
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, err
		}
		host, err := sshhost.Unmarshal(wire)
		if err != nil {
			return nil, err
		}
		fields := []FieldView{
			textField("Host", "host", host.Hostname, "Connection"),
			textField("User", "user", host.User, "Connection"),
			textField("Port", "port", strconv.Itoa(defaultPort(host.Port)), "Connection"),
			textField("Key", "key", host.KeyName, "Authentication"),
		}
		if host.ProxyJump != "" {
			fields = append(fields, textField("Proxy jump", "proxyJump", host.ProxyJump, "Connection"))
		}
		if host.Description != "" {
			fields = append(fields, textField("Notes", "description", host.Description, "Details"))
		}
		return fields, nil
	case string(sshkey.TypeEd25519), string(sshkey.TypeRSA), string(sshkey.TypeECDSA):
		var wire sshkey.JSON
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, err
		}
		return []FieldView{
			textField("Algorithm", "algorithm", wire.Type, "SSH key"),
			textField("Public key", "public", wire.Pub, "SSH key"),
			{Name: "Private key", Path: "private", Type: "secret", Sensitive: true, Copyable: true, Section: "SSH key"},
			textField("Comment", "comment", wire.Comment, "Details"),
		}, nil
	case kubeconfig.TypeKubeconfig:
		entry, err := kubeconfig.Unmarshal(raw)
		if err != nil {
			return nil, err
		}
		return []FieldView{
			textField("Server", "server", entry.Server, "Cluster"),
			textField("Namespace", "namespace", entry.Namespace, "Cluster"),
			{Name: "CA certificate", Path: "ca", Type: "secret", Sensitive: true, Copyable: true, Section: "Credentials"},
			{Name: "Client certificate", Path: "clientCert", Type: "secret", Sensitive: true, Copyable: true, Section: "Credentials"},
			{Name: "Client key", Path: "clientKey", Type: "secret", Sensitive: true, Copyable: true, Section: "Credentials"},
			{Name: "Token", Path: "token", Type: "secret", Sensitive: true, Copyable: true, Section: "Credentials"},
		}, nil
	case talosctx.TypeTalosContext:
		entry, err := talosctx.Unmarshal(raw)
		if err != nil {
			return nil, err
		}
		return []FieldView{
			textField("Endpoints", "endpoints", strings.Join(entry.Endpoints, ", "), "Cluster"),
			textField("Nodes", "nodes", strings.Join(entry.Nodes, ", "), "Cluster"),
			textField("Role", "role", entry.Role, "Cluster"),
			{Name: "CA certificate", Path: "ca", Type: "secret", Sensitive: true, Copyable: true, Section: "Credentials"},
			{Name: "Client certificate", Path: "certificate", Type: "secret", Sensitive: true, Copyable: true, Section: "Credentials"},
			{Name: "Client key", Path: "key", Type: "secret", Sensitive: true, Copyable: true, Section: "Credentials"},
		}, nil
	default:
		return []FieldView{{Name: "Value", Path: "value", Type: "secret", Sensitive: true, Copyable: true, Section: "Secret"}}, nil
	}
}

func passFieldViews(fields []passitem.Field, prefix, section string) []FieldView {
	views := make([]FieldView, 0, len(fields))
	for _, field := range fields {
		path := field.Name
		if prefix != "" {
			path = prefix + "/" + field.Name
		}
		view := FieldView{Name: field.Name, Path: path, Type: field.Type, Section: section}
		switch field.Type {
		case passitem.FieldSection:
			views = append(views, passFieldViews(field.Fields, path, field.Name)...)
			continue
		case passitem.FieldText:
			view.Value, _ = passitem.StringValue(field)
			view.Copyable = true
		case passitem.FieldSecret:
			view.Sensitive = true
			view.Copyable = true
		case passitem.FieldTOTP:
			if value, err := passitem.TOTPFromField(field); err == nil {
				view.Value, view.Remaining, _ = passitem.TOTPCode(value, time.Now())
				view.Copyable = true
			}
		case passitem.FieldFile:
			if value, err := passitem.FileFromField(field); err == nil {
				view.File = &FileView{Name: value.Name, MIME: value.MIME, Size: value.Size}
			}
		case passitem.FieldPasskey:
			view.Value = "Saved passkey data"
		}
		views = append(views, view)
	}
	return views
}

func (s *Service) fieldValue(ctx context.Context, params FieldValueParams) (FieldValueResult, error) {
	if err := params.RecordRef.Validate(); err != nil {
		return FieldValueResult{}, err
	}
	if strings.TrimSpace(params.Path) == "" {
		return FieldValueResult{}, fail("validation", "Field path is required.", "", false)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return FieldValueResult{}, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(params.ScopeID, params.Name)
	if err != nil {
		return FieldValueResult{}, mapDomainError(err)
	}
	raw, err := record.PayloadJSON()
	if err != nil {
		return FieldValueResult{}, err
	}
	if params.Path == "$raw" {
		if json.Valid(raw) {
			var formatted json.RawMessage
			if err := json.Unmarshal(raw, &formatted); err == nil {
				if pretty, err := json.MarshalIndent(formatted, "", "  "); err == nil {
					return FieldValueResult{Value: string(pretty)}, nil
				}
			}
		}
		return FieldValueResult{Value: string(raw)}, nil
	}
	switch record.Type {
	case passitem.TypePassItem:
		item, err := passitem.Decode(raw)
		if err != nil {
			return FieldValueResult{}, err
		}
		if params.Path == "$url" && len(item.URLs) > 0 {
			return FieldValueResult{Value: item.URLs[0]}, nil
		}
		field, err := item.Field(params.Path)
		if err != nil {
			return FieldValueResult{}, fail("not_found", "That field no longer exists.", "Refresh the item.", false)
		}
		switch field.Type {
		case passitem.FieldText, passitem.FieldSecret:
			value, err := passitem.StringValue(*field)
			return FieldValueResult{Value: value}, err
		case passitem.FieldTOTP:
			value, err := passitem.TOTPFromField(*field)
			if err != nil {
				return FieldValueResult{}, err
			}
			code, remaining, err := passitem.TOTPCode(value, time.Now())
			return FieldValueResult{Value: code, Remaining: remaining}, err
		default:
			return FieldValueResult{}, fail("unsupported", "That field cannot be copied as text.", "", false)
		}
	case string(sshkey.TypeEd25519), string(sshkey.TypeRSA), string(sshkey.TypeECDSA):
		var wire sshkey.JSON
		if err := json.Unmarshal(raw, &wire); err != nil {
			return FieldValueResult{}, err
		}
		switch params.Path {
		case "private":
			return FieldValueResult{Value: wire.Priv}, nil
		case "public":
			return FieldValueResult{Value: wire.Pub}, nil
		}
	case kubeconfig.TypeKubeconfig:
		entry, err := kubeconfig.Unmarshal(raw)
		if err != nil {
			return FieldValueResult{}, err
		}
		values := map[string]string{"ca": entry.CA, "clientCert": entry.ClientCert, "clientKey": entry.ClientKey, "token": entry.Token}
		if value, ok := values[params.Path]; ok {
			return FieldValueResult{Value: value}, nil
		}
	case talosctx.TypeTalosContext:
		entry, err := talosctx.Unmarshal(raw)
		if err != nil {
			return FieldValueResult{}, err
		}
		values := map[string]string{"ca": entry.CA, "certificate": entry.Crt, "key": entry.Key}
		if value, ok := values[params.Path]; ok {
			return FieldValueResult{Value: value}, nil
		}
	default:
		if params.Path == "value" {
			return FieldValueResult{Value: string(raw)}, nil
		}
	}
	return FieldValueResult{}, fail("not_found", "That field no longer exists.", "Refresh the item.", false)
}

func (s *Service) fieldAttachment(ctx context.Context, params FieldValueParams) (*FieldAttachmentResult, error) {
	if err := params.RecordRef.Validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(params.Path) == "" {
		return nil, fail("validation", "File field path is required.", "", false)
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	record, err := session.GetTypedSecret(params.ScopeID, params.Name)
	if err != nil {
		return nil, mapDomainError(err)
	}
	if record.Type != passitem.TypePassItem {
		return nil, fail("unsupported", "Only password item attachments can be saved here.", "", false)
	}
	raw, err := record.PayloadJSON()
	if err != nil {
		return nil, err
	}
	item, err := passitem.Decode(raw)
	if err != nil {
		return nil, err
	}
	field, err := item.Field(params.Path)
	if err != nil || field.Type != passitem.FieldFile {
		return nil, fail("not_found", "That file no longer exists.", "Refresh the item.", false)
	}
	value, err := passitem.FileFromField(*field)
	if err != nil {
		return nil, err
	}
	data, err := passitem.DecodeFileData(value)
	if err != nil {
		return nil, fail("invalid_record", "fd0 could not verify this attachment.", "Open Support before replacing it.", false)
	}
	return &FieldAttachmentResult{Name: value.Name, MIME: value.MIME, Data: data}, nil
}

func recordID(scopeID, name string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(scopeID + "\x00" + name))
}

func scopeLabel(session *cli.Session, scopeID string) string {
	label := strings.TrimSpace(session.Body.Scopes[scopeID].Label)
	if label == "" {
		return "Unnamed vault"
	}
	return label
}

func textField(name, path, value, section string) FieldView {
	return FieldView{Name: name, Path: path, Type: "text", Value: value, Copyable: value != "", Section: section}
}

func defaultPort(port int) int {
	if port == 0 {
		return 22
	}
	return port
}

func displayHost(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if slash := strings.IndexByte(raw, '/'); slash >= 0 {
		raw = raw[:slash]
	}
	return raw
}

func passTextField(fields []passitem.Field, names []string) string {
	for _, wanted := range names {
		for _, field := range fields {
			if field.Type == passitem.FieldSection {
				if value := passTextField(field.Fields, []string{wanted}); value != "" {
					return value
				}
			}
			if field.Type == passitem.FieldText && strings.EqualFold(field.Name, wanted) {
				value, _ := passitem.StringValue(field)
				return value
			}
		}
	}
	return ""
}

func metaString(meta map[string]any, key string) string {
	if value, ok := meta[key].(string); ok {
		return value
	}
	return ""
}

func metaBool(meta map[string]any, key string) bool {
	value, _ := meta[key].(bool)
	return value
}
