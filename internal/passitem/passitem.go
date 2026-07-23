package passitem

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	TypePassItem = "fd0.pass.item"

	FieldText    = "text"
	FieldSecret  = "secret"
	FieldTOTP    = "totp"
	FieldPasskey = "passkey"
	FieldFile    = "file"
	FieldSection = "section"

	MaxDepth      = 4
	MaxFields     = 128
	MaxNameLen    = 128
	MaxValueBytes = 32 * 1024
	MaxFileBytes  = 32 * 1024
	MaxItemBytes  = 60 * 1024
	DefaultDigits = 6
	DefaultPeriod = 30
	DefaultAlgo   = "SHA1"
)

type Item struct {
	Title  string         `json:"title"`
	URLs   []string       `json:"urls,omitempty"`
	Fields []Field        `json:"fields,omitempty"`
	Meta   map[string]any `json:"meta,omitempty"`
}

type Field struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Value  json.RawMessage `json:"value,omitempty"`
	Fields []Field         `json:"fields,omitempty"`
	Meta   map[string]any  `json:"meta,omitempty"`
}

type TOTPValue struct {
	Secret    string `json:"secret"`
	Issuer    string `json:"issuer,omitempty"`
	Account   string `json:"account,omitempty"`
	Digits    int    `json:"digits,omitempty"`
	Period    int    `json:"period,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

type FileValue struct {
	Name   string `json:"name"`
	MIME   string `json:"mime,omitempty"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
	Data   string `json:"data_b64"`
}

func New(title string, urls []string) *Item {
	now := time.Now().UTC().Format(time.RFC3339)
	return &Item{
		Title: strings.TrimSpace(title),
		URLs:  cleanURLs(urls),
		Meta: map[string]any{
			"created_at": now,
			"updated_at": now,
			"revision":   1,
		},
	}
}

func Decode(raw []byte) (*Item, error) {
	var item Item
	if err := json.Unmarshal(raw, &item); err != nil {
		return nil, fmt.Errorf("pass item: json: %w", err)
	}
	if err := item.Validate(); err != nil {
		return nil, err
	}
	return &item, nil
}

func (i *Item) Marshal() any {
	return i
}

func (i *Item) Touch() {
	if i.Meta == nil {
		i.Meta = map[string]any{}
	}
	i.Meta["updated_at"] = time.Now().UTC().Format(time.RFC3339)
	if rev, ok := i.Meta["revision"].(float64); ok {
		i.Meta["revision"] = int(rev) + 1
		return
	}
	if rev, ok := i.Meta["revision"].(int); ok {
		i.Meta["revision"] = rev + 1
		return
	}
	i.Meta["revision"] = 1
}

func (i *Item) Validate() error {
	i.Title = strings.TrimSpace(i.Title)
	if i.Title == "" {
		return errors.New("pass item: title required")
	}
	i.URLs = cleanURLs(i.URLs)
	total, err := validateFields(i.Fields, 0)
	if err != nil {
		return err
	}
	if total > MaxFields {
		return fmt.Errorf("pass item: too many fields (%d > %d)", total, MaxFields)
	}
	raw, err := json.Marshal(i)
	if err != nil {
		return fmt.Errorf("pass item: marshal: %w", err)
	}
	if len(raw) > MaxItemBytes {
		return fmt.Errorf("pass item: too large (%d bytes > %d)", len(raw), MaxItemBytes)
	}
	return nil
}

func (i *Item) AddSection(path string) error {
	parent, leaf, err := i.parentFor(path, true)
	if err != nil {
		return err
	}
	if findIndex(*parent, leaf) >= 0 {
		return fmt.Errorf("field %q already exists", path)
	}
	*parent = append(*parent, Field{Type: FieldSection, Name: leaf})
	sortFields(*parent)
	i.Touch()
	return i.Validate()
}

func (i *Item) SetField(path string, field Field) error {
	if field.Type == "" {
		field.Type = FieldText
	}
	parent, leaf, err := i.parentFor(path, true)
	if err != nil {
		return err
	}
	field.Name = leaf
	idx := findIndex(*parent, leaf)
	if idx >= 0 {
		(*parent)[idx] = field
	} else {
		*parent = append(*parent, field)
	}
	sortFields(*parent)
	i.Touch()
	return i.Validate()
}

func (i *Item) RemoveField(path string) error {
	parent, leaf, err := i.parentFor(path, false)
	if err != nil {
		return err
	}
	idx := findIndex(*parent, leaf)
	if idx < 0 {
		return fmt.Errorf("field %q not found", path)
	}
	*parent = append((*parent)[:idx], (*parent)[idx+1:]...)
	i.Touch()
	return i.Validate()
}

func (i *Item) Field(path string) (*Field, error) {
	parts, err := splitPath(path)
	if err != nil {
		return nil, err
	}
	fields := i.Fields
	for idx, part := range parts {
		pos := findIndex(fields, part)
		if pos < 0 {
			return nil, fmt.Errorf("field %q not found", path)
		}
		f := &fields[pos]
		if idx == len(parts)-1 {
			return f, nil
		}
		if f.Type != FieldSection {
			return nil, fmt.Errorf("field %q is not a section", strings.Join(parts[:idx+1], "/"))
		}
		fields = f.Fields
	}
	return nil, fmt.Errorf("field %q not found", path)
}

func (i *Item) parentFor(path string, create bool) (*[]Field, string, error) {
	parts, err := splitPath(path)
	if err != nil {
		return nil, "", err
	}
	fields := &i.Fields
	for idx, part := range parts[:len(parts)-1] {
		pos := findIndex(*fields, part)
		if pos < 0 {
			if !create {
				return nil, "", fmt.Errorf("section %q not found", strings.Join(parts[:idx+1], "/"))
			}
			*fields = append(*fields, Field{Type: FieldSection, Name: part})
			sortFields(*fields)
			pos = findIndex(*fields, part)
		}
		if (*fields)[pos].Type != FieldSection {
			return nil, "", fmt.Errorf("field %q is not a section", strings.Join(parts[:idx+1], "/"))
		}
		fields = &(*fields)[pos].Fields
	}
	return fields, parts[len(parts)-1], nil
}

func NewStringField(kind, value string) (Field, error) {
	if kind != FieldText && kind != FieldSecret {
		return Field{}, fmt.Errorf("string field kind %q", kind)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return Field{}, err
	}
	return Field{Type: kind, Value: raw}, nil
}

func NewTOTPField(v TOTPValue) (Field, error) {
	v = NormalizeTOTP(v)
	if err := ValidateTOTP(v); err != nil {
		return Field{}, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Field{}, err
	}
	return Field{Type: FieldTOTP, Value: raw}, nil
}

func NewFileField(name, mime string, data []byte) (Field, error) {
	if len(data) > MaxFileBytes {
		return Field{}, fmt.Errorf("file too large (%d bytes > %d)", len(data), MaxFileBytes)
	}
	name, err := SafeFileName(filepath.Base(name))
	if err != nil {
		return Field{}, err
	}
	sum := sha256.Sum256(data)
	v := FileValue{
		Name:   name,
		MIME:   mime,
		Size:   len(data),
		SHA256: fmt.Sprintf("%x", sum[:]),
		Data:   base64.StdEncoding.EncodeToString(data),
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Field{}, err
	}
	return Field{Type: FieldFile, Value: raw}, nil
}

// SafeFileName validates synchronized attachment display metadata before it is
// used as a local filename. Explicit export destinations are validated
// separately because they are trusted local user input.
func SafeFileName(name string) (string, error) {
	if name == "" || name != strings.TrimSpace(name) {
		return "", errors.New("attachment file name must be a non-empty basename without surrounding whitespace")
	}
	if name == "." || name == ".." || filepath.IsAbs(name) ||
		strings.ContainsAny(name, `/\`) || filepath.Base(name) != name {
		return "", fmt.Errorf("attachment file name %q must be a basename without path separators", name)
	}
	for i, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("attachment file name %q contains control char at offset %d", name, i)
		}
	}
	return name, nil
}

func NewRawJSONField(kind string, raw []byte) (Field, error) {
	if !json.Valid(raw) {
		return Field{}, errors.New("value is not valid JSON")
	}
	return Field{Type: kind, Value: append([]byte(nil), raw...)}, nil
}

func StringValue(f Field) (string, error) {
	if f.Type != FieldText && f.Type != FieldSecret {
		return "", fmt.Errorf("field %q is %s, not text/secret", f.Name, f.Type)
	}
	var s string
	if err := json.Unmarshal(f.Value, &s); err != nil {
		return "", err
	}
	return s, nil
}

func TOTPFromField(f Field) (TOTPValue, error) {
	if f.Type != FieldTOTP {
		return TOTPValue{}, fmt.Errorf("field %q is %s, not totp", f.Name, f.Type)
	}
	var v TOTPValue
	if err := json.Unmarshal(f.Value, &v); err != nil {
		return TOTPValue{}, err
	}
	v = NormalizeTOTP(v)
	return v, ValidateTOTP(v)
}

func FileFromField(f Field) (FileValue, error) {
	if f.Type != FieldFile {
		return FileValue{}, fmt.Errorf("field %q is %s, not file", f.Name, f.Type)
	}
	var v FileValue
	if err := json.Unmarshal(f.Value, &v); err != nil {
		return FileValue{}, err
	}
	return v, nil
}

func DecodeFileData(v FileValue) ([]byte, error) {
	name := strings.TrimSpace(v.Name)
	if name == "" {
		return nil, errors.New("file name required")
	}
	if v.Size < 0 || v.Size > MaxFileBytes {
		return nil, fmt.Errorf("file %q size out of range (%d bytes)", name, v.Size)
	}
	data, err := base64.StdEncoding.DecodeString(v.Data)
	if err != nil {
		return nil, fmt.Errorf("file %q data: %w", name, err)
	}
	if len(data) != v.Size {
		return nil, fmt.Errorf("file %q size mismatch (%d bytes, metadata says %d)", name, len(data), v.Size)
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(v.SHA256, fmt.Sprintf("%x", sum[:])) {
		return nil, fmt.Errorf("file %q sha256 mismatch", name)
	}
	return data, nil
}

func ParseTOTPURI(raw string) (TOTPValue, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return TOTPValue{}, err
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		return TOTPValue{}, errors.New("expected otpauth://totp/... URI")
	}
	q := u.Query()
	v := TOTPValue{
		Secret:    q.Get("secret"),
		Issuer:    q.Get("issuer"),
		Digits:    atoiDefault(q.Get("digits"), DefaultDigits),
		Period:    atoiDefault(q.Get("period"), DefaultPeriod),
		Algorithm: q.Get("algorithm"),
	}
	label, _ := url.PathUnescape(strings.TrimPrefix(u.Path, "/"))
	if label != "" {
		if before, after, ok := strings.Cut(label, ":"); ok {
			if v.Issuer == "" {
				v.Issuer = before
			}
			v.Account = after
		} else {
			v.Account = label
		}
	}
	return NormalizeTOTP(v), nil
}

func NormalizeTOTP(v TOTPValue) TOTPValue {
	v.Secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(v.Secret), " ", ""))
	if v.Digits == 0 {
		v.Digits = DefaultDigits
	}
	if v.Period == 0 {
		v.Period = DefaultPeriod
	}
	if v.Algorithm == "" {
		v.Algorithm = DefaultAlgo
	}
	v.Algorithm = strings.ToUpper(v.Algorithm)
	return v
}

func ValidateTOTP(v TOTPValue) error {
	if v.Secret == "" {
		return errors.New("totp secret required")
	}
	if _, err := decodeBase32(v.Secret); err != nil {
		return fmt.Errorf("totp secret: %w", err)
	}
	if v.Digits < 6 || v.Digits > 8 {
		return fmt.Errorf("totp digits must be 6..8")
	}
	if v.Period < 10 || v.Period > 300 {
		return fmt.Errorf("totp period must be 10..300 seconds")
	}
	switch v.Algorithm {
	case "SHA1", "SHA256", "SHA512":
		return nil
	default:
		return fmt.Errorf("unsupported totp algorithm %q", v.Algorithm)
	}
}

func TOTPCode(v TOTPValue, t time.Time) (string, int, error) {
	v = NormalizeTOTP(v)
	if err := ValidateTOTP(v); err != nil {
		return "", 0, err
	}
	key, err := decodeBase32(v.Secret)
	if err != nil {
		return "", 0, err
	}
	counter := uint64(t.Unix() / int64(v.Period))
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	var h func() hash.Hash
	switch v.Algorithm {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}
	mac := hmac.New(h, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 |
		(uint32(sum[off+1])&0xff)<<16 |
		(uint32(sum[off+2])&0xff)<<8 |
		(uint32(sum[off+3]) & 0xff)
	mod := uint32(1)
	for i := 0; i < v.Digits; i++ {
		mod *= 10
	}
	code := fmt.Sprintf("%0*d", v.Digits, bin%mod)
	remaining := v.Period - int(t.Unix()%int64(v.Period))
	return code, remaining, nil
}

func FieldValueSummary(f Field, reveal bool) string {
	switch f.Type {
	case FieldSection:
		return fmt.Sprintf("%d fields", len(f.Fields))
	case FieldText:
		s, err := StringValue(f)
		if err != nil {
			return "(invalid text)"
		}
		return s
	case FieldSecret:
		s, err := StringValue(f)
		if err != nil {
			return "(invalid secret)"
		}
		if reveal {
			return s
		}
		if s == "" {
			return "(empty)"
		}
		return strings.Repeat("•", min(len([]rune(s)), 32))
	case FieldTOTP:
		v, err := TOTPFromField(f)
		if err != nil {
			return "(invalid totp)"
		}
		if v.Issuer != "" || v.Account != "" {
			return strings.Trim(strings.TrimSpace(v.Issuer+" / "+v.Account), "/ ")
		}
		return "totp"
	case FieldPasskey:
		return "passkey"
	case FieldFile:
		v, err := FileFromField(f)
		if err != nil {
			return "(invalid file)"
		}
		return fmt.Sprintf("%s (%d bytes)", v.Name, v.Size)
	default:
		return "(unknown)"
	}
}

func splitPath(path string) ([]string, error) {
	path = strings.Trim(path, "/ ")
	if path == "" {
		return nil, errors.New("field path required")
	}
	parts := strings.Split(path, "/")
	if len(parts) > MaxDepth {
		return nil, fmt.Errorf("field path too deep (%d > %d)", len(parts), MaxDepth)
	}
	for _, p := range parts {
		if err := validateName(p); err != nil {
			return nil, err
		}
	}
	return parts, nil
}

func validateFields(fields []Field, depth int) (int, error) {
	if depth > MaxDepth {
		return 0, fmt.Errorf("sections too deep (%d > %d)", depth, MaxDepth)
	}
	seen := map[string]bool{}
	total := 0
	for idx := range fields {
		f := &fields[idx]
		f.Name = strings.TrimSpace(f.Name)
		if err := validateName(f.Name); err != nil {
			return 0, err
		}
		if seen[f.Name] {
			return 0, fmt.Errorf("duplicate field %q", f.Name)
		}
		seen[f.Name] = true
		if !validFieldType(f.Type) {
			return 0, fmt.Errorf("field %q: unsupported type %q", f.Name, f.Type)
		}
		total++
		if f.Type == FieldSection {
			n, err := validateFields(f.Fields, depth+1)
			if err != nil {
				return 0, err
			}
			total += n
			if len(f.Value) != 0 {
				return 0, fmt.Errorf("section %q must not carry value", f.Name)
			}
			continue
		}
		if len(f.Fields) != 0 {
			return 0, fmt.Errorf("field %q: only sections can have child fields", f.Name)
		}
		if len(f.Value) > MaxValueBytes {
			return 0, fmt.Errorf("field %q too large (%d bytes > %d)", f.Name, len(f.Value), MaxValueBytes)
		}
		if len(f.Value) == 0 {
			return 0, fmt.Errorf("field %q: value required", f.Name)
		}
		switch f.Type {
		case FieldText, FieldSecret:
			if _, err := StringValue(*f); err != nil {
				return 0, fmt.Errorf("field %q: %w", f.Name, err)
			}
		case FieldTOTP:
			if _, err := TOTPFromField(*f); err != nil {
				return 0, fmt.Errorf("field %q: %w", f.Name, err)
			}
		case FieldFile:
			v, err := FileFromField(*f)
			if err != nil {
				return 0, fmt.Errorf("field %q: %w", f.Name, err)
			}
			if _, err := DecodeFileData(v); err != nil {
				return 0, fmt.Errorf("field %q: %w", f.Name, err)
			}
		case FieldPasskey:
			if !json.Valid(f.Value) {
				return 0, fmt.Errorf("field %q: invalid passkey JSON", f.Name)
			}
		}
	}
	return total, nil
}

func validateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("field name required")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("field name %q too long", name)
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("field name %q must not contain /", name)
	}
	return nil
}

func validFieldType(t string) bool {
	switch t {
	case FieldText, FieldSecret, FieldTOTP, FieldPasskey, FieldFile, FieldSection:
		return true
	default:
		return false
	}
}

func findIndex(fields []Field, name string) int {
	for i := range fields {
		if fields[i].Name == name {
			return i
		}
	}
	return -1
}

func sortFields(fields []Field) {
	sort.SliceStable(fields, func(i, j int) bool {
		if fields[i].Type == FieldSection && fields[j].Type != FieldSection {
			return false
		}
		if fields[i].Type != FieldSection && fields[j].Type == FieldSection {
			return true
		}
		return fields[i].Name < fields[j].Name
	})
}

func cleanURLs(urls []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

func decodeBase32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(s, "="))
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil || n == 0 {
		return def
	}
	return n
}
