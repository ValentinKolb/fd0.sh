package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/valentinkolb/fd0.sh/internal/passitem"
)

// BrowserCredential is safe metadata for a pass item that can fill a web login.
// Secret values are returned only by RevealBrowserCredential after the origin is
// checked again.
type BrowserCredential struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Username string `json:"username,omitempty"`
	Revision string `json:"revision"`
	HasTOTP  bool   `json:"hasTotp,omitempty"`
	ScopeID  string `json:"scopeId"`
	Scope    string `json:"scope"`
}

// BrowserCredentialSecret is the smallest value set needed by the first
// browser integration slice.
type BrowserCredentialSecret struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
	HasTOTP  bool   `json:"hasTotp,omitempty"`
}

type BrowserScope struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type BrowserTOTPCode struct {
	Code      string `json:"code"`
	Remaining int    `json:"remaining"`
	Period    int    `json:"period"`
}

type BrowserSaveLoginInput struct {
	Origin   string
	ScopeID  string
	Title    string
	Username string
	Password string
}

type BrowserUpdateLoginInput struct {
	Origin       string
	CredentialID string
	Revision     string
	Title        string
	Username     string
	Password     string
}

// BrowserCredentialsForOrigin returns metadata for login items whose stored
// HTTPS URL covers origin. It never returns field values.
func BrowserCredentialsForOrigin(ctx context.Context, origin string) ([]BrowserCredential, error) {
	target, err := parseBrowserTarget(origin)
	if err != nil {
		return nil, err
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	rows, err := s.ListTypedSecrets("", passitem.TypePassItem)
	if err != nil {
		return nil, err
	}
	matches := make([]BrowserCredential, 0)
	for _, row := range rows {
		item, err := decodePassRecord(row)
		if err != nil || !browserItemMatches(item, target) {
			continue
		}
		if _, ok := browserPassword(item); !ok {
			continue
		}
		username, _ := browserUsername(item)
		matches = append(matches, BrowserCredential{
			ID:       encodeBrowserCredentialID(row.ScopeID, row.Name),
			Title:    item.Title,
			Username: username,
			Revision: browserRevision(item),
			HasTOTP:  browserTOTP(item) != nil,
			ScopeID:  row.ScopeID,
			Scope:    scopeLabelOf(s, row.ScopeID),
		})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		left := strings.ToLower(matches[i].Title + "\x00" + matches[i].Username)
		right := strings.ToLower(matches[j].Title + "\x00" + matches[j].Username)
		return left < right
	})
	return matches, nil
}

// RevealBrowserCredential resolves one opaque credential reference and repeats
// the origin check before returning a username or password.
func RevealBrowserCredential(ctx context.Context, origin, credentialID string) (BrowserCredentialSecret, error) {
	target, err := parseBrowserTarget(origin)
	if err != nil {
		return BrowserCredentialSecret{}, err
	}
	scopeID, name, err := decodeBrowserCredentialID(credentialID)
	if err != nil {
		return BrowserCredentialSecret{}, err
	}
	s, err := Open(ctx)
	if err != nil {
		return BrowserCredentialSecret{}, err
	}
	defer s.Close()

	row, err := s.GetTypedSecret(scopeID, name)
	if err != nil {
		return BrowserCredentialSecret{}, err
	}
	if row.Type != passitem.TypePassItem {
		return BrowserCredentialSecret{}, errors.New("browser credential is not a pass item")
	}
	item, err := decodePassRecord(*row)
	if err != nil {
		return BrowserCredentialSecret{}, err
	}
	if !browserItemMatches(item, target) {
		return BrowserCredentialSecret{}, errors.New("browser credential does not match this origin")
	}
	password, ok := browserPassword(item)
	if !ok {
		return BrowserCredentialSecret{}, errors.New("browser credential has no password field")
	}
	username, _ := browserUsername(item)
	return BrowserCredentialSecret{
		Username: username,
		Password: password,
		HasTOTP:  browserTOTP(item) != nil,
	}, nil
}

// BrowserScopes returns the writable vault choices shown by the browser save UI.
func BrowserScopes(ctx context.Context) ([]BrowserScope, error) {
	s, err := Open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	scopes := make([]BrowserScope, 0, len(s.Body.Scopes))
	for id, scope := range s.Body.Scopes {
		if scope.Leaving {
			continue
		}
		label := strings.TrimSpace(scope.Label)
		if label == "" {
			label = shortScopeID(id)
		}
		scopes = append(scopes, BrowserScope{ID: id, Label: label})
	}
	sort.Slice(scopes, func(i, j int) bool {
		left := strings.ToLower(scopes[i].Label + "\x00" + scopes[i].ID)
		right := strings.ToLower(scopes[j].Label + "\x00" + scopes[j].ID)
		return left < right
	})
	return scopes, nil
}

// BrowserTOTPForCredential returns a fresh code only after repeating the
// credential's origin check. The extension never receives the TOTP seed.
func BrowserTOTPForCredential(ctx context.Context, origin, credentialID string) (BrowserTOTPCode, error) {
	_, item, closeSession, err := openBrowserCredential(ctx, origin, credentialID)
	if err != nil {
		return BrowserTOTPCode{}, err
	}
	defer closeSession()
	field := browserTOTP(item)
	if field == nil {
		return BrowserTOTPCode{}, errors.New("browser credential has no TOTP field")
	}
	value, err := passitem.TOTPFromField(*field)
	if err != nil {
		return BrowserTOTPCode{}, err
	}
	code, remaining, err := passitem.TOTPCode(value, time.Now())
	if err != nil {
		return BrowserTOTPCode{}, err
	}
	return BrowserTOTPCode{Code: code, Remaining: remaining, Period: value.Period}, nil
}

// SaveBrowserLogin creates a new pass item after an explicit browser prompt.
func SaveBrowserLogin(ctx context.Context, input BrowserSaveLoginInput) (BrowserCredential, error) {
	target, err := parseBrowserTarget(input.Origin)
	if err != nil {
		return BrowserCredential{}, err
	}
	if err := validateBrowserLoginInput(input.Title, input.Username, input.Password); err != nil {
		return BrowserCredential{}, err
	}
	s, err := Open(ctx)
	if err != nil {
		return BrowserCredential{}, err
	}
	defer s.Close()
	scopeID, err := s.resolveScopeID(strings.TrimSpace(input.ScopeID))
	if err != nil {
		return BrowserCredential{}, err
	}
	item := passitem.New(input.Title, []string{browserTargetURL(target)})
	if err := setBrowserLoginFields(item, input.Username, input.Password); err != nil {
		return BrowserCredential{}, err
	}
	baseName := browserPassName(input.Title, target.host)
	name := baseName
	for suffix := 1; suffix <= 100; suffix++ {
		if suffix > 1 {
			name = fmt.Sprintf("%s-%d", baseName, suffix)
		}
		err = s.CreateTypedSecret(ctx, scopeID, name, passitem.TypePassItem, item.Marshal())
		if err == nil {
			return browserCredentialMetadata(s, scopeID, name, item), nil
		}
		if !strings.Contains(err.Error(), "already exists") {
			return BrowserCredential{}, err
		}
	}
	return BrowserCredential{}, errors.New("too many logins use this name; choose a more specific title")
}

// UpdateBrowserLogin updates only the origin-bound item and only when the
// revision shown to the browser still matches.
func UpdateBrowserLogin(ctx context.Context, input BrowserUpdateLoginInput) (BrowserCredential, error) {
	if err := validateBrowserLoginInput(input.Title, input.Username, input.Password); err != nil {
		return BrowserCredential{}, err
	}
	s, rec, item, err := openBrowserCredentialSession(ctx, input.Origin, input.CredentialID)
	if err != nil {
		return BrowserCredential{}, err
	}
	defer s.Close()
	if input.Revision == "" || browserRevision(item) != input.Revision {
		return BrowserCredential{}, errors.New("browser credential changed; review it and try again")
	}
	if err := setBrowserLoginFields(item, input.Username, input.Password); err != nil {
		return BrowserCredential{}, err
	}
	item.Title = strings.TrimSpace(input.Title)
	if err := s.UpdateTypedSecret(ctx, rec.ScopeID, rec.Name, passitem.TypePassItem, passitem.TypePassItem, item.Marshal()); err != nil {
		return BrowserCredential{}, err
	}
	return browserCredentialMetadata(s, rec.ScopeID, rec.Name, item), nil
}

// AddBrowserTOTP attaches a validated otpauth URI to one origin-bound item.
func AddBrowserTOTP(ctx context.Context, origin, credentialID, revision, uri string) (BrowserCredential, error) {
	if len(uri) > 4096 {
		return BrowserCredential{}, errors.New("TOTP setup link is too long")
	}
	value, err := passitem.ParseTOTPURI(uri)
	if err != nil {
		return BrowserCredential{}, err
	}
	field, err := passitem.NewTOTPField(value)
	if err != nil {
		return BrowserCredential{}, err
	}
	s, rec, item, err := openBrowserCredentialSession(ctx, origin, credentialID)
	if err != nil {
		return BrowserCredential{}, err
	}
	defer s.Close()
	if revision == "" || browserRevision(item) != revision {
		return BrowserCredential{}, errors.New("browser credential changed; review it and try again")
	}
	if err := setBrowserTOTPField(item, field); err != nil {
		return BrowserCredential{}, err
	}
	if err := s.UpdateTypedSecret(ctx, rec.ScopeID, rec.Name, passitem.TypePassItem, passitem.TypePassItem, item.Marshal()); err != nil {
		return BrowserCredential{}, err
	}
	return browserCredentialMetadata(s, rec.ScopeID, rec.Name, item), nil
}

type browserTarget struct {
	host string
	port string
}

func parseBrowserTarget(raw string) (browserTarget, error) {
	u, err := parseBrowserURL(raw)
	if err != nil {
		return browserTarget{}, err
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return browserTarget{}, errors.New("browser origin must not contain a path, query, or fragment")
	}
	return browserTargetFromURL(u)
}

func parseStoredBrowserURL(raw string) (browserTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return browserTarget{}, errors.New("empty browser URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := parseBrowserURL(raw)
	if err != nil {
		return browserTarget{}, err
	}
	return browserTargetFromURL(u)
}

func parseBrowserURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("browser origin: %w", err)
	}
	if u.Scheme != "https" || u.Opaque != "" {
		return nil, errors.New("browser origin must use https")
	}
	if u.User != nil {
		return nil, errors.New("browser origin must not contain credentials")
	}
	if u.Host == "" {
		return nil, errors.New("browser origin requires a host")
	}
	return u, nil
}

func browserTargetFromURL(u *url.URL) (browserTarget, error) {
	host, err := canonicalBrowserHost(u.Hostname())
	if err != nil {
		return browserTarget{}, err
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return browserTarget{}, errors.New("browser origin has an invalid port")
	}
	if port == "" {
		port = "443"
	} else {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return browserTarget{}, errors.New("browser origin has an invalid port")
		}
		port = strconv.Itoa(number)
	}
	return browserTarget{host: host, port: port}, nil
}

func canonicalBrowserHost(raw string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if host == "" {
		return "", errors.New("browser origin requires a host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", fmt.Errorf("browser origin host: %w", err)
	}
	ascii = strings.ToLower(strings.TrimSuffix(ascii, "."))
	if ascii == "" || strings.ContainsAny(ascii, " /\\") {
		return "", errors.New("browser origin has an invalid host")
	}
	return ascii, nil
}

func browserItemMatches(item *passitem.Item, target browserTarget) bool {
	for _, raw := range item.URLs {
		stored, err := parseStoredBrowserURL(raw)
		if err != nil || stored.port != target.port {
			continue
		}
		if stored.host == target.host {
			return true
		}
		if net.ParseIP(stored.host) != nil || net.ParseIP(target.host) != nil {
			continue
		}
		storedSite, storedErr := publicsuffix.EffectiveTLDPlusOne(stored.host)
		targetSite, targetErr := publicsuffix.EffectiveTLDPlusOne(target.host)
		if storedErr == nil && targetErr == nil && storedSite == targetSite &&
			strings.HasSuffix(target.host, "."+stored.host) {
			return true
		}
	}
	return false
}

func browserUsername(item *passitem.Item) (string, bool) {
	ref, ok := browserStringFieldRef(item.Fields, "", passitem.FieldText, []string{"username", "email", "login", "user"})
	if !ok {
		return "", false
	}
	value, err := passitem.StringValue(*ref.field)
	return value, err == nil && value != ""
}

func browserPassword(item *passitem.Item) (string, bool) {
	ref, ok := browserStringFieldRef(item.Fields, "", passitem.FieldSecret, []string{"password", "passwd", "pass"})
	if !ok {
		return "", false
	}
	value, err := passitem.StringValue(*ref.field)
	return value, err == nil && value != ""
}

func browserTOTP(item *passitem.Item) *passitem.Field {
	refs := browserTOTPRefs(item.Fields, "")
	if len(refs) == 0 {
		return nil
	}
	return refs[0].field
}

func browserRevision(item *passitem.Item) string {
	if item == nil || item.Meta == nil {
		return "0"
	}
	switch revision := item.Meta["revision"].(type) {
	case float64:
		return strconv.FormatInt(int64(revision), 10)
	case int:
		return strconv.Itoa(revision)
	case int64:
		return strconv.FormatInt(revision, 10)
	case json.Number:
		return revision.String()
	default:
		return "0"
	}
}

func browserCredentialMetadata(s *Session, scopeID, name string, item *passitem.Item) BrowserCredential {
	username, _ := browserUsername(item)
	return BrowserCredential{
		ID:       encodeBrowserCredentialID(scopeID, name),
		Title:    item.Title,
		Username: username,
		Revision: browserRevision(item),
		HasTOTP:  browserTOTP(item) != nil,
		ScopeID:  scopeID,
		Scope:    scopeLabelOf(s, scopeID),
	}
}

func openBrowserCredential(
	ctx context.Context,
	origin, credentialID string,
) (*TypedRecord, *passitem.Item, func(), error) {
	s, record, item, err := openBrowserCredentialSession(ctx, origin, credentialID)
	if err != nil {
		return nil, nil, func() {}, err
	}
	return record, item, func() { s.Close() }, nil
}

func openBrowserCredentialSession(
	ctx context.Context,
	origin, credentialID string,
) (*Session, *TypedRecord, *passitem.Item, error) {
	target, err := parseBrowserTarget(origin)
	if err != nil {
		return nil, nil, nil, err
	}
	scopeID, name, err := decodeBrowserCredentialID(credentialID)
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	record, err := s.GetTypedSecret(scopeID, name)
	if err != nil {
		s.Close()
		return nil, nil, nil, err
	}
	if record.Type != passitem.TypePassItem {
		s.Close()
		return nil, nil, nil, errors.New("browser credential is not a pass item")
	}
	item, err := decodePassRecord(*record)
	if err != nil {
		s.Close()
		return nil, nil, nil, err
	}
	if !browserItemMatches(item, target) {
		s.Close()
		return nil, nil, nil, errors.New("browser credential does not match this origin")
	}
	return s, record, item, nil
}

func validateBrowserLoginInput(title, username, password string) error {
	if strings.TrimSpace(title) == "" || len(title) > passitem.MaxNameLen {
		return errors.New("login title is required and must be at most 128 characters")
	}
	if len(username) > passitem.MaxValueBytes {
		return errors.New("username is too long")
	}
	if password == "" || len(password) > passitem.MaxValueBytes {
		return errors.New("password is required and is too long")
	}
	return nil
}

func setBrowserLoginFields(item *passitem.Item, username, password string) error {
	usernameNames := []string{"username", "email", "login", "user"}
	usernameRef, hasUsernameRef := browserStringFieldRef(
		item.Fields,
		"",
		passitem.FieldText,
		usernameNames,
	)
	if username == "" {
		matchingRefs := browserMatchingStringFieldRefs(
			item.Fields,
			"",
			passitem.FieldText,
			usernameNames,
		)
		if len(matchingRefs) > 1 {
			return errors.New("login has multiple username fields; clear it in fd0 Desktop")
		}
		if len(matchingRefs) == 1 {
			if err := item.RemoveField(matchingRefs[0].path); err != nil {
				return err
			}
		}
	} else {
		field, err := passitem.NewStringField(passitem.FieldText, username)
		if err != nil {
			return err
		}
		path := "username"
		if hasUsernameRef {
			path = usernameRef.path
		}
		if err := item.SetField(path, field); err != nil {
			return err
		}
	}
	field, err := passitem.NewStringField(passitem.FieldSecret, password)
	if err != nil {
		return err
	}
	passwordNames := []string{"password", "passwd", "pass"}
	path := "password"
	if passwordRef, ok := browserStringFieldRef(
		item.Fields,
		"",
		passitem.FieldSecret,
		passwordNames,
	); ok {
		path = passwordRef.path
	}
	return item.SetField(path, field)
}

func setBrowserTOTPField(item *passitem.Item, field passitem.Field) error {
	refs := browserTOTPRefs(item.Fields, "")
	switch len(refs) {
	case 0:
		return item.SetField("one-time password", field)
	case 1:
		return item.SetField(refs[0].path, field)
	default:
		return errors.New("login has multiple one-time passwords; update it in fd0 Desktop")
	}
}

func browserTargetURL(target browserTarget) string {
	host := target.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if target.port != "443" {
		host += ":" + target.port
	}
	return "https://" + host
}

func browserPassName(title, host string) string {
	base := strings.TrimSpace(title)
	if base == "" {
		base = host
	}
	return passNamePrefix + base
}

type browserFieldRef struct {
	path  string
	field *passitem.Field
}

func browserStringFieldRef(
	fields []passitem.Field,
	prefix string,
	kind string,
	names []string,
) (browserFieldRef, bool) {
	for _, preferred := range names {
		if ref, ok := browserNamedFieldRef(fields, prefix, kind, preferred, true); ok {
			return ref, true
		}
	}
	for _, preferred := range names {
		if ref, ok := browserNamedFieldRef(fields, prefix, kind, preferred, false); ok {
			return ref, true
		}
	}
	return browserFieldRef{}, false
}

func browserNamedFieldRef(
	fields []passitem.Field,
	prefix, kind, preferred string,
	exact bool,
) (browserFieldRef, bool) {
	for index := range fields {
		field := &fields[index]
		path := field.Name
		if prefix != "" {
			path = prefix + "/" + field.Name
		}
		if field.Type == passitem.FieldSection {
			if ref, ok := browserNamedFieldRef(field.Fields, path, kind, preferred, exact); ok {
				return ref, true
			}
			continue
		}
		name := strings.ToLower(strings.TrimSpace(field.Name))
		matches := name == preferred
		if !exact {
			matches = browserFuzzyFieldNameMatches(name, preferred)
		}
		if field.Type != kind || !matches {
			continue
		}
		value, err := passitem.StringValue(*field)
		if err == nil && value != "" {
			return browserFieldRef{path: path, field: field}, true
		}
	}
	return browserFieldRef{}, false
}

func browserFuzzyFieldNameMatches(name, preferred string) bool {
	tokens := strings.FieldsFunc(name, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
	found := false
	for _, token := range tokens {
		if token == preferred {
			found = true
		}
		switch token {
		case "account", "address", "current", "email", "login", "name",
			"pass", "passwd", "password", "site", "user", "username":
		default:
			return false
		}
	}
	return found
}

func browserMatchingStringFieldRefs(
	fields []passitem.Field,
	prefix, kind string,
	names []string,
) []browserFieldRef {
	var refs []browserFieldRef
	var visit func([]passitem.Field, string)
	visit = func(current []passitem.Field, currentPrefix string) {
		for index := range current {
			field := &current[index]
			path := field.Name
			if currentPrefix != "" {
				path = currentPrefix + "/" + field.Name
			}
			if field.Type == passitem.FieldSection {
				visit(field.Fields, path)
				continue
			}
			if field.Type != kind {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(field.Name))
			matches := false
			for _, preferred := range names {
				matches = matches || name == preferred ||
					browserFuzzyFieldNameMatches(name, preferred)
			}
			if matches {
				value, err := passitem.StringValue(*field)
				if err == nil && value != "" {
					refs = append(refs, browserFieldRef{path: path, field: field})
				}
			}
		}
	}
	visit(fields, prefix)
	return refs
}

func browserTOTPRefs(fields []passitem.Field, prefix string) []browserFieldRef {
	var refs []browserFieldRef
	for index := range fields {
		field := &fields[index]
		path := field.Name
		if prefix != "" {
			path = prefix + "/" + field.Name
		}
		if field.Type == passitem.FieldTOTP {
			refs = append(refs, browserFieldRef{path: path, field: field})
		}
		if field.Type == passitem.FieldSection {
			refs = append(refs, browserTOTPRefs(field.Fields, path)...)
		}
	}
	return refs
}

func encodeBrowserCredentialID(scopeID, name string) string {
	raw := scopeID + "\x00" + name
	return "v1." + base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeBrowserCredentialID(id string) (string, string, error) {
	if len(id) > 1024 || !strings.HasPrefix(id, "v1.") {
		return "", "", errors.New("invalid browser credential reference")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, "v1."))
	if err != nil {
		return "", "", errors.New("invalid browser credential reference")
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 2 || parts[0] == "" || !strings.HasPrefix(parts[1], passNamePrefix) {
		return "", "", errors.New("invalid browser credential reference")
	}
	return parts[0], parts[1], nil
}
