package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

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
}

// BrowserCredentialSecret is the smallest value set needed by the first
// browser integration slice.
type BrowserCredentialSecret struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password"`
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
	return BrowserCredentialSecret{Username: username, Password: password}, nil
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
	return browserStringField(item.Fields, passitem.FieldText, []string{"username", "email", "login", "user"})
}

func browserPassword(item *passitem.Item) (string, bool) {
	return browserStringField(item.Fields, passitem.FieldSecret, []string{"password", "passwd", "pass"})
}

func browserStringField(fields []passitem.Field, kind string, names []string) (string, bool) {
	for _, preferred := range names {
		if value, ok := browserNamedField(fields, kind, preferred, true); ok {
			return value, true
		}
	}
	for _, preferred := range names {
		if value, ok := browserNamedField(fields, kind, preferred, false); ok {
			return value, true
		}
	}
	return "", false
}

func browserNamedField(fields []passitem.Field, kind, preferred string, exact bool) (string, bool) {
	for _, field := range fields {
		if field.Type == passitem.FieldSection {
			if value, ok := browserNamedField(field.Fields, kind, preferred, exact); ok {
				return value, true
			}
			continue
		}
		name := strings.ToLower(strings.TrimSpace(field.Name))
		matches := name == preferred
		if !exact {
			matches = strings.Contains(name, preferred)
		}
		if field.Type != kind || !matches {
			continue
		}
		value, err := passitem.StringValue(field)
		if err == nil && value != "" {
			return value, true
		}
	}
	return "", false
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
