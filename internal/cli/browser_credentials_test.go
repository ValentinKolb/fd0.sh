package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/passitem"
)

func TestParseBrowserTargetRequiresHTTPS(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"",
		"example.com",
		"http://example.com",
		"file:///tmp/login",
		"https://user:pass@example.com",
		"https://example.com/login",
		"https://example.com/?next=login",
		"https://example.com/#login",
		"https://example.com:",
		"https://example.com:0",
		"https://example.com:65536",
	} {
		if _, err := parseBrowserTarget(raw); err == nil {
			t.Fatalf("parseBrowserTarget(%q) succeeded", raw)
		}
	}
}

func TestParseBrowserTargetCanonicalizesOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw  string
		want browserTarget
	}{
		{raw: "https://EXAMPLE.com/", want: browserTarget{host: "example.com", port: "443"}},
		{raw: "https://bücher.example:0443", want: browserTarget{host: "xn--bcher-kva.example", port: "443"}},
		{raw: "https://[2001:db8::1]:8443", want: browserTarget{host: "2001:db8::1", port: "8443"}},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parseBrowserTarget(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("parseBrowserTarget(%q) = %+v, want %+v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestBrowserItemMatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		stored string
		target string
		want   bool
	}{
		{name: "exact", stored: "https://accounts.example.com/login", target: "https://accounts.example.com", want: true},
		{name: "scheme less stored", stored: "example.com", target: "https://login.example.com", want: true},
		{name: "parent domain", stored: "https://example.com", target: "https://login.example.com/", want: true},
		{name: "sibling rejected", stored: "https://accounts.example.com", target: "https://mail.example.com/", want: false},
		{name: "suffix confusion rejected", stored: "https://example.com", target: "https://notexample.com/", want: false},
		{name: "public suffix rejected", stored: "https://com", target: "https://example.com/", want: false},
		{name: "different port rejected", stored: "https://example.com:8443", target: "https://example.com/", want: false},
		{name: "http stored rejected", stored: "http://example.com", target: "https://example.com/", want: false},
		{name: "stored credentials rejected", stored: "https://user@example.com", target: "https://example.com/", want: false},
		{name: "idn", stored: "https://bücher.example", target: "https://xn--bcher-kva.example/", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := parseBrowserTarget(tt.target)
			if err != nil {
				t.Fatal(err)
			}
			item := passitem.New("login", []string{tt.stored})
			if got := browserItemMatches(item, target); got != tt.want {
				t.Fatalf("browserItemMatches(%q, %q) = %v, want %v", tt.stored, tt.target, got, tt.want)
			}
		})
	}
}

func TestBrowserFieldsPreferNamedLoginValues(t *testing.T) {
	t.Parallel()
	text := func(name, value string) passitem.Field {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return passitem.Field{Type: passitem.FieldText, Name: name, Value: raw}
	}
	secret := func(name, value string) passitem.Field {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return passitem.Field{Type: passitem.FieldSecret, Name: name, Value: raw}
	}
	item := passitem.New("login", []string{"https://example.com"})
	item.Fields = []passitem.Field{
		text(passitem.NotesFieldName, "not a username"),
		{Type: passitem.FieldSection, Name: "Login", Fields: []passitem.Field{
			text("email address", "user@example.com"),
			secret("password", "correct horse"),
		}},
	}
	if got, ok := browserUsername(item); !ok || got != "user@example.com" {
		t.Fatalf("browserUsername() = %q, %v", got, ok)
	}
	if got, ok := browserPassword(item); !ok || got != "correct horse" {
		t.Fatalf("browserPassword() = %q, %v", got, ok)
	}
}

func TestBrowserCredentialIDRoundTrip(t *testing.T) {
	t.Parallel()
	id := encodeBrowserCredentialID("s_example", "pass:GitHub")
	scope, name, err := decodeBrowserCredentialID(id)
	if err != nil {
		t.Fatal(err)
	}
	if scope != "s_example" || name != "pass:GitHub" {
		t.Fatalf("decodeBrowserCredentialID() = %q, %q", scope, name)
	}
	for _, invalid := range []string{"", "v2.abc", "v1.not-base64", "v1.", "v1." + strings.Repeat("a", 1024)} {
		if _, _, err := decodeBrowserCredentialID(invalid); err == nil {
			t.Fatalf("decodeBrowserCredentialID(%q) succeeded", invalid)
		}
	}
}

func TestBrowserCredentialMetadataJSONIncludesUsernameButNoSecret(t *testing.T) {
	t.Parallel()
	payload, err := json.Marshal(BrowserCredential{
		ID:       "opaque",
		Title:    "Example",
		Username: "user@example.com",
		Revision: "3",
		ScopeID:  "s_example",
		Scope:    "Personal",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(payload)
	if got != `{"id":"opaque","title":"Example","username":"user@example.com","revision":"3","scopeId":"s_example","scope":"Personal"}` {
		t.Fatalf("BrowserCredential JSON = %s", got)
	}
	if strings.Contains(got, "password") {
		t.Fatalf("BrowserCredential JSON contains secret metadata: %s", got)
	}
}

func TestBrowserRevisionIsStableAndOpaque(t *testing.T) {
	t.Parallel()
	item := passitem.New("login", []string{"https://example.com"})
	if got := browserRevision(item); got != "1" {
		t.Fatalf("browserRevision() = %q, want 1", got)
	}
	item.Touch()
	if got := browserRevision(item); got != "2" {
		t.Fatalf("browserRevision() after Touch = %q, want 2", got)
	}
}

func TestBrowserTOTPFindsNestedFieldWithoutExposingSeed(t *testing.T) {
	t.Parallel()
	field, err := passitem.NewTOTPField(passitem.TOTPValue{
		Secret: "JBSWY3DPEHPK3PXP",
		Issuer: "Example",
	})
	if err != nil {
		t.Fatal(err)
	}
	field.Name = "one-time password"
	item := passitem.New("login", []string{"https://example.com"})
	item.Fields = []passitem.Field{{
		Type:   passitem.FieldSection,
		Name:   "Authentication",
		Fields: []passitem.Field{field},
	}}
	if browserTOTP(item) == nil {
		t.Fatal("browserTOTP() did not find nested TOTP")
	}
	metadata := browserCredentialMetadata(nil, "s_example", "pass:login", item)
	payload, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.HasTOTP || strings.Contains(string(payload), "JBSWY3DPEHPK3PXP") {
		t.Fatalf("metadata = %s", payload)
	}
}

func TestSetBrowserLoginFieldsUpdatesNestedAliasesAndClearsUsername(t *testing.T) {
	t.Parallel()
	text, err := passitem.NewStringField(passitem.FieldText, "old@example.com")
	if err != nil {
		t.Fatal(err)
	}
	text.Name = "email"
	secret, err := passitem.NewStringField(passitem.FieldSecret, "old-password")
	if err != nil {
		t.Fatal(err)
	}
	secret.Name = "passwd"
	staleUsername, err := passitem.NewStringField(passitem.FieldText, "stale@example.com")
	if err != nil {
		t.Fatal(err)
	}
	staleUsername.Name = "user"
	stalePassword, err := passitem.NewStringField(passitem.FieldSecret, "stale-password")
	if err != nil {
		t.Fatal(err)
	}
	stalePassword.Name = "pass"
	recoveryEmail, err := passitem.NewStringField(passitem.FieldText, "backup@example.com")
	if err != nil {
		t.Fatal(err)
	}
	recoveryEmail.Name = "recovery email"
	passportNumber, err := passitem.NewStringField(passitem.FieldSecret, "P123456")
	if err != nil {
		t.Fatal(err)
	}
	passportNumber.Name = "passport number"
	passwordHint, err := passitem.NewStringField(passitem.FieldSecret, "first pet")
	if err != nil {
		t.Fatal(err)
	}
	passwordHint.Name = "password hint"
	item := passitem.New("login", []string{"https://example.com"})
	item.Fields = []passitem.Field{
		staleUsername,
		stalePassword,
		recoveryEmail,
		passportNumber,
		passwordHint,
		{
			Type:   passitem.FieldSection,
			Name:   "Login",
			Fields: []passitem.Field{text, secret},
		},
	}

	if err := setBrowserLoginFields(item, "new@example.com", "new-password"); err != nil {
		t.Fatal(err)
	}
	if got, ok := browserUsername(item); !ok || got != "new@example.com" {
		t.Fatalf("browserUsername() = %q, %v", got, ok)
	}
	if got, ok := browserPassword(item); !ok || got != "new-password" {
		t.Fatalf("browserPassword() = %q, %v", got, ok)
	}
	if _, err := item.Field("username"); err == nil {
		t.Fatal("setBrowserLoginFields created a duplicate root username")
	}
	if _, err := item.Field("user"); err != nil {
		t.Fatalf("separate username alias was removed: %v", err)
	}
	if _, err := item.Field("pass"); err != nil {
		t.Fatalf("separate password alias was removed: %v", err)
	}
	for _, path := range []string{"recovery email", "passport number", "password hint"} {
		if _, err := item.Field(path); err != nil {
			t.Fatalf("unrelated field %q was removed: %v", path, err)
		}
	}

	if err := setBrowserLoginFields(item, "", "newer-password"); err == nil ||
		!strings.Contains(err.Error(), "multiple username fields") {
		t.Fatalf("ambiguous username clear err = %v", err)
	}
	if got, ok := browserUsername(item); !ok || got != "new@example.com" {
		t.Fatalf("ambiguous clear changed username to %q, %v", got, ok)
	}
	if _, err := item.Field("Login/email"); err != nil {
		t.Fatalf("ambiguous clear removed selected username: %v", err)
	}
	if _, err := item.Field("recovery email"); err != nil {
		t.Fatalf("unrelated username-like field was removed: %v", err)
	}

	single := passitem.New("single login", []string{"https://example.com"})
	single.Fields = []passitem.Field{text, secret}
	if err := setBrowserLoginFields(single, "", "single-password"); err != nil {
		t.Fatal(err)
	}
	if got, ok := browserUsername(single); ok || got != "" {
		t.Fatalf("single cleared browserUsername() = %q, %v", got, ok)
	}

	emptyAlias, err := passitem.NewStringField(passitem.FieldText, "")
	if err != nil {
		t.Fatal(err)
	}
	emptyAlias.Name = "username"
	oneReadable := passitem.New("one readable username", []string{"https://example.com"})
	oneReadable.Fields = []passitem.Field{text, emptyAlias, secret}
	if err := setBrowserLoginFields(oneReadable, "", "password"); err != nil {
		t.Fatalf("empty alias made username clear ambiguous: %v", err)
	}
	if got, ok := browserUsername(oneReadable); ok || got != "" {
		t.Fatalf("one-readable cleared browserUsername() = %q, %v", got, ok)
	}

	fuzzyFirst, err := passitem.NewStringField(passitem.FieldText, "first@example.com")
	if err != nil {
		t.Fatal(err)
	}
	fuzzyFirst.Name = "account email"
	fuzzySecond, err := passitem.NewStringField(passitem.FieldText, "second@example.com")
	if err != nil {
		t.Fatal(err)
	}
	fuzzySecond.Name = "login email"
	ambiguous := passitem.New("ambiguous login", []string{"https://example.com"})
	ambiguous.Fields = []passitem.Field{fuzzyFirst, fuzzySecond, secret}
	if err := setBrowserLoginFields(ambiguous, "", "password"); err == nil ||
		!strings.Contains(err.Error(), "multiple username fields") {
		t.Fatalf("fuzzy ambiguous username clear err = %v", err)
	}
}

func TestSetBrowserTOTPFieldReplacesNestedSeedAndRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	oldField, err := passitem.NewTOTPField(passitem.TOTPValue{
		Secret: "JBSWY3DPEHPK3PXP",
		Issuer: "Old",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldField.Name = "2fa"
	item := passitem.New("login", []string{"https://example.com"})
	item.Fields = []passitem.Field{{
		Type:   passitem.FieldSection,
		Name:   "Authentication",
		Fields: []passitem.Field{oldField},
	}}
	newField, err := passitem.NewTOTPField(passitem.TOTPValue{
		Secret: "KRUGS4ZANFZSAYJA",
		Issuer: "New",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := setBrowserTOTPField(item, newField); err != nil {
		t.Fatal(err)
	}
	if len(browserTOTPRefs(item.Fields, "")) != 1 {
		t.Fatalf("expected one TOTP field, got %d", len(browserTOTPRefs(item.Fields, "")))
	}
	replaced, err := item.Field("Authentication/2fa")
	if err != nil {
		t.Fatal(err)
	}
	value, err := passitem.TOTPFromField(*replaced)
	if err != nil {
		t.Fatal(err)
	}
	if value.Secret != "KRUGS4ZANFZSAYJA" {
		t.Fatalf("TOTP secret = %q", value.Secret)
	}

	second := newField
	second.Name = "backup"
	item.Fields = append(item.Fields, second)
	if err := setBrowserTOTPField(item, newField); err == nil {
		t.Fatal("multiple TOTP fields were replaced without an explicit choice")
	}
}

func TestBrowserLoginLifecycleAdvancesRevisionAndRejectsStaleUpdates(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	created, err := SaveBrowserLogin(ctx, BrowserSaveLoginInput{
		Origin:   "https://example.test",
		ScopeID:  scopeID,
		Title:    "Example",
		Username: "first@example.test",
		Password: "first-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision == "" {
		t.Fatal("created revision is empty")
	}

	updated, err := UpdateBrowserLogin(ctx, BrowserUpdateLoginInput{
		Origin:       "https://example.test",
		CredentialID: created.ID,
		Revision:     created.Revision,
		Title:        "Renamed example",
		Username:     "second@example.test",
		Password:     "second-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision == created.Revision {
		t.Fatalf("updated revision remained %q", updated.Revision)
	}
	if updated.Title != "Renamed example" {
		t.Fatalf("updated title = %q", updated.Title)
	}
	revealed, err := RevealBrowserCredential(ctx, "https://example.test", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revealed.Username != "second@example.test" || revealed.Password != "second-password" {
		t.Fatalf("revealed credential = %+v", revealed)
	}

	_, err = UpdateBrowserLogin(ctx, BrowserUpdateLoginInput{
		Origin:       "https://example.test",
		CredentialID: created.ID,
		Revision:     created.Revision,
		Title:        "Stale example",
		Username:     "stale@example.test",
		Password:     "stale-password",
	})
	if err == nil || !strings.Contains(err.Error(), "changed; review") {
		t.Fatalf("stale update error = %v", err)
	}

	withTOTP, err := AddBrowserTOTP(
		ctx,
		"https://example.test",
		created.ID,
		updated.Revision,
		"otpauth://totp/Example:test?secret=JBSWY3DPEHPK3PXP&issuer=Example",
	)
	if err != nil {
		t.Fatal(err)
	}
	if withTOTP.Revision == updated.Revision || !withTOTP.HasTOTP {
		t.Fatalf("TOTP metadata = %+v", withTOTP)
	}
	code, err := BrowserTOTPForCredential(ctx, "https://example.test", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(code.Code) != 6 || code.Remaining < 1 || code.Remaining > code.Period {
		t.Fatalf("TOTP code = %+v", code)
	}
}
