package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestPassSummaryRowsDoNotExposeFieldValues(t *testing.T) {
	item := passitem.New("GitHub", []string{"https://github.com"})
	password, err := passitem.NewStringField(passitem.FieldSecret, "super-secret-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("password", password); err != nil {
		t.Fatal(err)
	}
	totp, err := passitem.NewTOTPField(passitem.TOTPValue{Secret: "JBSWY3DPEHPK3PXP"})
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("2fa", totp); err != nil {
		t.Fatal(err)
	}
	file, err := passitem.NewFileField("key.pem", "", []byte("secret-key-data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("SSH/key.pem", file); err != nil {
		t.Fatal(err)
	}

	s := &Session{Body: &proto.VaultBody{Scopes: map[string]proto.ScopeVaultData{
		"s_scope": {Label: "work"},
	}}}
	raw, err := json.Marshal(passSummaryRows(s, []passRow{{
		ScopeID: "s_scope",
		Name:    "pass:github",
		Item:    item,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, leak := range []string{"super-secret-password", "JBSWY3DPEHPK3PXP", "secret-key-data", "data_b64"} {
		if strings.Contains(got, leak) {
			t.Fatalf("summary JSON leaked %q:\n%s", leak, got)
		}
	}
	for _, want := range []string{"github", "GitHub", "password", "2fa", "SSH/key.pem"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary JSON missing %q:\n%s", want, got)
		}
	}
}

func TestPreferredPassFieldFindsNestedPassword(t *testing.T) {
	item := passitem.New("GitHub", nil)
	token, err := passitem.NewStringField(passitem.FieldSecret, "token")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("api-token", token); err != nil {
		t.Fatal(err)
	}
	password, err := passitem.NewStringField(passitem.FieldSecret, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("Credentials/password", password); err != nil {
		t.Fatal(err)
	}

	got, err := preferredPassField(item.Fields, passitem.FieldSecret, []string{"password", "pass"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "Credentials/password" {
		t.Fatalf("preferred field = %q, want Credentials/password", got)
	}
}

func TestNormalizePassNameTrims(t *testing.T) {
	got, err := normalizePassName(" github ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "github" {
		t.Fatalf("name = %q, want github", got)
	}
	if _, err := normalizePassName("   "); err == nil {
		t.Fatal("empty name should fail")
	}
}
