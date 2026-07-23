package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestPassFileExportPath(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got, err := passFileExportPath("key.pem", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(cwd, "key.pem") {
		t.Fatalf("default export = %q", got)
	}

	for _, out := range []string{
		filepath.Join("nested", "key.pem"),
		filepath.Join(t.TempDir(), "key.pem"),
	} {
		got, err := passFileExportPath("key.pem", out)
		if err != nil {
			t.Fatalf("explicit output %q: %v", out, err)
		}
		if got != out {
			t.Fatalf("explicit output = %q, want %q", got, out)
		}
	}

	for _, storedName := range []string{
		"../key.pem",
		"nested/key.pem",
		`nested\key.pem`,
		"/tmp/key.pem",
		"..",
	} {
		if _, err := passFileExportPath(storedName, filepath.Join(t.TempDir(), "safe.pem")); err == nil {
			t.Fatalf("unsafe stored name %q should be rejected even with explicit output", storedName)
		}
	}
}

func TestWritePassFileExportUsesSafeCreateAndAtomicForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := writePassFileExport(path, []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if err := writePassFileExport(path, []byte("second"), false); err == nil {
		t.Fatal("non-force export should reject a collision")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "first" {
		t.Fatalf("collision changed existing file: %q, %v", got, err)
	}
	if err := writePassFileExport(path, []byte("second"), true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "second" {
		t.Fatalf("force export = %q, %v", got, err)
	}
}

func TestWritePassFileExportDoesNotFollowSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writePassFileExport(link, []byte("blocked"), false); err == nil {
		t.Fatal("non-force export should reject an existing symlink")
	}
	if err := writePassFileExport(link, []byte("replacement"), true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "target" {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("force export should replace the symlink itself")
	}
	if got, err := os.ReadFile(link); err != nil || string(got) != "replacement" {
		t.Fatalf("replacement = %q, %v", got, err)
	}
}
