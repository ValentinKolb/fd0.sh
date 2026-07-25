package cli

import (
	"bytes"
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

// notesTestItem builds an item carrying one ordinary field, so the tests below
// can tell the notes block apart from the field table.
func notesTestItem(t *testing.T) *passitem.Item {
	t.Helper()
	item := passitem.New("GitHub", nil)
	user, err := passitem.NewStringField(passitem.FieldText, "octocat")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("username", user); err != nil {
		t.Fatal(err)
	}
	return item
}

func TestPassNotesRoundTripAndShowRendersOnce(t *testing.T) {
	item := notesTestItem(t)
	if err := setPassNotes(item, "recovery contact: ops@example.com"); err != nil {
		t.Fatal(err)
	}
	if got := item.Notes(); got != "recovery contact: ops@example.com" {
		t.Fatalf("Notes() = %q", got)
	}

	var buf bytes.Buffer
	renderPassItem(&buf, item, "work", false)
	out := buf.String()
	if n := strings.Count(out, "ops@example.com"); n != 1 {
		t.Fatalf("note text rendered %d times, want 1:\n%s", n, out)
	}
	// The note must not also appear as a row in the field table, which is the
	// only place a "text" type column is printed.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, passitem.NotesFieldName) && strings.Contains(line, passitem.FieldText) {
			t.Fatalf("notes listed as an ordinary field:\n%s", out)
		}
	}
	if !strings.Contains(out, "\n  notes\n") {
		t.Fatalf("missing notes heading:\n%s", out)
	}
	if !strings.Contains(out, "  username") {
		t.Fatalf("ordinary fields disappeared:\n%s", out)
	}
}

func TestPassNotesMultilineStaysIndented(t *testing.T) {
	item := notesTestItem(t)
	if err := setPassNotes(item, "line one\nline two\n\nline four"); err != nil {
		t.Fatal(err)
	}
	if got := item.Notes(); got != "line one\nline two\n\nline four" {
		t.Fatalf("multi-line note round-trip = %q", got)
	}

	var buf bytes.Buffer
	renderPassItem(&buf, item, "work", false)
	lines := strings.Split(buf.String(), "\n")
	head := -1
	for i, line := range lines {
		if line == "  notes" {
			head = i
			break
		}
	}
	if head < 0 {
		t.Fatalf("no notes heading:\n%s", buf.String())
	}
	want := []string{"    line one", "    line two", "", "    line four"}
	got := lines[head+1 : head+1+len(want)]
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("notes body line %d = %q, want %q\nfull output:\n%s", i, got[i], want[i], buf.String())
		}
	}
}

func TestPassNotesRemoveLeavesNoField(t *testing.T) {
	item := notesTestItem(t)
	if err := setPassNotes(item, "temporary"); err != nil {
		t.Fatal(err)
	}
	if err := setPassNotes(item, ""); err != nil {
		t.Fatal(err)
	}
	if got := item.Notes(); got != "" {
		t.Fatalf("Notes() after removal = %q", got)
	}
	for _, f := range item.Fields {
		if strings.EqualFold(f.Name, passitem.NotesFieldName) {
			t.Fatalf("notes field survived removal: %+v", item.Fields)
		}
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"notes"`) {
		t.Fatalf("removed note still on the wire: %s", raw)
	}

	var buf bytes.Buffer
	renderPassItem(&buf, item, "work", false)
	if strings.Contains(buf.String(), "notes") {
		t.Fatalf("show still renders a notes block:\n%s", buf.String())
	}
}

func TestPassNotesEmptyValueRemovesTheNote(t *testing.T) {
	item := notesTestItem(t)
	// An item that never had a note stays note-free rather than gaining an
	// empty field, so `pass add` can pass the flag through unconditionally.
	if err := setPassNotes(item, ""); err != nil {
		t.Fatal(err)
	}
	if len(item.Fields) != 1 {
		t.Fatalf("empty note added a field: %+v", item.Fields)
	}
	// Whitespace-only input is equivalent to empty.
	if err := setPassNotes(item, "kept"); err != nil {
		t.Fatal(err)
	}
	if err := setPassNotes(item, "  \n\t\n"); err != nil {
		t.Fatal(err)
	}
	if got := item.Notes(); got != "" {
		t.Fatalf("whitespace-only note = %q, want removal", got)
	}
}

func TestPassNotesIgnoresNotesFieldInsideSection(t *testing.T) {
	item := notesTestItem(t)
	nested, err := passitem.NewStringField(passitem.FieldText, "belongs to the section")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("Recovery/notes", nested); err != nil {
		t.Fatal(err)
	}
	if got := item.Notes(); got != "" {
		t.Fatalf("nested notes leaked into Notes(): %q", got)
	}

	// The nested field must stay in the field table, and no notes block may
	// appear for it.
	var buf bytes.Buffer
	renderPassItem(&buf, item, "work", false)
	out := buf.String()
	if !strings.Contains(out, "Recovery/notes") {
		t.Fatalf("nested notes field dropped from the field list:\n%s", out)
	}
	if strings.Contains(out, "\n  notes\n") {
		t.Fatalf("nested notes rendered as the item note:\n%s", out)
	}

	// Setting and removing the item's note must leave the nested field alone.
	if err := setPassNotes(item, "top level"); err != nil {
		t.Fatal(err)
	}
	if err := setPassNotes(item, ""); err != nil {
		t.Fatal(err)
	}
	f, err := item.Field("Recovery/notes")
	if err != nil {
		t.Fatalf("nested notes field removed: %v", err)
	}
	if got, err := passitem.StringValue(*f); err != nil || got != "belongs to the section" {
		t.Fatalf("nested notes value = %q, %v", got, err)
	}
}

func TestPassNotesListedFieldsKeepsNestedNotes(t *testing.T) {
	item := notesTestItem(t)
	nested, err := passitem.NewStringField(passitem.FieldText, "section note")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("Recovery/notes", nested); err != nil {
		t.Fatal(err)
	}
	if err := setPassNotes(item, "item note"); err != nil {
		t.Fatal(err)
	}
	listed := passListedFields(item)
	for _, f := range listed {
		if strings.EqualFold(f.Name, passitem.NotesFieldName) {
			t.Fatalf("top-level notes field still listed: %+v", listed)
		}
	}
	if len(listed) != 2 { // username + Recovery section
		t.Fatalf("listed fields = %d, want 2: %+v", len(listed), listed)
	}
}

func TestEditPassNotesUsesEditorAndKeepsTempFilePrivate(t *testing.T) {
	dir := t.TempDir()
	modeOut := filepath.Join(dir, "mode")
	pathOut := filepath.Join(dir, "path")
	script := filepath.Join(dir, "fake-editor.sh")
	// The fake editor records the buffer's path and permissions, then edits it
	// the way a real editor would.
	body := "#!/bin/sh\n" +
		"printf '%s' \"$1\" > " + pathOut + "\n" +
		"ls -l \"$1\" | cut -c1-10 > " + modeOut + "\n" +
		"printf 'appended\\n' >> \"$1\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", script)
	t.Setenv("VISUAL", "")

	got, err := editPassNotes("seed line\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != "seed line\nappended" {
		t.Fatalf("edited note = %q", got)
	}

	mode, err := os.ReadFile(modeOut)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(mode)) != "-rw-------" {
		t.Fatalf("temp buffer mode = %q, want -rw-------", strings.TrimSpace(string(mode)))
	}
	tmpPath, err := os.ReadFile(pathOut)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(strings.TrimSpace(string(tmpPath))); !os.IsNotExist(err) {
		t.Fatalf("temp buffer %q survived the edit: %v", tmpPath, err)
	}
}

func TestEditPassNotesFallsBackToVisualAndRemovesBufferOnFailure(t *testing.T) {
	dir := t.TempDir()
	pathOut := filepath.Join(dir, "path")
	script := filepath.Join(dir, "failing-editor.sh")
	body := "#!/bin/sh\nprintf '%s' \"$1\" > " + pathOut + "\nexit 3\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", "")
	t.Setenv("VISUAL", script)

	if _, err := editPassNotes("seed"); err == nil {
		t.Fatal("a failing editor should abort the edit")
	}
	tmpPath, err := os.ReadFile(pathOut)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(strings.TrimSpace(string(tmpPath))); !os.IsNotExist(err) {
		t.Fatalf("temp buffer %q survived a failed edit: %v", tmpPath, err)
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
