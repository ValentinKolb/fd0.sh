package passitem

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestItemSectionsAndFieldPaths(t *testing.T) {
	item := New("GitHub", []string{"https://github.com"})
	if err := item.AddSection("Recovery"); err != nil {
		t.Fatalf("add section: %v", err)
	}
	secret, err := NewStringField(FieldSecret, "code-1")
	if err != nil {
		t.Fatalf("secret field: %v", err)
	}
	if err := item.SetField("Recovery/code-1", secret); err != nil {
		t.Fatalf("set nested field: %v", err)
	}
	got, err := item.Field("Recovery/code-1")
	if err != nil {
		t.Fatalf("field lookup: %v", err)
	}
	val, err := StringValue(*got)
	if err != nil {
		t.Fatalf("string value: %v", err)
	}
	if val != "code-1" {
		t.Fatalf("value = %q, want code-1", val)
	}
	if err := item.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRejectDuplicateFieldsInSection(t *testing.T) {
	raw := []byte(`{
		"title": "bad",
		"fields": [
			{"type":"section","name":"A","fields":[
				{"type":"text","name":"x","value":"one"},
				{"type":"text","name":"x","value":"two"}
			]}
		]
	}`)
	var item Item
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	if err := item.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("expected duplicate field error, got %v", err)
	}
}

func TestValidateTrimsFieldNamesBeforeDuplicateCheck(t *testing.T) {
	raw := []byte(`{
		"title": "bad",
		"fields": [
			{"type":"text","name":" username ","value":"one"},
			{"type":"text","name":"username","value":"two"}
		]
	}`)
	var item Item
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	if err := item.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("expected duplicate field error after trim, got %v", err)
	}
}

func TestTOTPCodeRFC6238SHA1(t *testing.T) {
	v := TOTPValue{
		Secret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		Digits:    8,
		Period:    30,
		Algorithm: "SHA1",
	}
	code, _, err := TOTPCode(v, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("totp: %v", err)
	}
	if code != "94287082" {
		t.Fatalf("code = %s, want 94287082", code)
	}
}

func TestParseTOTPURI(t *testing.T) {
	v, err := ParseTOTPURI("otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v.Issuer != "GitHub" || v.Account != "me@example.com" || v.Digits != 6 || v.Period != 30 || v.Algorithm != "SHA1" {
		t.Fatalf("unexpected value: %+v", v)
	}
}

func TestParseTOTPURIValidatesParameters(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{"missing secret", "otpauth://totp/GitHub:me@example.com?issuer=GitHub", "secret required"},
		{"invalid secret", "otpauth://totp/GitHub:me@example.com?secret=not-base32!", "base32"},
		{"invalid digits", "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&digits=9", "digits"},
		{"non-numeric digits", "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&digits=six", "number"},
		{"invalid period", "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&period=1", "period"},
		{"non-numeric period", "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&period=thirty", "number"},
		{"invalid algorithm", "otpauth://totp/GitHub:me@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "algorithm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTOTPURI(tt.uri)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.want) {
				t.Fatalf("ParseTOTPURI() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestFileSizeLimit(t *testing.T) {
	data := make([]byte, MaxFileBytes+1)
	if _, err := NewFileField("too-big.pem", "", data); err == nil {
		t.Fatalf("expected size limit error")
	}
}

func TestFileIntegrityIsValidated(t *testing.T) {
	field, err := NewFileField("key.pem", "", []byte("secret-key"))
	if err != nil {
		t.Fatalf("new file field: %v", err)
	}
	file, err := FileFromField(field)
	if err != nil {
		t.Fatalf("file value: %v", err)
	}
	data, err := DecodeFileData(file)
	if err != nil {
		t.Fatalf("decode file data: %v", err)
	}
	if string(data) != "secret-key" {
		t.Fatalf("data = %q", string(data))
	}

	file.SHA256 = strings.Repeat("0", 64)
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	item := New("bad-file", nil)
	item.Fields = []Field{{Type: FieldFile, Name: "key", Value: raw}}
	if err := item.Validate(); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch, got %v", err)
	}
}

func TestSafeFileName(t *testing.T) {
	for _, name := range []string{"key.pem", ".env", "backup key.txt"} {
		got, err := SafeFileName(name)
		if err != nil {
			t.Fatalf("%q should be valid: %v", name, err)
		}
		if got != name {
			t.Fatalf("SafeFileName(%q) = %q", name, got)
		}
	}
	for _, name := range []string{
		"",
		".",
		"..",
		"../key.pem",
		"nested/key.pem",
		`\..\key.pem`,
		`nested\key.pem`,
		"/tmp/key.pem",
		" key.pem",
		"key.pem ",
		"key\n.pem",
	} {
		if _, err := SafeFileName(name); err == nil {
			t.Fatalf("%q should be rejected", name)
		}
	}
}

func TestNewFileFieldStoresOnlySafeBasename(t *testing.T) {
	field, err := NewFileField("/tmp/key.pem", "", []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := FileFromField(field)
	if err != nil {
		t.Fatal(err)
	}
	if value.Name != "key.pem" {
		t.Fatalf("stored name = %q, want key.pem", value.Name)
	}
	if _, err := NewFileField(`nested\key.pem`, "", []byte("key")); err == nil {
		t.Fatal("platform-alternate separator should be rejected")
	}
}

// TestNotesReservedField covers notes as a reserved top-level text field.
func TestNotesReservedField(t *testing.T) {
	t.Run("set, read, round trip", func(t *testing.T) {
		item := New("GitHub", nil)
		if err := item.SetNotes("Konsole nur über VPN.\nBackup-Codes im Safe."); err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := back.Notes(); got != item.Notes() {
			t.Fatalf("notes round trip: got %q, want %q", got, item.Notes())
		}
	})

	t.Run("stored as an ordinary text field so old clients keep it", func(t *testing.T) {
		item := New("GitHub", nil)
		if err := item.SetNotes("hello"); err != nil {
			t.Fatal(err)
		}
		if len(item.Fields) != 1 {
			t.Fatalf("expected one field, got %d", len(item.Fields))
		}
		if item.Fields[0].Type != FieldText || item.Fields[0].Name != NotesFieldName {
			t.Fatalf("notes stored as %s/%q, want %s/%q",
				item.Fields[0].Type, item.Fields[0].Name, FieldText, NotesFieldName)
		}
	})

	t.Run("empty removes the field entirely", func(t *testing.T) {
		item := New("GitHub", nil)
		if err := item.SetNotes("hello"); err != nil {
			t.Fatal(err)
		}
		if err := item.SetNotes(""); err != nil {
			t.Fatal(err)
		}
		if len(item.Fields) != 0 {
			t.Fatalf("empty notes must leave no field, got %d", len(item.Fields))
		}
		raw, _ := json.Marshal(item)
		if bytes.Contains(raw, []byte(NotesFieldName)) {
			t.Fatalf("empty notes must not appear on the wire: %s", raw)
		}
	})

	t.Run("a nested notes field is not the item's notes", func(t *testing.T) {
		item, err := Decode([]byte(`{"title":"GitHub","fields":[
			{"type":"section","name":"Server","fields":[
				{"type":"text","name":"notes","value":"gehört zum Abschnitt"}]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		if got := item.Notes(); got != "" {
			t.Fatalf("nested notes must not be claimed as the item's notes, got %q", got)
		}
	})

	t.Run("an oversized note is rejected, not written", func(t *testing.T) {
		item := &Item{Title: "GitHub"}
		err := item.SetNotes(strings.Repeat("a", MaxValueBytes+1))
		if err == nil {
			t.Fatal("a note past MaxValueBytes must be rejected by SetNotes")
		}
		// Without this the note is stored and only fails later, on decode.
		raw, marshalErr := json.Marshal(item)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, decErr := Decode(raw); decErr == nil {
			t.Fatal("the rejected note must not have produced a decodable item")
		}
	})

	t.Run("writing notes stamps the item, a no-op removal does not", func(t *testing.T) {
		item := &Item{Title: "GitHub"}
		if err := item.SetNotes("erste"); err != nil {
			t.Fatal(err)
		}
		stamped := item.Meta
		if stamped == nil {
			t.Fatal("SetNotes must stamp the item, as SetField does")
		}
		fresh := &Item{Title: "GitHub"}
		if err := fresh.SetNotes(""); err != nil {
			t.Fatal(err)
		}
		if fresh.Meta != nil {
			t.Fatal("removing a note that never existed must not stamp the item")
		}
	})

	t.Run("an item without notes decodes", func(t *testing.T) {
		back, err := Decode([]byte(`{"title":"GitHub","fields":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		if back.Notes() != "" {
			t.Fatalf("notes should default to empty, got %q", back.Notes())
		}
	})
}

// TestUnknownKeysSurviveRoundTrip is the forward-compatibility guarantee: a
// build that does not understand a key must not delete it when writing the item
// back. Without this, upgrading one client silently destroys data written by a
// newer one.
func TestUnknownKeysSurviveRoundTrip(t *testing.T) {
	const future = `{
		"title": "GitHub",
		"urls": ["https://github.com"],
		"colour": "amber",
		"attachments": [{"id": "a1"}],
		"fields": [
			{"type": "secret", "name": "password", "value": "x", "autofillHint": "current-password"}
		],
		"meta": {"revision": 3}
	}`

	item, err := Decode([]byte(future))
	if err != nil {
		t.Fatalf("an item with unknown keys must still decode: %v", err)
	}

	// A normal edit by this build.
	item.Title = "GitHub (edited)"

	out, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}

	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back["colour"] != "amber" {
		t.Fatalf("unknown top-level key was dropped: %s", out)
	}
	if _, ok := back["attachments"]; !ok {
		t.Fatalf("unknown top-level array was dropped: %s", out)
	}
	if back["title"] != "GitHub (edited)" {
		t.Fatalf("known key was not updated: %s", out)
	}

	fields, ok := back["fields"].([]any)
	if !ok || len(fields) != 1 {
		t.Fatalf("fields malformed: %s", out)
	}
	first, ok := fields[0].(map[string]any)
	if !ok {
		t.Fatalf("field malformed: %s", out)
	}
	if first["autofillHint"] != "current-password" {
		t.Fatalf("unknown key inside a field was dropped: %s", out)
	}
	if first["name"] != "password" {
		t.Fatalf("known field key was lost: %s", out)
	}
}
