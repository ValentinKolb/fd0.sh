package passitem

import (
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
