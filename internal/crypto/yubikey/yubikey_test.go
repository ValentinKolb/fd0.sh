package yubikey

import "testing"

// Note: TestStubBuild_NoSurprises is gated to the no-tag build via the
// _stub_test.go file. Tests in this file run in both build modes.

func TestValidatePIN(t *testing.T) {
	cases := []struct {
		pin     string
		wantErr bool
	}{
		{"", true},          // empty: too short
		{"12345", true},     // 5 chars: too short
		{"123456", false},   // 6 chars: ok
		{"12345678", false}, // 8 chars: max
		{"123456789", true}, // 9 chars: too long
		{"abcdef", false},   // ASCII letters ok
		{"abc 12", false},   // space is printable ASCII
		{"abc\n12", true},   // control char rejected
		{"abc\t12", true},   // tab rejected
		{"abc🙂12", true},   // multi-byte UTF-8 rejected (Yubico PIV is ASCII)
	}
	for _, c := range cases {
		err := ValidatePIN([]byte(c.pin))
		if (err != nil) != c.wantErr {
			t.Errorf("ValidatePIN(%q) err=%v, wantErr=%v", c.pin, err, c.wantErr)
		}
	}
}

