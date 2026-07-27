package desktopbridge

import "testing"

func TestValidateSSHKeyMetadata(t *testing.T) {
	for _, test := range []struct {
		name    string
		keyName string
		comment string
		wantErr bool
	}{
		{name: "valid", keyName: "deploy", comment: "ops@example.com"},
		{name: "empty name", comment: "ops@example.com", wantErr: true},
		{name: "name newline", keyName: "deploy\nforged", wantErr: true},
		{name: "comment newline", keyName: "deploy", comment: "ops@example.com\nssh-ed25519 forged", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSSHKeyMetadata(test.keyName, test.comment)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateSSHKeyMetadata() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
