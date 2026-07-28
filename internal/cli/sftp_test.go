package cli

import (
	"reflect"
	"testing"
)

func TestSFTPSubsystemArgsKeepOpenSSHSecurityAndHostOrdering(t *testing.T) {
	connection := OpenSSHConnection{
		Alias:      "production",
		ConfigPath: "/tmp/fd0 connect.conf",
		SSHBinary:  "/usr/bin/ssh",
	}
	want := []string{
		"-F", "/tmp/fd0 connect.conf",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-s", "production", "sftp",
	}
	if got := connection.SFTPSubsystemArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%q want=%q", got, want)
	}
}

func TestSFTPCopyRequiresExactlyOneRemoteOperand(t *testing.T) {
	for _, test := range []struct {
		source string
		dest   string
		valid  bool
	}{
		{source: "./local", dest: "remote:/srv/file", valid: true},
		{source: "remote:/srv/file", dest: "./local", valid: true},
		{source: "./one", dest: "./two", valid: false},
		{source: "remote:/one", dest: "remote:/two", valid: false},
	} {
		_, err := validateSFTPCopyOperands(test.source, test.dest)
		if got := err == nil; got != test.valid {
			t.Fatalf("source=%q dest=%q valid=%v err=%v", test.source, test.dest, got, err)
		}
	}
}

func TestRemotePathValidation(t *testing.T) {
	if got, err := requiredRemotePath("remote:/srv/app"); err != nil || got != "/srv/app" {
		t.Fatalf("path=%q err=%v", got, err)
	}
	for _, invalid := range []string{"", "remote:", "bad\x00path"} {
		if _, err := requiredRemotePath(invalid); err == nil {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
	for _, valid := range []string{"-leading", "folder with spaces/file", "资料/über"} {
		if got, err := requiredRemotePath(valid); err != nil || got != valid {
			t.Fatalf("valid path=%q got=%q err=%v", valid, got, err)
		}
	}
}
