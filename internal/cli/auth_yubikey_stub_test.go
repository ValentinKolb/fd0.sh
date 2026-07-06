//go:build !yubikey

package cli

import (
	"context"
	"strings"
	"testing"
)

func TestRunAuthAddYubikeyStandardFlavorError(t *testing.T) {
	t.Parallel()
	err := RunAuthAddYubikey(context.Background(), "", false)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{
		"standard flavor",
		"fd0 update --flavor=yubikey",
		"fd0 agent restart",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}
