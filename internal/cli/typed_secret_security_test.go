package cli

import (
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestCheckedTypedWritePreconditions(t *testing.T) {
	pass := &proto.SecretRecord{Name: "pass:item", Type: "fd0-pass"}
	host := &proto.SecretRecord{Name: "host:item", Type: "fd0-host"}

	tests := []struct {
		name           string
		current        *proto.SecretRecord
		requireMissing bool
		expectedType   string
		wantError      string
	}{
		{name: "create missing", requireMissing: true},
		{name: "create collision", current: host, requireMissing: true, wantError: "already exists"},
		{name: "update matching", current: pass, expectedType: "fd0-pass"},
		{name: "update missing", expectedType: "fd0-pass", wantError: "not found"},
		{name: "update cross type", current: host, expectedType: "fd0-pass", wantError: `has type "fd0-host"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkTypedWriteTarget("item", tt.current, tt.requireMissing, tt.expectedType)
			if tt.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("err=%v, want %q", err, tt.wantError)
			}
		})
	}
}
