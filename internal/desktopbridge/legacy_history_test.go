package desktopbridge

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/cli"
)

// A vault written by the retired v1 compactor is the one failure a user can
// hit on an otherwise healthy install. It must never reach the UI as the
// generic "fd0 could not complete that action" — the message has to say what
// the vault is, what has to happen, and that nothing was changed.
func TestMapDomainErrorExplainsLegacyHistoryRepair(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		code      string
		retryable bool
		message   []string
		action    []string
	}{
		{
			name:      "offline or unpinned",
			err:       fmt.Errorf("scope s_abc: %w: connection refused", cli.ErrLegacyScopeHistoryNeedsServer),
			code:      "legacy_history_repair_offline",
			retryable: true,
			message:   []string{"older version of fd0", "one-time repair", "fd0 server"},
			action:    []string{"Sync", "Nothing on this device has been changed", "safe to try again"},
		},
		{
			name:      "server history does not match the local anchor",
			err:       fmt.Errorf("scope s_abc: %w: tip mismatch", cli.ErrLegacyScopeHistoryUnverifiable),
			code:      "legacy_history_repair_blocked",
			retryable: false,
			message:   []string{"older version of fd0", "does not match the history this device already trusts"},
			action:    []string{"fd0 sync", "Nothing on this device has been changed"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mapped := mapDomainError(tc.err)
			var typed *methodError
			if !errors.As(mapped, &typed) {
				t.Fatalf("error was not mapped to a bridge error: %v", mapped)
			}
			if typed.bridge.Code != tc.code {
				t.Fatalf("code = %q, want %q", typed.bridge.Code, tc.code)
			}
			if typed.bridge.Retryable != tc.retryable {
				t.Fatalf("retryable = %v, want %v", typed.bridge.Retryable, tc.retryable)
			}
			for _, want := range tc.message {
				if !strings.Contains(typed.bridge.Message, want) {
					t.Fatalf("message %q is missing %q", typed.bridge.Message, want)
				}
			}
			for _, want := range tc.action {
				if !strings.Contains(typed.bridge.Action, want) {
					t.Fatalf("action %q is missing %q", typed.bridge.Action, want)
				}
			}
			if strings.Contains(typed.bridge.Message, "could not complete that action") {
				t.Fatal("legacy-history failure fell back to the generic message")
			}
		})
	}
}
