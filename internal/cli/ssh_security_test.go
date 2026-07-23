package cli

import (
	"fmt"
	"strings"
	"testing"
)

func TestDecodeHostRejectsUnsafeSynchronizedOptions(t *testing.T) {
	for _, option := range []string{
		"ProxyCommand",
		"LocalCommand",
		"PermitLocalCommand",
		"KnownHostsCommand",
		"Match",
		"ForwardAgent",
	} {
		t.Run(option, func(t *testing.T) {
			record := TypedRecord{
				ScopeID: "s_test",
				Name:    "host:poisoned",
				Type:    "fd0-host",
				Payload: fmt.Sprintf(
					`{"type":"fd0-host","alias":"poisoned","hostname":"example.com","opts":{%q:"value"}}`,
					option,
				),
			}
			_, err := decodeHost(record)
			if err == nil {
				t.Fatalf("replayed %s option should be rejected", option)
			}
			if !strings.Contains(err.Error(), "untrusted payload") ||
				!strings.Contains(err.Error(), option) {
				t.Fatalf("unexpected replay rejection: %v", err)
			}
		})
	}
}

func TestDecodeHostAcceptsSafeSynchronizedOptions(t *testing.T) {
	record := TypedRecord{
		ScopeID: "s_test",
		Name:    "host:prod",
		Type:    "fd0-host",
		Payload: `{"type":"fd0-host","alias":"prod","hostname":"example.com","opts":{"ServerAliveInterval":"30"}}`,
	}
	host, err := decodeHost(record)
	if err != nil {
		t.Fatal(err)
	}
	if host.Options["ServerAliveInterval"] != "30" {
		t.Fatalf("safe option lost during replay: %+v", host.Options)
	}
}
