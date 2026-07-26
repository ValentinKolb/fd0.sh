package main

import (
	"strings"
	"testing"
	"time"
)

func TestResolveDuration(t *testing.T) {
	tests := []struct {
		name      string
		flag      string
		config    string
		fallback  time.Duration
		want      time.Duration
		wantError string
	}{
		{name: "fallback", fallback: 5 * time.Minute, want: 5 * time.Minute},
		{name: "config", config: "30m", fallback: 5 * time.Minute, want: 30 * time.Minute},
		{name: "flag wins", flag: "10m", config: "30m", fallback: 5 * time.Minute, want: 10 * time.Minute},
		{name: "zero rejected", flag: "0s", wantError: "greater than zero"},
		{name: "negative rejected", config: "-1m", wantError: "greater than zero"},
		{name: "invalid rejected", config: "later", wantError: "invalid duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveDuration(tt.flag, tt.config, tt.fallback, "idle-timeout")
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("err = %v, want substring %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("duration = %v, want %v", got, tt.want)
			}
		})
	}
}
