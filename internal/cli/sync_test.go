package cli

import (
	"testing"
	"time"
)

func TestRetryAfterDelay(t *testing.T) {
	const max = 30 * time.Second
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", time.Second},          // empty → default 1s
		{"garbage", time.Second},   // unparseable → default
		{"0", time.Second},         // non-positive → default
		{"-5", time.Second},        // negative → default
		{"3", 3 * time.Second},     // normal
		{" 7 ", 7 * time.Second},   // whitespace tolerated
		{"999", max},               // clamped to max
	}
	for _, c := range cases {
		if got := retryAfterDelay(c.header, max); got != c.want {
			t.Errorf("retryAfterDelay(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}
