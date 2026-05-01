package fdhome

import (
	"errors"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the user-editable ~/.fd0/config.toml. All fields are optional;
// missing files / fields fall back to documented defaults.
type Config struct {
	ShortID   string          `toml:"short_id"`
	Sync      SyncConfig      `toml:"sync"`
	Client    ClientConfig    `toml:"client"`
	Agent     AgentConfig     `toml:"agent"`
	Clipboard ClipboardConfig `toml:"clipboard"`
}

// AgentConfig collects fd0-agent lifecycle knobs. Read by the agent when the
// matching CLI flag / env var are not set. Precedence: flag > env > config >
// default. Empty strings here mean "fall through to the next layer".
type AgentConfig struct {
	// IdleTimeout is a Go duration string ("5m", "30m"). Empty = use default.
	// Overridden by --idle-timeout flag and FD0_AGENT_IDLE env.
	IdleTimeout string `toml:"idle_timeout"`
	// MaxLifetime is a Go duration string ("8h", "24h"). Empty = use default.
	// Overridden by --max-lifetime flag and FD0_AGENT_MAX_LIFETIME env.
	MaxLifetime string `toml:"max_lifetime"`
}

// ClientConfig collects per-CLI knobs that aren't sync-related.
type ClientConfig struct {
	// LockWait is a Go duration string ("10s", "1m"). Empty = fail fast on
	// flock contention. Overridden by FD0_LOCK_WAIT env when set.
	LockWait string `toml:"lock_wait"`
}

// SyncConfig drives the agent-managed background sync.
type SyncConfig struct {
	// Server is the fd0-server URL the agent should sync against. Falls
	// back to FD0_SERVER env if empty.
	Server string `toml:"server"`
	// Interval as Go duration string ("1h", "5m"). Empty/zero disables.
	Interval string `toml:"interval"`
	// OnUnlock controls the post-unlock auto-sync. Pointer so we can
	// distinguish "absent" (apply default = true) from "explicitly false".
	OnUnlock *bool `toml:"on_unlock"`
}

// OnUnlockEnabled returns the effective on-unlock flag. Default is true
// when not set in config.
func (c SyncConfig) OnUnlockEnabled() bool {
	if c.OnUnlock == nil {
		return true
	}
	return *c.OnUnlock
}

// ClipboardConfig tunes `fd0 copy`. Read by the CLI when the user does not
// pass `--clear-after` on the command line.
type ClipboardConfig struct {
	// ClearAfterSeconds: 0 = disabled. Default applied by the CLI is 30s.
	ClearAfterSeconds int `toml:"clear_after_seconds"`
}

// LoadConfig reads ~/.fd0/config.toml. A missing file is not an error.
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return c, err
	}
	if _, err := toml.Decode(string(data), &c); err != nil {
		return c, err
	}
	return c, nil
}

// SyncIntervalDuration parses Sync.Interval; "" / parse-failure / zero return
// 0 meaning "auto-sync disabled".
func (c Config) SyncIntervalDuration() time.Duration {
	if c.Sync.Interval == "" {
		return 0
	}
	d, err := time.ParseDuration(c.Sync.Interval)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}
