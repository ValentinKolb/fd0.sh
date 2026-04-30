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
	Clipboard ClipboardConfig `toml:"clipboard"`
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

// ClipboardConfig is reserved for the v1.x clipboard tuning section.
type ClipboardConfig struct {
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
