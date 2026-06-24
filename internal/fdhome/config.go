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
	ShortID   string           `toml:"short_id"`
	Sync      SyncConfig       `toml:"sync"`
	Client    ClientConfig     `toml:"client"`
	Agent     AgentConfig      `toml:"agent"`
	Clipboard ClipboardConfig  `toml:"clipboard"`
	Witnesses []WitnessConfig  `toml:"witness"`        // [[witness]] entries
	WitnessP  WitnessPolicy    `toml:"witness_policy"` // global cross-check policy
}

// WitnessConfig is one configured witness the client trusts. Per
// TRANSLOG.md §10 the witness pubkey is operator-pinned (no TOFU)
// because witnesses are operational identities, not peer-to-peer.
type WitnessConfig struct {
	URL    string `toml:"url"`
	PubHex string `toml:"pub"` // hex ed25519 pubkey
}

// WitnessPolicy expresses the cross-check policy: how many cosigns
// the client requires per sync round.
//
// MinCosigns is INDEPENDENT of len(Witnesses): the operator can
// configure 3 witnesses but require only 2 matching cosigns,
// leaving headroom for a single witness outage. A lagging or
// unreachable witness simply doesn't contribute, so MinCosigns is
// the absolute floor — there is no "lag tolerance" knob that
// silently lowers it (codex fix #3 hardened this against the
// timing-game attack where an adversary could DOS witnesses to
// drive the threshold to zero).
//
// Default policy (MinCosigns=0) DISABLES cross-check entirely; this
// matches the v1 OPTIONAL spec stance and lets single-user installs
// run without any witness infrastructure.
type WitnessPolicy struct {
	MinCosigns int `toml:"min_cosigns"`
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
	// Server is the LEGACY single-server URL. Kept for backward
	// compatibility with pre-v0.0.4 configs; when both Server and
	// Servers are set, Servers wins. Falls back to FD0_SERVER env
	// downstream if both are empty.
	Server string `toml:"server"`
	// Servers is the configured server list. fd0 writes/reads to a SINGLE
	// primary (see REPLICATION.md): a scope has exactly one ordering
	// authority, so replicas can never diverge. A config listing more than
	// one server is therefore a hard error (RunSyncAll surfaces it) — for
	// redundancy run a server-side DR backup (FD0_REPLICATE_FROM), not a
	// second write target. Empty falls back to Server, then env, then
	// DefaultServers.
	Servers []string `toml:"servers"`
	// Interval as Go duration string ("1h", "5m"). Empty/zero disables.
	Interval string `toml:"interval"`
	// OnUnlock controls the post-unlock auto-sync. Pointer so we can
	// distinguish "absent" (apply default = true) from "explicitly false".
	OnUnlock *bool `toml:"on_unlock"`
}

// DefaultServers is the hard-coded fallback when the user has neither
// Sync.Servers, Sync.Server, nor FD0_SERVER set. Points at the hosted
// fd0.sh primary described in docs/HOSTING.md — a self-hoster who runs
// `fd0 init` against their own server immediately overwrites this by
// writing config.toml. Exactly one entry: fd0 has a single write/read
// authority; redundancy is a server-side DR backup, not a second URL.
var DefaultServers = []string{
	"https://api.fd0.sh",
}

// ResolvedServers returns the effective server list, applying the
// precedence: explicit Servers > legacy singular Server > defaults.
// Callers add the flag/env override one level up — this stays config-
// only so it's pure and unit-testable. The single-primary invariant
// (len <= 1) is enforced by the sync entry point, not here, so this
// stays a pure projection of config.
func (c SyncConfig) ResolvedServers() []string {
	if len(c.Servers) > 0 {
		out := make([]string, 0, len(c.Servers))
		for _, s := range c.Servers {
			if s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if c.Server != "" {
		return []string{c.Server}
	}
	return append([]string(nil), DefaultServers...)
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

// WitnessCrossCheckEnabled returns true iff the client should
// perform cross-check on every sync. Disabled when no witnesses are
// configured OR MinCosigns is zero. Either knob can disable it
// independently — operators turning min_cosigns to 0 temporarily
// shouldn't have to also delete every [[witness]] block.
func (c Config) WitnessCrossCheckEnabled() bool {
	return len(c.Witnesses) > 0 && c.WitnessP.MinCosigns > 0
}
