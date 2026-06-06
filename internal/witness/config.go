package witness

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the operator-supplied configuration for one witness
// process. Loaded from TOML at boot; never reloaded at runtime
// (operators restart the witness for changes — keeps the state
// machine small).
//
// One Witness instance handles many Targets. Each Target has its
// own server URL, pinned pubkey, list of chains to poll, and poll
// interval. Mixing servers under one witness is fine — the shared
// SQLite archive groups STHs by server_url so cross-server
// equivocation evidence (which is impossible: equivocation is a
// per-server property) doesn't muddle.
type Config struct {
	Targets []Target `toml:"target"`
}

// Target is one (server, pubkey, chains, interval) tuple.
type Target struct {
	ServerURL    string        `toml:"server_url"`
	ServerPubHex string        `toml:"server_pub"`     // hex-encoded ed25519 pubkey
	ServerPub    []byte        `toml:"-"`              // decoded; populated by Validate
	Chains       []string      `toml:"chains"`         // e.g. ["user:abc12345", "scope:s_..."]
	PollInterval time.Duration `toml:"poll_interval"`  // e.g. "1h"; default 1h

	// AutoDiscover pulls the chain list from GET /v1/chains on every
	// poll round and merges it with the static Chains slice above.
	// New chains start being polled the next round; deleted ones (if
	// the server ever removed any) are still re-polled until removed
	// from the static list. Safe to combine with Chains — the union
	// is deduplicated.
	//
	// Off by default to preserve the explicit-pinning posture of the
	// original config. Recommended on for self-hosted deployments
	// where one operator owns both server and witness.
	AutoDiscover bool `toml:"auto_discover"`

	// PinOnFirstUse fetches the server pubkey from GET /v1/server-info
	// on the first poll and pins whatever the server returns. SSH-
	// known_hosts model: subsequent changes get rejected via
	// Store.ErrPinMismatch, so a witness that pinned correctly on day 1
	// catches a key swap on day 2.
	//
	// Footgun: `/v1/server-info` is self-signed — the server signs the
	// pubkey announcement with the very key it presents. A MITM at
	// first contact pins the attacker's key. The witness is then
	// cosigning the attacker's STHs, not the real server's; anyone
	// who cross-checks the witness's published cosigns against the
	// real server pubkey (shown on the website, in another witness's
	// archive) detects the divergence.
	//
	// Safe for self-hosted deployments where the same operator owns
	// both server and witness — the bootstrap window is under that
	// operator's control. Not safe for independent witnesses watching
	// a server they don't control: pin server_pub explicitly out-of-
	// band.
	//
	// When set, ServerPubHex may be empty. The pin lives in the
	// witness store after first contact regardless of config.
	PinOnFirstUse bool `toml:"pin_on_first_use"`
}

// LoadConfig reads and validates a TOML config file.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate decodes ServerPubHex into ServerPub and applies defaults.
// Idempotent — Validate may be called multiple times safely.
func (c *Config) Validate() error {
	if len(c.Targets) == 0 {
		return errors.New("witness config: at least one [[target]] required")
	}
	for i := range c.Targets {
		t := &c.Targets[i]
		if t.ServerURL == "" {
			return fmt.Errorf("target #%d: server_url required", i)
		}
		// Validate as URL with scheme + host. Strip trailing slash
		// for storage-key consistency.
		u, err := url.Parse(t.ServerURL)
		if err != nil {
			return fmt.Errorf("target #%d: server_url parse: %w", i, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("target #%d: server_url must include scheme and host: %q", i, t.ServerURL)
		}
		t.ServerURL = strings.TrimRight(t.ServerURL, "/")
		hexStr := strings.TrimSpace(t.ServerPubHex)
		if hexStr == "" {
			if !t.PinOnFirstUse {
				return fmt.Errorf("target %s: server_pub required (or set pin_on_first_use=true)", t.ServerURL)
			}
			// TOFU mode — the pub is fetched from /v1/server-info on
			// first poll and persisted by Store.PinServer.
			t.ServerPub = nil
		} else {
			raw, err := hex.DecodeString(hexStr)
			if err != nil {
				return fmt.Errorf("target %s: server_pub hex decode: %w", t.ServerURL, err)
			}
			if len(raw) != 32 {
				return fmt.Errorf("target %s: server_pub must be 32 bytes (got %d)", t.ServerURL, len(raw))
			}
			t.ServerPub = raw
		}
		if len(t.Chains) == 0 && !t.AutoDiscover {
			return fmt.Errorf("target %s: at least one chain required (or set auto_discover=true)", t.ServerURL)
		}
		for _, ch := range t.Chains {
			if !strings.HasPrefix(ch, "user:") && !strings.HasPrefix(ch, "scope:") {
				return fmt.Errorf("target %s: chain %q must start with %q or %q", t.ServerURL, ch, "user:", "scope:")
			}
		}
		if t.PollInterval <= 0 {
			t.PollInterval = time.Hour
		}
		if t.PollInterval < time.Second {
			return fmt.Errorf("target %s: poll_interval must be at least 1s", t.ServerURL)
		}
	}
	return nil
}

// SaveConfig writes a (validated) config back to disk. Operators
// editing the config by hand should use TOML directly; this helper
// exists for future tooling that adds/removes targets
// programmatically. Existing comments are NOT preserved (toml.Encode
// is property-only).
func SaveConfig(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := toml.NewEncoder(f)
	enc.Indent = ""
	if err := enc.Encode(cfg); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
