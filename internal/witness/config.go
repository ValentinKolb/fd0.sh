package witness

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Config is the operator-supplied configuration for one witness
// process. One witness watches exactly one fd0-server — to watch
// multiple servers, run multiple witness containers (process
// isolation, independent storage, independent metrics; the binary
// is ~18 MB scratch and idle-cheap).
//
// Source of truth is env or flags via the cmd/fd0-witness CLI
// struct. No file format — fewer ways to misconfigure, no parser
// surface to test.
type Config struct {
	// ServerURL is the fd0-server this witness watches. Scheme + host
	// required; trailing slash is stripped.
	ServerURL string

	// ServerPub is the server's ed25519 cosign pubkey, the trust
	// anchor for every STH signature check. Set explicitly out-of-band
	// for an independent witness. Leave empty + set PinOnFirstUse for
	// self-host (TOFU on first contact).
	ServerPub []byte
	// ServerPubHex is the operator-facing form of ServerPub; Validate
	// decodes it into ServerPub. May be empty when PinOnFirstUse is
	// true.
	ServerPubHex string

	// PollInterval between rounds. Minimum 1 s. Default 30 s when
	// non-positive.
	PollInterval time.Duration

	// AutoDiscover refreshes the chain list from GET /v1/chains on
	// every poll round and unions it with Chains (deduplicated). When
	// false and Chains is empty, Validate fails.
	AutoDiscover bool

	// PinOnFirstUse fetches the server pubkey from GET /v1/server-info
	// on first poll and persists it via Store.PinServer (SSH-
	// known_hosts semantics; later changes fail with ErrPinMismatch).
	//
	// Footgun: /v1/server-info is self-signed, so a MITM at first
	// contact pins the attacker's key. Safe for self-host where one
	// operator runs both server and witness; for independent witnesses,
	// set ServerPubHex explicitly out-of-band instead.
	PinOnFirstUse bool

	// Chains is an explicit allow-list of chains to poll. Empty +
	// AutoDiscover = "poll whatever the server reports". Each entry
	// must start with "user:" or "scope:".
	Chains []string
}

// Validate decodes ServerPubHex into ServerPub and applies defaults.
// Idempotent — Validate may be called multiple times safely.
func (c *Config) Validate() error {
	if c.ServerURL == "" {
		return errors.New("witness: ServerURL required")
	}
	u, err := url.Parse(c.ServerURL)
	if err != nil {
		return fmt.Errorf("witness: server_url parse: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("witness: server_url must include scheme and host: %q", c.ServerURL)
	}
	c.ServerURL = strings.TrimRight(c.ServerURL, "/")

	hexStr := strings.TrimSpace(c.ServerPubHex)
	if hexStr == "" {
		if !c.PinOnFirstUse {
			return errors.New("witness: server_pub required (or set pin_on_first_use=true)")
		}
		c.ServerPub = nil
	} else {
		raw, err := hex.DecodeString(hexStr)
		if err != nil {
			return fmt.Errorf("witness: server_pub hex decode: %w", err)
		}
		if len(raw) != 32 {
			return fmt.Errorf("witness: server_pub must be 32 bytes (got %d)", len(raw))
		}
		c.ServerPub = raw
	}

	if len(c.Chains) == 0 && !c.AutoDiscover {
		return errors.New("witness: at least one chain required (or set auto_discover=true)")
	}
	for _, ch := range c.Chains {
		if !strings.HasPrefix(ch, "user:") && !strings.HasPrefix(ch, "scope:") {
			return fmt.Errorf("witness: chain %q must start with %q or %q", ch, "user:", "scope:")
		}
	}

	if c.PollInterval <= 0 {
		c.PollInterval = 30 * time.Second
	}
	if c.PollInterval < time.Second {
		return errors.New("witness: poll_interval must be at least 1s")
	}
	return nil
}
