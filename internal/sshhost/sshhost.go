// Package sshhost is the structured-data layer for SSH hosts managed
// by fd0. A Host is stored in the vault as a JSON secret with a
// `type` discriminator so the agent and CLI can filter SSH hosts out
// of the same secret-store the rest of fd0 uses. Render takes a slice
// of Hosts plus a known socket path and emits a valid ssh_config
// snippet ready to be Include'd from the user's ~/.ssh/config.
//
// The renderer is a pure function: same Hosts in → same bytes out.
// This is what makes the "auto-render on every vault mutation"
// invariant cheap; we don't need to compare against the on-disk file
// to decide whether to write, the bytes themselves are the cache key.
package sshhost

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// TypeHost is the JSON `type` discriminator for fd0-managed SSH hosts.
// Anything in the vault tagged with this type is rendered into
// ~/.ssh/fd0.conf; everything else (including raw string secrets, key
// blobs, future kube clusters, ...) is ignored by this package.
const TypeHost = "fd0-host"

// Host is the in-memory representation of one fd0-managed SSH host.
// Marshal/Unmarshal round-trip through the JSON shape (see JSON).
type Host struct {
	Alias       string            // unique within a scope; the SSH `Host X` directive
	Hostname    string            // -> ssh_config HostName
	User        string            // -> User, omitempty
	Port        int               // -> Port, omit if 0 or 22
	KeyName     string            // fd0 key secret name (without prefix); resolved at render
	ProxyJump   string            // another fd0 host alias OR raw ssh-style spec
	Tags        []string          // shared metadata, embedded as comment
	Description string            // shared metadata, embedded as comment
	Options     map[string]string // verbatim ssh_config Key Value pairs (ForwardAgent, etc.)
	Scope       string            // SOURCE scope; not part of the JSON value, set by the loader
}

// JSON is the on-the-wire shape stored as a fd0 secret value. Keep
// field names short — they end up in CBOR-encoded events that we sync
// across the network on every push.
type JSON struct {
	Type        string            `json:"type"`
	Alias       string            `json:"alias"`
	Hostname    string            `json:"hostname"`
	User        string            `json:"user,omitempty"`
	Port        int               `json:"port,omitempty"`
	KeyName     string            `json:"key,omitempty"`
	ProxyJump   string            `json:"jump,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Description string            `json:"desc,omitempty"`
	Options     map[string]string `json:"opts,omitempty"`
}

// Marshal serialises a Host to its JSON form. The scope is NOT part
// of the value because scope membership is communicated by where the
// secret lives, not by the value itself.
func (h *Host) Marshal() JSON {
	return JSON{
		Type:        TypeHost,
		Alias:       h.Alias,
		Hostname:    h.Hostname,
		User:        h.User,
		Port:        h.Port,
		KeyName:     h.KeyName,
		ProxyJump:   h.ProxyJump,
		Tags:        h.Tags,
		Description: h.Description,
		Options:     h.Options,
	}
}

// Unmarshal recovers a Host. The scope must be set by the caller from
// the source of the secret; this function deliberately ignores any
// `Scope` field that might be present in the JSON (forward-compat
// guard against badly-migrated data).
func Unmarshal(j JSON) (*Host, error) {
	if j.Type != TypeHost {
		return nil, fmt.Errorf("sshhost: wrong type %q want %q", j.Type, TypeHost)
	}
	if j.Alias == "" {
		return nil, fmt.Errorf("sshhost: empty alias")
	}
	if j.Hostname == "" {
		return nil, fmt.Errorf("sshhost: empty hostname for alias %q", j.Alias)
	}
	return &Host{
		Alias:       j.Alias,
		Hostname:    j.Hostname,
		User:        j.User,
		Port:        j.Port,
		KeyName:     j.KeyName,
		ProxyJump:   j.ProxyJump,
		Tags:        j.Tags,
		Description: j.Description,
		Options:     j.Options,
	}, nil
}

// aliasRE bounds host aliases: SSH config aliases are conventionally
// alphanumeric + hyphen + dot + underscore. Whitespace and special
// shell characters break the `Host X` directive's tokenisation, so we
// reject them at the data layer.
var aliasRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate runs a strict sanity check at write time so the vault never
// holds a host that would render to a malformed ssh_config.
func (h *Host) Validate() error {
	if !aliasRE.MatchString(h.Alias) {
		return fmt.Errorf("sshhost: alias %q must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}", h.Alias)
	}
	if h.Hostname == "" {
		return fmt.Errorf("sshhost: alias %q has empty hostname", h.Alias)
	}
	// Reject newlines + whitespace + control chars in fields that
	// render verbatim into ssh_config directives. Without this a
	// shared payload like hostname="x\n    ProxyCommand sh -c …"
	// would inject executable directives downstream — high impact
	// because the host record is scope-shared, so any teammate who
	// renders the config would execute the injected command on
	// connection.
	if err := rejectControl("hostname", h.Hostname); err != nil {
		return fmt.Errorf("sshhost: alias %q %w", h.Alias, err)
	}
	if h.User != "" {
		if err := rejectControl("user", h.User); err != nil {
			return fmt.Errorf("sshhost: alias %q %w", h.Alias, err)
		}
	}
	if h.ProxyJump != "" {
		if err := rejectControl("proxy-jump", h.ProxyJump); err != nil {
			return fmt.Errorf("sshhost: alias %q %w", h.Alias, err)
		}
	}
	if h.Port < 0 || h.Port > 65535 {
		return fmt.Errorf("sshhost: alias %q port %d out of range", h.Alias, h.Port)
	}
	if h.Description != "" {
		if err := rejectControl("description", h.Description); err != nil {
			return fmt.Errorf("sshhost: alias %q %w", h.Alias, err)
		}
	}
	// Tags land verbatim in the `#@fd0:tags=<csv>` metadata comment.
	// A newline in a tag closes the comment and lets the rest land as
	// a real ssh_config directive — same class as the hostname/proxy-
	// jump injection. Commas would also corrupt the csv parse.
	for _, t := range h.Tags {
		if strings.ContainsRune(t, ',') {
			return fmt.Errorf("sshhost: alias %q tag %q contains comma", h.Alias, t)
		}
		if err := rejectControl("tag", t); err != nil {
			return fmt.Errorf("sshhost: alias %q %w", h.Alias, err)
		}
	}
	for k, v := range h.Options {
		if strings.ContainsAny(k, " \t") {
			return fmt.Errorf("sshhost: option key %q contains whitespace", k)
		}
		if err := rejectControl("option-key", k); err != nil {
			return fmt.Errorf("sshhost: alias %q %w", h.Alias, err)
		}
		if err := rejectControl("option-value", v); err != nil {
			return fmt.Errorf("sshhost: alias %q %w", h.Alias, err)
		}
	}
	return nil
}

// rejectControl returns an error if v contains a control character
// (\x00..\x1f, \x7f) — including newlines and tabs. Used by Validate
// to keep render-verbatim fields safe.
func rejectControl(field, v string) error {
	for i, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s contains control char at offset %d (0x%02x)", field, i, r)
		}
	}
	return nil
}

// ParseConnString parses a `[user@]hostname[:port]` shorthand into
// the typed fields. Used by the CLI as a convenience so `fd0 ssh add
// prod-db app@db.example.com:2222` works without three separate flags.
// Returns the user, host, and port; port=0 means "not specified".
//
// We deliberately keep this dumb: no IPv6 bracket parsing, no URI
// interpretation. The CLI also accepts explicit --user / --port flags
// for anything more elaborate.
func ParseConnString(s string) (user, host string, port int, err error) {
	if s == "" {
		return "", "", 0, nil
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		user = s[:at]
		s = s[at+1:]
	}
	if colon := strings.LastIndex(s, ":"); colon >= 0 {
		host = s[:colon]
		p := s[colon+1:]
		var n int
		_, err = fmt.Sscanf(p, "%d", &n)
		if err != nil {
			return "", "", 0, fmt.Errorf("sshhost: invalid port %q: %w", p, err)
		}
		port = n
	} else {
		host = s
	}
	return user, host, port, nil
}

// HasTag reports whether the host carries the given tag. Matches
// case-sensitively — tags are user input, we don't second-guess.
func (h *Host) HasTag(t string) bool {
	for _, x := range h.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// SortHosts sorts a slice of Hosts deterministically: scope ASC, then
// alias ASC. The renderer relies on this — same input order → same
// output bytes.
func SortHosts(hh []*Host) {
	sort.SliceStable(hh, func(i, j int) bool {
		if hh[i].Scope != hh[j].Scope {
			return hh[i].Scope < hh[j].Scope
		}
		return hh[i].Alias < hh[j].Alias
	})
}
