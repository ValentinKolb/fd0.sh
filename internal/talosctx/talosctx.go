// Package talosctx models a Talos client context — the per-cluster
// entry that lives under `contexts:` in ~/.talos/config. A context
// holds the Talos OS API endpoints + nodes plus the per-operator
// mTLS material (CA + client cert + client key) issued by the
// cluster's Talos OS CA.
//
// Contexts are stored as scope-shared typed secrets in fd0 and
// rendered to a deterministic YAML file (~/.talos/config.fd0) that
// is then merged into the user's ~/.talos/config via talosctl —
// same mental model as fd0 ssh's hosts → ~/.ssh/fd0.conf.
//
// The secrets.yaml bundle (cluster root PKI, DR-grade) is *not*
// modelled here — that lives in internal/cli/talos_secrets.go and
// is stored under a separate typed secret type so the day-to-day
// `fd0 talos sync` codepath never has to touch it.
package talosctx

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// TypeTalosContext is the SecretRecord.Type discriminator used to
// distinguish Talos contexts from other typed secrets in the vault.
const TypeTalosContext = "fd0-talos-context"

// Role catalogue — talosctl assigns these to client certificates
// via the --roles flag on `talosctl config new`. The role is
// embedded in the cert itself; fd0 also stores it as metadata so
// `fd0 talos ls` can surface it without parsing the cert.
const (
	RoleAdmin       = "os:admin"
	RoleOperator    = "os:operator"
	RoleReader      = "os:reader"
	RoleEtcdBackup  = "os:etcd:backup"
	RoleImpersonate = "os:impersonator"
)

// TalosContext is a per-cluster Talos client context.
//
// Field naming mirrors the YAML layout of `contexts.<name>` in
// ~/.talos/config so round-tripping is mechanical.
type TalosContext struct {
	// Name is the context alias — unique within a scope. Acts as
	// the YAML key under `contexts:` in the rendered output.
	Name string

	// Endpoints are the control-plane IPs / hostnames the Talos
	// machine API listens on (port 50000 by default). talosctl
	// dials these in order until one answers.
	Endpoints []string

	// Nodes is the default --nodes target list. Optional; if
	// empty, talosctl requires --nodes on every command.
	Nodes []string

	// CA, Crt, Key are the PEM-encoded materials, base64-encoded
	// for YAML transport. CA is the Talos OS CA cert, Crt+Key is
	// the operator's client cert + private key.
	CA  string // base64(PEM Talos OS CA cert)
	Crt string // base64(PEM client cert)
	Key string // base64(PEM client EC private key)

	// Role is informational — what's in Crt. Surfaced by `fd0
	// talos ls` without having to parse the cert.
	Role string

	// Description is a single-line human note.
	Description string

	// Tags are free-form scope-shared labels.
	Tags []string

	// Scope is the fd0 scope this context belongs to. Set at
	// load time by the CLI layer; NOT marshalled into the typed
	// secret payload (scope membership is out-of-band metadata).
	Scope string
}

// JSON is the on-wire / on-vault shape. Field names are short
// because every byte gets multi-pushed to every configured server.
type JSON struct {
	Type        string   `json:"type"`
	Name        string   `json:"n"`
	Endpoints   []string `json:"ep,omitempty"`
	Nodes       []string `json:"no,omitempty"`
	CA          string   `json:"ca,omitempty"`
	Crt         string   `json:"crt,omitempty"`
	Key         string   `json:"key,omitempty"`
	Role        string   `json:"r,omitempty"`
	Description string   `json:"d,omitempty"`
	Tags        []string `json:"t,omitempty"`
}

// Marshal turns a context into its vault-storable JSON shape.
func (c *TalosContext) Marshal() JSON {
	return JSON{
		Type:        TypeTalosContext,
		Name:        c.Name,
		Endpoints:   c.Endpoints,
		Nodes:       c.Nodes,
		CA:          c.CA,
		Crt:         c.Crt,
		Key:         c.Key,
		Role:        c.Role,
		Description: c.Description,
		Tags:        c.Tags,
	}
}

// Unmarshal hydrates a TalosContext from a JSON blob pulled out of
// the vault. Scope is *not* derived from JSON — the caller knows
// which scope a secret came from.
func Unmarshal(b []byte) (*TalosContext, error) {
	var j JSON
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("talosctx: json: %w", err)
	}
	if j.Type != "" && j.Type != TypeTalosContext {
		return nil, fmt.Errorf("talosctx: wrong type %q", j.Type)
	}
	return &TalosContext{
		Name:        j.Name,
		Endpoints:   j.Endpoints,
		Nodes:       j.Nodes,
		CA:          j.CA,
		Crt:         j.Crt,
		Key:         j.Key,
		Role:        j.Role,
		Description: j.Description,
		Tags:        j.Tags,
	}, nil
}

// nameRE: Same charset as talosctl tolerates for context names. We
// stay conservative because the name becomes a YAML key.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate checks the context for protocol-level sanity. Doesn't
// open any network connections — that's deliberately separate so
// `fd0 talos add` can validate without touching the cluster.
func (c *TalosContext) Validate() error {
	if !nameRE.MatchString(c.Name) {
		return fmt.Errorf("talosctx: bad name %q (must match %s)", c.Name, nameRE)
	}
	if len(c.Endpoints) == 0 {
		return fmt.Errorf("talosctx: %q has no endpoints", c.Name)
	}
	for _, ep := range c.Endpoints {
		if strings.TrimSpace(ep) == "" {
			return fmt.Errorf("talosctx: %q has empty endpoint", c.Name)
		}
	}
	for _, n := range c.Nodes {
		if strings.TrimSpace(n) == "" {
			return fmt.Errorf("talosctx: %q has empty node", c.Name)
		}
	}
	if c.CA == "" {
		return fmt.Errorf("talosctx: %q missing ca", c.Name)
	}
	if c.Crt == "" || c.Key == "" {
		return fmt.Errorf("talosctx: %q missing client cert/key", c.Name)
	}
	for _, f := range []struct{ name, b64 string }{
		{"ca", c.CA}, {"crt", c.Crt}, {"key", c.Key},
	} {
		if _, err := base64.StdEncoding.DecodeString(f.b64); err != nil {
			return fmt.Errorf("talosctx: %q field %s: bad base64: %w", c.Name, f.name, err)
		}
	}
	if c.Role != "" && !validRole(c.Role) {
		return fmt.Errorf("talosctx: %q has unknown role %q", c.Name, c.Role)
	}
	return nil
}

func validRole(r string) bool {
	switch r {
	case RoleAdmin, RoleOperator, RoleReader, RoleEtcdBackup, RoleImpersonate:
		return true
	}
	// Talos may add roles in the future; only warn on the catalogue
	// we know about, accept the rest. Pattern matches `os:foo` /
	// `os:foo:bar`.
	return strings.HasPrefix(r, "os:")
}

// HasTag reports whether the context carries the given tag.
func (c *TalosContext) HasTag(t string) bool {
	for _, x := range c.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// SortContexts puts contexts into a deterministic order so the
// rendered YAML is byte-stable for any given input set.
func SortContexts(cc []*TalosContext) {
	sort.SliceStable(cc, func(i, j int) bool {
		if cc[i].Scope != cc[j].Scope {
			return cc[i].Scope < cc[j].Scope
		}
		return cc[i].Name < cc[j].Name
	})
}

// SplitEndpoints handles both space-separated and comma-separated
// inputs from the CLI (`--endpoint a,b` and `--endpoint a --endpoint b`
// both produce the same []string after this).
func SplitEndpoints(raw []string) []string {
	var out []string
	for _, x := range raw {
		for _, p := range strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ' ' }) {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// ValidateHostPort is a soft check used by `fd0 talos add` so we
// catch typos at write time. Returns nil for both plain IPs and
// IP:port forms; talosctl dials whatever it's given.
func ValidateHostPort(ep string) error {
	if strings.Contains(ep, ":") {
		host, port, err := net.SplitHostPort(ep)
		if err != nil {
			return fmt.Errorf("bad endpoint %q: %w", ep, err)
		}
		if host == "" || port == "" {
			return fmt.Errorf("bad endpoint %q: empty host or port", ep)
		}
		return nil
	}
	if strings.TrimSpace(ep) == "" {
		return fmt.Errorf("empty endpoint")
	}
	return nil
}
