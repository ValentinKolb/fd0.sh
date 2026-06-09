package talosctx

import (
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// rawTalosconfig is the on-disk shape of ~/.talos/config — kept
// internal because users interact via TalosContext, not this.
//
// The YAML field names are dictated by talosctl; we can't change
// them and tag them explicitly so go-yaml maps correctly even when
// it normally lowercases struct field names.
type rawTalosconfig struct {
	Context  string                 `yaml:"context,omitempty"`
	Contexts map[string]*rawContext `yaml:"contexts"`
}

type rawContext struct {
	Endpoints []string `yaml:"endpoints"`
	Nodes     []string `yaml:"nodes,omitempty"`
	CA        string   `yaml:"ca,omitempty"`
	Crt       string   `yaml:"crt,omitempty"`
	Key       string   `yaml:"key,omitempty"`
}

// ParseTalosconfig reads a talosconfig YAML blob and returns every
// context inside it as a TalosContext. The active-context pointer
// is returned separately — callers use it when importing to also
// preserve which context the user had as default.
//
// Empty contexts maps are tolerated (an empty file is OK), but a
// malformed YAML payload errors.
func ParseTalosconfig(yamlBytes []byte) (active string, ctxs []*TalosContext, err error) {
	var raw rawTalosconfig
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return "", nil, fmt.Errorf("talosctx: parse: %w", err)
	}
	for name, rc := range raw.Contexts {
		if rc == nil {
			continue
		}
		ctxs = append(ctxs, &TalosContext{
			Name:      name,
			Endpoints: rc.Endpoints,
			Nodes:     rc.Nodes,
			CA:        normaliseBase64(rc.CA),
			Crt:       normaliseBase64(rc.Crt),
			Key:       normaliseBase64(rc.Key),
		})
	}
	SortContexts(ctxs)
	return raw.Context, ctxs, nil
}

// normaliseBase64 strips PEM whitespace if a user accidentally
// pasted a raw PEM. talosctl writes single-line base64 by default
// so this is a defensive no-op most of the time.
func normaliseBase64(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// If it parses as base64 already, return as-is.
	if _, err := base64.StdEncoding.DecodeString(s); err == nil {
		return s
	}
	// PEM with line breaks — strip whitespace and try again.
	flat := strings.Join(strings.Fields(s), "")
	if _, err := base64.StdEncoding.DecodeString(flat); err == nil {
		return flat
	}
	// Wasn't valid base64 at all; return original so Validate can
	// surface the precise error path.
	return s
}
