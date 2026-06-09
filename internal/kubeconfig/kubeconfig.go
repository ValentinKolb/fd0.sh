// Package kubeconfig models a Kubernetes client config — the
// per-cluster bundle of (cluster endpoint + CA, user credential,
// context tying them together) that lives in ~/.kube/config.
//
// Unlike talosconfig where a "context" is a flat record, kubeconfig
// splits the same idea across THREE related top-level lists
// (clusters / users / contexts). fd0 keeps them bundled per-cluster
// so the typed-secret payload is one record per logical entry.
// Render reconstitutes the three lists for kubectl.
package kubeconfig

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const TypeKubeconfig = "fd0-kubeconfig"

// Kubeconfig is one logical "I can talk to this cluster" entry.
// In ~/.kube/config it shows up as one cluster + one user + one
// context all wired together; here we represent that as a single
// record so the user thinks in clusters rather than three parallel
// lists.
type Kubeconfig struct {
	// Name is the alias — used as the cluster name, user name,
	// and context name in the rendered config. Unique within a
	// scope.
	Name string

	// Server is the API server URL, e.g. https://10.0.1.10:6443.
	Server string

	// CA is the base64-encoded PEM cluster CA cert (matches the
	// `certificate-authority-data` field in kubeconfig).
	CA string

	// InsecureSkipTLSVerify mirrors kubeconfig's
	// `insecure-skip-tls-verify`. Off-label by default — most
	// users want CA pinning. Surfaced because the talosctl
	// kubeconfig pipeline occasionally emits it.
	InsecureSkipTLSVerify bool

	// User auth — exactly one of (ClientCert+ClientKey) or Token
	// is expected. Both populated is fine (kubectl picks the cert),
	// both empty errors.
	ClientCert string // base64(PEM client cert)
	ClientKey  string // base64(PEM client key)
	Token      string // bearer token, raw (not base64)

	// Namespace defaults the kubectl --namespace flag for this
	// context. Optional.
	Namespace string

	// Description is a single-line human note.
	Description string

	// Tags are scope-shared labels.
	Tags []string

	// Scope is the fd0 scope. Set by the CLI layer.
	Scope string
}

// JSON is the vault payload shape.
type JSON struct {
	Type                  string   `json:"type"`
	Name                  string   `json:"n"`
	Server                string   `json:"s"`
	CA                    string   `json:"ca,omitempty"`
	InsecureSkipTLSVerify bool     `json:"sk,omitempty"`
	ClientCert            string   `json:"cc,omitempty"`
	ClientKey             string   `json:"ck,omitempty"`
	Token                 string   `json:"tk,omitempty"`
	Namespace             string   `json:"ns,omitempty"`
	Description           string   `json:"d,omitempty"`
	Tags                  []string `json:"t,omitempty"`
}

func (k *Kubeconfig) Marshal() JSON {
	return JSON{
		Type:                  TypeKubeconfig,
		Name:                  k.Name,
		Server:                k.Server,
		CA:                    k.CA,
		InsecureSkipTLSVerify: k.InsecureSkipTLSVerify,
		ClientCert:            k.ClientCert,
		ClientKey:             k.ClientKey,
		Token:                 k.Token,
		Namespace:             k.Namespace,
		Description:           k.Description,
		Tags:                  k.Tags,
	}
}

func Unmarshal(b []byte) (*Kubeconfig, error) {
	var j JSON
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, fmt.Errorf("kubeconfig: json: %w", err)
	}
	if j.Type != "" && j.Type != TypeKubeconfig {
		return nil, fmt.Errorf("kubeconfig: wrong type %q", j.Type)
	}
	return &Kubeconfig{
		Name:                  j.Name,
		Server:                j.Server,
		CA:                    j.CA,
		InsecureSkipTLSVerify: j.InsecureSkipTLSVerify,
		ClientCert:            j.ClientCert,
		ClientKey:             j.ClientKey,
		Token:                 j.Token,
		Namespace:             j.Namespace,
		Description:           j.Description,
		Tags:                  j.Tags,
	}, nil
}

// nameRE: tighter than kubeconfig allows in theory; matches what
// kubectl's user-input parser is comfortable with. Keeps the
// rendered YAML free of quoting surprises.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Validate runs sanity checks. Doesn't reach out over the network.
func (k *Kubeconfig) Validate() error {
	if !nameRE.MatchString(k.Name) {
		return fmt.Errorf("kubeconfig: bad name %q (must match %s)", k.Name, nameRE)
	}
	if k.Server == "" {
		return fmt.Errorf("kubeconfig: %q missing server", k.Name)
	}
	if !strings.HasPrefix(k.Server, "https://") && !strings.HasPrefix(k.Server, "http://") {
		return fmt.Errorf("kubeconfig: %q server must start with http(s)://", k.Name)
	}
	if !k.InsecureSkipTLSVerify && k.CA == "" {
		return fmt.Errorf("kubeconfig: %q has no CA and is not insecure-skip-tls-verify", k.Name)
	}
	if k.CA != "" {
		if _, err := base64.StdEncoding.DecodeString(k.CA); err != nil {
			return fmt.Errorf("kubeconfig: %q ca: bad base64: %w", k.Name, err)
		}
	}
	// Need *some* auth.
	hasCert := k.ClientCert != "" && k.ClientKey != ""
	hasToken := k.Token != ""
	if !hasCert && !hasToken {
		return fmt.Errorf("kubeconfig: %q has no client cert/key and no token", k.Name)
	}
	if hasCert {
		for _, f := range []struct{ name, b64 string }{
			{"client-cert", k.ClientCert}, {"client-key", k.ClientKey},
		} {
			if _, err := base64.StdEncoding.DecodeString(f.b64); err != nil {
				return fmt.Errorf("kubeconfig: %q %s: bad base64: %w", k.Name, f.name, err)
			}
		}
	}
	return nil
}

// HasTag reports whether the kubeconfig carries the given tag.
func (k *Kubeconfig) HasTag(t string) bool {
	for _, x := range k.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// SortKubeconfigs orders by (scope, name) for deterministic output.
func SortKubeconfigs(kk []*Kubeconfig) {
	sort.SliceStable(kk, func(i, j int) bool {
		if kk[i].Scope != kk[j].Scope {
			return kk[i].Scope < kk[j].Scope
		}
		return kk[i].Name < kk[j].Name
	})
}
