package kubeconfig

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type RenderInput struct {
	// Configs is the set of kubeconfigs to emit. Caller filters
	// and de-duplicates first.
	Configs []*Kubeconfig

	// CurrentContext, if non-empty and matching a config in the list,
	// becomes the rendered current-context. When empty, a single rendered
	// config becomes current automatically; multiple configs omit it.
	CurrentContext string

	// Now feeds the header timestamp.
	Now time.Time
}

func Render(in RenderInput) (data []byte, warnings []string) {
	configs := append([]*Kubeconfig(nil), in.Configs...)
	SortKubeconfigs(configs)

	// Cross-scope collision detection.
	seen := map[string]*Kubeconfig{}
	emit := make([]*Kubeconfig, 0, len(configs))
	for _, k := range configs {
		if prev, ok := seen[k.Name]; ok {
			warnings = append(warnings,
				fmt.Sprintf("kubeconfig name %q exists in both scope %q and %q — first-by-sort wins",
					k.Name, prev.Scope, k.Scope))
			continue
		}
		seen[k.Name] = k
		emit = append(emit, k)
	}

	raw := rawKubeconfig{
		APIVersion: "v1",
		Kind:       "Config",
	}
	current := in.CurrentContext
	if current == "" && len(emit) == 1 {
		current = emit[0].Name
	}
	if current != "" && seen[current] != nil {
		raw.CurrentContext = current
	}
	for _, k := range emit {
		raw.Clusters = append(raw.Clusters, rawClusterItem{
			Name: k.Name,
			Cluster: rawCluster{
				Server:                   k.Server,
				CertificateAuthorityData: k.CA,
				InsecureSkipTLSVerify:    k.InsecureSkipTLSVerify,
			},
		})
		raw.Users = append(raw.Users, rawUserItem{
			Name: k.Name,
			User: rawUser{
				ClientCertificateData: k.ClientCert,
				ClientKeyData:         k.ClientKey,
				Token:                 k.Token,
			},
		})
		raw.Contexts = append(raw.Contexts, rawContextItem{
			Name: k.Name,
			Context: rawContext{
				Cluster:   k.Name,
				User:      k.Name,
				Namespace: k.Namespace,
			},
		})
	}

	body, err := yaml.Marshal(raw)
	if err != nil {
		return []byte(fmt.Sprintf("# render error: %v\n", err)), warnings
	}
	header := renderHeader(emit, in.Now, warnings)
	return append([]byte(header), body...), warnings
}

func renderHeader(kk []*Kubeconfig, now time.Time, warnings []string) string {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "# fd0 — managed kubeconfig. Do not edit by hand.")
	fmt.Fprintln(&buf, "#")
	fmt.Fprintln(&buf, "# Regenerate with `fd0 kube sync`. The original ~/.kube/config")
	fmt.Fprintln(&buf, "# is left alone — this file is meant to be merged via")
	fmt.Fprintln(&buf, "#   KUBECONFIG=~/.kube/config.fd0:~/.kube/config kubectl config view --merge --flatten")
	fmt.Fprintln(&buf, "# (`fd0 kube sync --merge` does this automatically).")
	fmt.Fprintln(&buf, "#")
	fmt.Fprintf(&buf, "# Rendered at %s · %d cluster(s)\n",
		now.UTC().Format("2006-01-02 15:04:05 UTC"), len(kk))

	byScope := map[string][]*Kubeconfig{}
	for _, k := range kk {
		byScope[k.Scope] = append(byScope[k.Scope], k)
	}
	scopes := make([]string, 0, len(byScope))
	for s := range byScope {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	for _, s := range scopes {
		display := s
		if display == "" {
			display = "(no scope)"
		}
		fmt.Fprintf(&buf, "#   scope %q: ", display)
		names := make([]string, 0, len(byScope[s]))
		for _, k := range byScope[s] {
			names = append(names, k.Name)
		}
		fmt.Fprintln(&buf, strings.Join(names, ", "))
	}
	if len(warnings) > 0 {
		fmt.Fprintln(&buf, "#")
		fmt.Fprintln(&buf, "# WARNINGS:")
		for _, w := range warnings {
			fmt.Fprintf(&buf, "#   - %s\n", w)
		}
	}
	fmt.Fprintln(&buf, "")
	return buf.String()
}
