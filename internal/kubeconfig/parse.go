package kubeconfig

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// rawKubeconfig is the on-disk shape kubectl uses. We're parsing
// a strict subset (the bits an fd0-managed Kubeconfig can represent
// faithfully). Exec plugins and OIDC blocks land in the import
// error path with a clear "skipped" note.
type rawKubeconfig struct {
	APIVersion     string           `yaml:"apiVersion"`
	Kind           string           `yaml:"kind"`
	CurrentContext string           `yaml:"current-context,omitempty"`
	Clusters       []rawClusterItem `yaml:"clusters,omitempty"`
	Users          []rawUserItem    `yaml:"users,omitempty"`
	Contexts       []rawContextItem `yaml:"contexts,omitempty"`
}

type rawClusterItem struct {
	Name    string     `yaml:"name"`
	Cluster rawCluster `yaml:"cluster"`
}

type rawCluster struct {
	Server                   string `yaml:"server,omitempty"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
}

type rawUserItem struct {
	Name string  `yaml:"name"`
	User rawUser `yaml:"user"`
}

type rawUser struct {
	ClientCertificateData string `yaml:"client-certificate-data,omitempty"`
	ClientKeyData         string `yaml:"client-key-data,omitempty"`
	Token                 string `yaml:"token,omitempty"`
	// We deliberately don't model exec / auth-provider / etc. —
	// they need richer support than fd0 currently offers.
	Exec         *yaml.Node `yaml:"exec,omitempty"`
	AuthProvider *yaml.Node `yaml:"auth-provider,omitempty"`
}

type rawContextItem struct {
	Name    string     `yaml:"name"`
	Context rawContext `yaml:"context"`
}

type rawContext struct {
	Cluster   string `yaml:"cluster,omitempty"`
	User      string `yaml:"user,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
}

// ParseKubeconfig returns one Kubeconfig per (cluster, user,
// context) trio that fd0 can represent natively. Unsupported entries
// (exec auth plugins, auth-provider blocks, missing cluster/user
// refs) are skipped with notes in `skipped`.
//
// The active context name from `current-context` is returned for
// callers that want to preserve it.
func ParseKubeconfig(yamlBytes []byte) (active string, kk []*Kubeconfig, skipped []string, err error) {
	var raw rawKubeconfig
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return "", nil, nil, fmt.Errorf("kubeconfig: parse: %w", err)
	}
	clusters := map[string]rawCluster{}
	for _, c := range raw.Clusters {
		clusters[c.Name] = c.Cluster
	}
	users := map[string]rawUser{}
	for _, u := range raw.Users {
		users[u.Name] = u.User
	}
	for _, ctx := range raw.Contexts {
		clu, ok := clusters[ctx.Context.Cluster]
		if !ok {
			skipped = append(skipped, fmt.Sprintf("%s: cluster %q not declared", ctx.Name, ctx.Context.Cluster))
			continue
		}
		usr, ok := users[ctx.Context.User]
		if !ok {
			skipped = append(skipped, fmt.Sprintf("%s: user %q not declared", ctx.Name, ctx.Context.User))
			continue
		}
		if usr.Exec != nil || usr.AuthProvider != nil {
			skipped = append(skipped, fmt.Sprintf("%s: exec/auth-provider auth not supported by fd0 (yet)", ctx.Name))
			continue
		}
		hasCert := usr.ClientCertificateData != "" && usr.ClientKeyData != ""
		hasToken := usr.Token != ""
		if !hasCert && !hasToken {
			skipped = append(skipped, fmt.Sprintf("%s: user has no client cert/key and no token (file-path auth not supported by fd0)", ctx.Name))
			continue
		}
		kk = append(kk, &Kubeconfig{
			Name:                  ctx.Name,
			Server:                clu.Server,
			CA:                    clu.CertificateAuthorityData,
			InsecureSkipTLSVerify: clu.InsecureSkipTLSVerify,
			ClientCert:            usr.ClientCertificateData,
			ClientKey:             usr.ClientKeyData,
			Token:                 usr.Token,
			Namespace:             ctx.Context.Namespace,
		})
	}
	SortKubeconfigs(kk)
	return raw.CurrentContext, kk, skipped, nil
}
