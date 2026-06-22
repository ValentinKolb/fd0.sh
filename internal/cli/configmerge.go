package cli

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// configmerge.go folds fd0's rendered config files into the user's
// primary ~/.talos/config and ~/.kube/config using a pure-Go
// structural YAML merge — no talosctl / kubectl on the box required.
//
// The merge is structural (it works on generic YAML maps), NOT via the
// typed talosctx / kubeconfig codecs. Those codecs are intentionally
// lossy — kubeconfig parsing drops exec / auth-provider auth — so
// routing the user's existing file through them would silently delete
// their EKS / GKE / OIDC clusters. Operating on generic maps preserves
// every field we don't model.

// loadYAMLMap reads a YAML document into a generic string-keyed map.
// A missing file returns os.ErrNotExist so callers can pick a skeleton;
// an empty file yields an empty map.
func loadYAMLMap(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	if len(raw) == 0 {
		return m, nil
	}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// writeYAMLMap marshals m and writes it atomically at 0600.
func writeYAMLMap(path string, m map[string]any) error {
	out, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(parentDir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, out, 0o600)
}

// asSlice / asStringMap coerce a generic YAML value, nil-safe.
func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asStringMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

// mergeNamedList merges overlay entries into base by their "name"
// field: a same-named overlay entry replaces the base entry in place,
// a new one is appended, and base entries the overlay doesn't mention
// are preserved. Drives the kubeconfig clusters / users / contexts
// lists.
func mergeNamedList(base, overlay []any) []any {
	idx := map[string]int{}
	for i, e := range base {
		if m, ok := e.(map[string]any); ok {
			if n, ok := m["name"].(string); ok {
				idx[n] = i
			}
		}
	}
	for _, e := range overlay {
		m, ok := e.(map[string]any)
		if !ok {
			base = append(base, e)
			continue
		}
		n, _ := m["name"].(string)
		if n == "" {
			base = append(base, e)
			continue
		}
		if i, ok := idx[n]; ok {
			base[i] = e
		} else {
			idx[n] = len(base)
			base = append(base, e)
		}
	}
	return base
}

// mergeKubeconfigFile folds the fd0-rendered kubeconfig at fd0Path into
// the user's kubeconfig at userPath. fd0's clusters / users / contexts
// replace same-named entries; everything else the user has — including
// exec / auth-provider clusters fd0 doesn't model — is preserved. The
// user's current-context is left untouched.
func mergeKubeconfigFile(fd0Path, userPath string) error {
	fd0Doc, err := loadYAMLMap(fd0Path)
	if err != nil {
		return fmt.Errorf("kube merge: read rendered config: %w", err)
	}
	userDoc, err := loadYAMLMap(userPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("kube merge: read %s: %w", userPath, err)
		}
		userDoc = map[string]any{}
	}
	if userDoc["apiVersion"] == nil {
		userDoc["apiVersion"] = "v1"
	}
	if userDoc["kind"] == nil {
		userDoc["kind"] = "Config"
	}
	for _, key := range []string{"clusters", "users", "contexts"} {
		userDoc[key] = mergeNamedList(asSlice(userDoc[key]), asSlice(fd0Doc[key]))
	}
	return writeYAMLMap(userPath, userDoc)
}

// mergeTalosconfigFile folds the fd0-rendered talosconfig at fd0Path
// into the user's talosconfig at userPath. fd0's contexts overwrite
// same-named ones; the user's other contexts are preserved. The active
// `context` pointer is left alone unless the user has none yet, in
// which case fd0's is adopted so the merge is immediately usable.
func mergeTalosconfigFile(fd0Path, userPath string) error {
	fd0Doc, err := loadYAMLMap(fd0Path)
	if err != nil {
		return fmt.Errorf("talos merge: read rendered config: %w", err)
	}
	userDoc, err := loadYAMLMap(userPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("talos merge: read %s: %w", userPath, err)
		}
		userDoc = map[string]any{}
	}
	uctx := asStringMap(userDoc["contexts"])
	for name, v := range asStringMap(fd0Doc["contexts"]) {
		uctx[name] = v
	}
	userDoc["contexts"] = uctx
	if userDoc["context"] == nil || userDoc["context"] == "" {
		if c := fd0Doc["context"]; c != nil {
			userDoc["context"] = c
		}
	}
	return writeYAMLMap(userPath, userDoc)
}
