package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
)

const kubeNamePrefix = "kube:"

// KubeAddOpts drives `fd0 kube add`. Mirrors TalosAddOpts.
type KubeAddOpts struct {
	Name string

	Server string

	CA     string
	CAFile string

	ClientCert     string
	ClientCertFile string
	ClientKey      string
	ClientKeyFile  string

	Token     string
	Namespace string

	InsecureSkipTLSVerify bool

	// FromConfig imports every importable context from an existing
	// kubeconfig file.
	FromConfig string
	// FromBytes is the same as FromConfig but with bytes directly
	// — used by `fd0 talos kubeconfig` which pipes from talosctl.
	FromBytes []byte
	// ImportContext (when FromConfig set) limits import to one ctx.
	ImportContext string

	Description string
	Tags        []string
	Scope       string

	// Force overrides the duplicate-name preflight.
	Force bool
}

func RunKubeAdd(ctx context.Context, o KubeAddOpts) error {
	// Same flock discipline as RunTalosAdd: read+parse a --from-config
	// file BEFORE we open the vault session, so the flock isn't held
	// during a symlink / oversized / non-regular read.
	var preparsedRaw []byte
	if o.FromConfig != "" && len(o.FromBytes) == 0 {
		raw, err := safeReadConfigFile(o.FromConfig, MaxConfigFile)
		if err != nil {
			return fmt.Errorf("--from-config: %w", err)
		}
		preparsedRaw = raw
	} else if len(o.FromBytes) > 0 {
		// In-memory path (RunTalosKubeconfig pipes here).
		preparsedRaw = o.FromBytes
	}

	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	scope, err := s.resolveScopeID(o.Scope)
	if err != nil {
		return err
	}

	if preparsedRaw != nil {
		return importKubeconfigBytes(ctx, s, scope, preparsedRaw, &o)
	}

	k, err := buildKubeconfigFromOpts(&o)
	if err != nil {
		return err
	}
	k.Scope = scope
	if err := k.Validate(); err != nil {
		return err
	}
	if err := ensureNoDuplicate(s, scope, kubeNamePrefix, k.Name, o.Force); err != nil {
		return err
	}
	if err := storeKubeconfig(ctx, s, scope, k); err != nil {
		return err
	}
	stderrln("✓ added kubeconfig %q (scope: %s)", k.Name, scopeName(s, scope))
	if err := renderAndAutoMergeKube(s); err != nil {
		return err
	}
	hintSyncForPeers()
	return nil
}

func buildKubeconfigFromOpts(o *KubeAddOpts) (*kubeconfig.Kubeconfig, error) {
	if o.CA == "" && o.CAFile != "" {
		b, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read --ca-file: %w", err)
		}
		o.CA = base64.StdEncoding.EncodeToString(b)
	}
	if o.ClientCert == "" && o.ClientCertFile != "" {
		b, err := os.ReadFile(o.ClientCertFile)
		if err != nil {
			return nil, fmt.Errorf("read --client-cert-file: %w", err)
		}
		o.ClientCert = base64.StdEncoding.EncodeToString(b)
	}
	if o.ClientKey == "" && o.ClientKeyFile != "" {
		b, err := os.ReadFile(o.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read --client-key-file: %w", err)
		}
		o.ClientKey = base64.StdEncoding.EncodeToString(b)
	}
	return &kubeconfig.Kubeconfig{
		Name:                  o.Name,
		Server:                o.Server,
		CA:                    o.CA,
		InsecureSkipTLSVerify: o.InsecureSkipTLSVerify,
		ClientCert:            o.ClientCert,
		ClientKey:             o.ClientKey,
		Token:                 o.Token,
		Namespace:             o.Namespace,
		Description:           o.Description,
		Tags:                  o.Tags,
	}, nil
}

// addKubeconfigBytesOnSession is the re-entrancy-safe entrypoint
// other commands (notably RunTalosKubeconfig) use to add a kubeconfig
// without re-acquiring the vault flock. `refreshExisting` toggles the
// "preserve user metadata" behaviour used by cert-refresh paths:
// namespace / tags / description / insecure-skip-tls-verify of an
// existing record are kept; server / CA / client cert / client key
// / token are overwritten from the new bytes.
func addKubeconfigBytesOnSession(ctx context.Context, s *Session, scopeID, defaultName string, raw []byte, refreshExisting bool) error {
	if len(raw) == 0 {
		return errors.New("addKubeconfig: empty input")
	}
	_, configs, skipped, err := kubeconfig.ParseKubeconfig(raw)
	if err != nil {
		return err
	}
	for _, sk := range skipped {
		stderrln("  ! skipping: %s", sk)
	}
	if len(configs) != 1 {
		return fmt.Errorf("addKubeconfig: expected exactly one importable context, got %d", len(configs))
	}
	k := configs[0]
	k.Name = defaultName
	k.Scope = scopeID

	// Refresh-preserving merge: pick up existing namespace / tags /
	// description so a cert refresh doesn't wipe user customisations.
	if refreshExisting {
		if existing, err := s.GetTypedSecret(scopeID, kubeNamePrefix+k.Name); err == nil && existing != nil {
			if prev, err := decodeKubeconfig(*existing); err == nil {
				if prev.Namespace != "" {
					k.Namespace = prev.Namespace
				}
				if len(prev.Tags) > 0 {
					k.Tags = prev.Tags
				}
				if prev.Description != "" {
					k.Description = prev.Description
				}
				if prev.InsecureSkipTLSVerify {
					k.InsecureSkipTLSVerify = true
				}
			}
		}
		// Annotate provenance.
		k.Tags = appendUnique(k.Tags, "from-talos")
	}
	if err := k.Validate(); err != nil {
		return err
	}
	if err := storeKubeconfig(ctx, s, scopeID, k); err != nil {
		return err
	}
	stderrln("✓ stored kubeconfig %q (scope: %s)", k.Name, scopeName(s, scopeID))
	if err := renderAndAutoMergeKube(s); err != nil {
		return err
	}
	hintSyncForPeers()
	return nil
}

// appendUnique appends tag to tags if not already present.
func appendUnique(tags []string, tag string) []string {
	for _, t := range tags {
		if t == tag {
			return tags
		}
	}
	return append(tags, tag)
}

func importKubeconfigBytes(ctx context.Context, s *Session, scopeID string, raw []byte, o *KubeAddOpts) error {
	_, configs, skipped, err := kubeconfig.ParseKubeconfig(raw)
	if err != nil {
		return err
	}
	if len(configs) == 0 {
		return errors.New("--from-config: no importable contexts found in file")
	}
	for _, sk := range skipped {
		stderrln("  ! skipping: %s", sk)
	}
	if o.ImportContext != "" {
		filtered := make([]*kubeconfig.Kubeconfig, 0, 1)
		for _, k := range configs {
			if k.Name == o.ImportContext {
				filtered = append(filtered, k)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("--import-context %q: not present (or skipped)", o.ImportContext)
		}
		configs = filtered
	}
	var stored, skippedDup int
	for _, k := range configs {
		k.Scope = scopeID
		if o.Name != "" && len(configs) == 1 {
			k.Name = o.Name
		}
		// Only overwrite from opts when the user actually supplied
		// the flag — empty Namespace/Description/Tags from --from-
		// config should pass through from the source file rather
		// than being silently wiped to zero.
		if o.Namespace != "" {
			k.Namespace = o.Namespace
		}
		if o.Description != "" {
			k.Description = o.Description
		}
		if len(o.Tags) > 0 {
			k.Tags = append([]string(nil), o.Tags...)
		}
		if err := k.Validate(); err != nil {
			stderrln("  ! skipping %q: %v", k.Name, err)
			continue
		}
		if err := ensureNoDuplicate(s, scopeID, kubeNamePrefix, k.Name, o.Force); err != nil {
			stderrln("  ! skipping %q: %v", k.Name, err)
			skippedDup++
			continue
		}
		if err := storeKubeconfig(ctx, s, scopeID, k); err != nil {
			return err
		}
		stderrln("✓ imported kubeconfig %q (scope: %s)", k.Name, scopeName(s, scopeID))
		stored++
	}
	if stored == 0 {
		if skippedDup > 0 {
			return fmt.Errorf("--from-config: every importable context (%d) is already in scope %s — pass --force to overwrite",
				skippedDup, scopeName(s, scopeID))
		}
		return fmt.Errorf("--from-config: no kubeconfigs stored")
	}
	if err := renderAndAutoMergeKube(s); err != nil {
		return err
	}
	hintSyncForPeers()
	return nil
}

func storeKubeconfig(ctx context.Context, s *Session, scopeID string, k *kubeconfig.Kubeconfig) error {
	return s.SetTypedSecret(ctx, scopeID, kubeNamePrefix+k.Name,
		kubeconfig.TypeKubeconfig, k.Marshal())
}

func RunKubeList(ctx context.Context, scopeID string, anyTags, noTags []string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	kk, err := loadKubeconfigs(s, scopeID)
	if err != nil {
		return err
	}
	kk = filterKubeconfigs(kk, anyTags, noTags)
	kubeconfig.SortKubeconfigs(kk)
	if len(kk) == 0 {
		stderrln("no kubeconfigs")
		return nil
	}
	for _, k := range kk {
		auth := "cert"
		if k.Token != "" && k.ClientCert == "" {
			auth = "token"
		}
		extra := ""
		if k.Namespace != "" {
			extra = "  ns=" + k.Namespace
		}
		if len(k.Tags) > 0 {
			extra += "  tags=[" + strings.Join(k.Tags, ",") + "]"
		}
		fmt.Printf("%-24s  %-32s  auth=%s  scope=%s%s\n",
			k.Name, k.Server, auth, scopeName(s, k.Scope), extra)
	}
	return nil
}

func RunKubeShow(ctx context.Context, scopeID, name string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	k, err := lookupKubeconfig(s, scopeID, name)
	if err != nil {
		return err
	}
	fmt.Println("name        :", k.Name)
	fmt.Println("scope       :", scopeName(s, k.Scope))
	fmt.Println("server      :", k.Server)
	if k.Namespace != "" {
		fmt.Println("namespace   :", k.Namespace)
	}
	fmt.Println("auth        :", authDesc(k))
	if k.InsecureSkipTLSVerify {
		fmt.Println("verify-tls  : DISABLED (insecure-skip-tls-verify)")
	}
	if k.Description != "" {
		fmt.Println("description :", k.Description)
	}
	if len(k.Tags) > 0 {
		fmt.Println("tags        :", strings.Join(k.Tags, ", "))
	}
	if k.CA != "" {
		fmt.Println("ca          : <" + lenDesc(k.CA) + " base64>")
	}
	return nil
}

func RunKubeRemove(ctx context.Context, scopeID, name string, yes bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	k, err := lookupKubeconfig(s, scopeID, name)
	if err != nil {
		return err
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove kubeconfig %q from %s?", k.Name, scopeName(s, k.Scope))); err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, k.Scope, kubeNamePrefix+k.Name); err != nil {
		return err
	}
	stderrln("✓ removed kubeconfig %q from scope %s", k.Name, scopeName(s, k.Scope))
	if err := renderAndAutoMergeKube(s); err != nil {
		return err
	}
	hintSyncForPeers()
	return nil
}

func RunKubeMove(ctx context.Context, name, fromScope, toScope string, force bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(fromScope, kubeNamePrefix+name)
	if err != nil {
		return err
	}
	k, err := decodeKubeconfig(*r)
	if err != nil {
		return err
	}
	to, err := s.resolveScopeID(toScope)
	if err != nil {
		return err
	}
	if r.ScopeID == to {
		return fmt.Errorf("source and destination scopes are the same: %s", scopeName(s, to))
	}
	if err := ensureNoDuplicate(s, to, kubeNamePrefix, name, force); err != nil {
		return err
	}
	k.Scope = to
	if err := storeKubeconfig(ctx, s, to, k); err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, r.ScopeID, r.Name); err != nil {
		return fmt.Errorf("moved kube %q to %s but failed to remove from %s: %w (clean up with: fd0 kube rm %s --scope %s)",
			name, scopeName(s, to), scopeName(s, r.ScopeID), err, name, scopeName(s, r.ScopeID))
	}
	stderrln("✓ moved kube %q: %s → %s", name, scopeName(s, r.ScopeID), scopeName(s, to))
	if err := renderAndAutoMergeKube(s); err != nil {
		return err
	}
	hintSyncForPeers()
	return nil
}

func RunKubeEnable(ctx context.Context, merge bool) error {
	if err := RunKubeSync(ctx, merge, false); err != nil {
		return err
	}
	if err := setProjectionConfig("kube", true, merge); err != nil {
		return err
	}
	stderrln("✓ kube auto-refresh enabled")
	if merge {
		stderrln("✓ kube auto-merge enabled")
	}
	return nil
}

func RunKubeDisable(_ context.Context) error {
	if err := setProjectionConfig("kube", false, false); err != nil {
		return err
	}
	stderrln("✓ kube auto-refresh disabled")
	stderrln("  generated config left at %s", kubeconfPath())
	return nil
}

func RunKubeSync(ctx context.Context, merge, replaceActive bool) error {
	if replaceActive && !merge {
		return errors.New("kube sync: --replace-active requires --merge")
	}
	// Render under flock; close the session BEFORE shelling out to
	// kubectl so a slow kubectl plugin / blocked filesystem can't
	// block every other fd0 command on the lock.
	{
		s, err := Open(ctx)
		if err != nil {
			return err
		}
		if err := renderAndWarnKube(s); err != nil {
			s.Close()
			return err
		}
		s.Close()
	}
	if merge {
		if err := mergeKubeconfigFile(kubeconfPath(), userKubeconfigPath(), replaceActive); err != nil {
			return err
		}
		stderrln("✓ merged into %s", userKubeconfigPath())
		if err := setProjectionConfig("kube", true, true); err != nil {
			return err
		}
	}
	return nil
}

func renderAndWarnKube(s *Session) error {
	configs, err := loadKubeconfigs(s, "")
	if err != nil {
		return err
	}
	bytes, warnings := kubeconfig.Render(kubeconfig.RenderInput{
		Configs: configs,
		Now:     nowFunc(),
	})
	for _, w := range warnings {
		stderrln("⚠ %s", w)
	}
	return writeManagedFile(kubeconfPath(), bytes, "clusters", len(configs))
}

func renderAndAutoMergeKube(s *Session) error {
	if err := renderAndWarnKube(s); err != nil {
		return err
	}
	autoMergeKubeIfEnabled()
	return nil
}

func loadKubeconfigs(s *Session, scopeID string) ([]*kubeconfig.Kubeconfig, error) {
	rows, err := s.ListTypedSecrets(scopeID, kubeconfig.TypeKubeconfig)
	if err != nil {
		return nil, err
	}
	out := make([]*kubeconfig.Kubeconfig, 0, len(rows))
	for _, r := range rows {
		k, err := decodeKubeconfig(r)
		if err != nil {
			stderrln("  ! malformed kubeconfig %q in scope %s: %v",
				r.Name, scopeName(s, r.ScopeID), err)
			continue
		}
		out = append(out, k)
	}
	return out, nil
}

func filterKubeconfigs(kk []*kubeconfig.Kubeconfig, anyTags, noTags []string) []*kubeconfig.Kubeconfig {
	if len(anyTags) == 0 && len(noTags) == 0 {
		return kk
	}
	var out []*kubeconfig.Kubeconfig
next:
	for _, k := range kk {
		for _, t := range anyTags {
			if !k.HasTag(t) {
				continue next
			}
		}
		for _, t := range noTags {
			if k.HasTag(t) {
				continue next
			}
		}
		out = append(out, k)
	}
	return out
}

func decodeKubeconfig(r TypedRecord) (*kubeconfig.Kubeconfig, error) {
	raw, err := r.PayloadJSON()
	if err != nil {
		return nil, err
	}
	k, err := kubeconfig.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("decode kube %q: %w", r.Name, err)
	}
	k.Scope = r.ScopeID
	// Read-time Validate (mirror of decodeHost/decodeTalosContext) —
	// keep peer-pushed payloads from reaching the renderer.
	if err := k.Validate(); err != nil {
		return nil, fmt.Errorf("decode kube %q: untrusted payload: %w", r.Name, err)
	}
	return k, nil
}

func lookupKubeconfig(s *Session, scopeID, name string) (*kubeconfig.Kubeconfig, error) {
	kk, err := loadKubeconfigs(s, scopeID)
	if err != nil {
		return nil, err
	}
	var match []*kubeconfig.Kubeconfig
	for _, k := range kk {
		if k.Name == name {
			match = append(match, k)
		}
	}
	switch len(match) {
	case 0:
		if scopeID != "" {
			return nil, fmt.Errorf("no kubeconfig %q in scope %s", name, scopeName(s, scopeID))
		}
		return nil, fmt.Errorf("no kubeconfig %q in any scope", name)
	case 1:
		return match[0], nil
	default:
		return nil, fmt.Errorf("kubeconfig %q is ambiguous across multiple scopes — use --scope", name)
	}
}

func authDesc(k *kubeconfig.Kubeconfig) string {
	if k.ClientCert != "" && k.ClientKey != "" {
		return "client-cert (" + lenDesc(k.ClientCert) + " / " + lenDesc(k.ClientKey) + ")"
	}
	if k.Token != "" {
		return "bearer token (hidden)"
	}
	return "(none)"
}
