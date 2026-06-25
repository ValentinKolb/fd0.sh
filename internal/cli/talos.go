package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

// talosNamePrefix scopes the typed-secret key namespace for
// talosconfig contexts. Combined with TypeTalosContext to filter the
// vault during list/render.
const talosNamePrefix = "talos:"

// TalosAddOpts bundles the parameters fed by `fd0 talos add` /
// `fd0 talos new`.
type TalosAddOpts struct {
	// Name is the context alias inside the rendered talosconfig.
	Name string

	// Endpoints / Nodes accept repeated --endpoint / --node flags
	// or single comma-separated values; the parser splits both.
	Endpoints []string
	Nodes     []string

	// PEM material — caller can supply either base64-encoded
	// strings (already wire-ready) OR file paths via the
	// CAFile / CrtFile / KeyFile helpers. The CLI layer normalises
	// to base64 before validation.
	CA  string
	Crt string
	Key string

	CAFile  string
	CrtFile string
	KeyFile string

	// FromConfig optionally imports every context from an existing
	// talosconfig YAML file. When set, the per-field options above
	// are ignored except for Scope / Description / Tags which
	// apply to every imported context.
	FromConfig string

	// Only used in the FromConfig path: which context to import.
	// Empty means "all contexts in that file".
	ImportContext string

	Role        string
	Description string
	Tags        []string
	Scope       string

	// Force lets the user knowingly overwrite an existing typed
	// secret with the same name. Without it we refuse to clobber a
	// stored context — accidental name reuse was silently dropping
	// state in the previous behaviour.
	Force bool
}

// RunTalosAdd creates one or more talosconfig contexts inside the
// vault. The single-context path mirrors `fd0 ssh add`; the bulk-
// import path (`--from-config`) lets operators bootstrap from an
// existing ~/.talos/config file.
//
// For the --from-config path we deliberately read + parse the YAML
// BEFORE opening the vault session. That keeps the vault flock from
// being held during a symlink / 500 MB / non-UTF8 file read, which
// in the previous version blocked every other fd0 command until the
// read finished or failed.
func RunTalosAdd(ctx context.Context, o TalosAddOpts) error {
	// Bounded, kind-checked read happens before any session work.
	var preparsed []*talosctx.TalosContext
	if o.FromConfig != "" {
		raw, err := safeReadConfigFile(o.FromConfig, MaxConfigFile)
		if err != nil {
			return fmt.Errorf("--from-config: %w", err)
		}
		_, ctxs, err := talosctx.ParseTalosconfig(raw)
		if err != nil {
			return err
		}
		if len(ctxs) == 0 {
			return errors.New("--from-config: no contexts found in file")
		}
		preparsed = ctxs
	}

	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	scopeID, err := s.resolveScopeID(o.Scope)
	if err != nil {
		return err
	}

	if preparsed != nil {
		return importTalosconfigContexts(ctx, s, scopeID, preparsed, &o)
	}

	// Single-context path.
	c, err := buildTalosContextFromOpts(&o)
	if err != nil {
		return err
	}
	c.Scope = scopeID
	if err := c.Validate(); err != nil {
		return err
	}

	if err := ensureNoDuplicate(s, scopeID, talosNamePrefix, c.Name, o.Force); err != nil {
		return err
	}
	if err := storeTalosContext(ctx, s, scopeID, c); err != nil {
		return err
	}
	stderrln("✓ added talos context %q (scope: %s)", c.Name, scopeName(s, scopeID))
	return renderAndAutoMergeTalos(s)
}

func buildTalosContextFromOpts(o *TalosAddOpts) (*talosctx.TalosContext, error) {
	// Resolve PEM-from-file → base64.
	if o.CA == "" && o.CAFile != "" {
		b, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read --ca-file: %w", err)
		}
		o.CA = base64.StdEncoding.EncodeToString(b)
	}
	if o.Crt == "" && o.CrtFile != "" {
		b, err := os.ReadFile(o.CrtFile)
		if err != nil {
			return nil, fmt.Errorf("read --crt-file: %w", err)
		}
		o.Crt = base64.StdEncoding.EncodeToString(b)
	}
	if o.Key == "" && o.KeyFile != "" {
		b, err := os.ReadFile(o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read --key-file: %w", err)
		}
		o.Key = base64.StdEncoding.EncodeToString(b)
	}
	return &talosctx.TalosContext{
		Name:        o.Name,
		Endpoints:   talosctx.SplitEndpoints(o.Endpoints),
		Nodes:       talosctx.SplitEndpoints(o.Nodes),
		CA:          o.CA,
		Crt:         o.Crt,
		Key:         o.Key,
		Role:        o.Role,
		Description: o.Description,
		Tags:        o.Tags,
	}, nil
}

// importTalosconfigContexts is the part of `fd0 talos add
// --from-config` that mutates the vault. The file read + parse
// happens upstream in RunTalosAdd so the flock isn't held during a
// potentially-slow disk read.
func importTalosconfigContexts(ctx context.Context, s *Session, scopeID string, contexts []*talosctx.TalosContext, o *TalosAddOpts) error {
	if o.ImportContext != "" {
		filtered := make([]*talosctx.TalosContext, 0, 1)
		for _, c := range contexts {
			if c.Name == o.ImportContext {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("--import-context %q: not present in file", o.ImportContext)
		}
		contexts = filtered
	}
	for _, c := range contexts {
		c.Scope = scopeID
		c.Description = o.Description
		c.Role = o.Role
		c.Tags = append([]string(nil), o.Tags...)
		if err := c.Validate(); err != nil {
			stderrln("  ! skipping %q: %v", c.Name, err)
			continue
		}
		if err := ensureNoDuplicate(s, scopeID, talosNamePrefix, c.Name, o.Force); err != nil {
			stderrln("  ! skipping %q: %v", c.Name, err)
			continue
		}
		if err := storeTalosContext(ctx, s, scopeID, c); err != nil {
			return err
		}
		stderrln("✓ imported %q from %s (scope: %s)", c.Name, o.FromConfig, scopeName(s, scopeID))
	}
	return renderAndAutoMergeTalos(s)
}

func storeTalosContext(ctx context.Context, s *Session, scopeID string, c *talosctx.TalosContext) error {
	name := talosNamePrefix + c.Name
	return s.SetTypedSecret(ctx, scopeID, name, talosctx.TypeTalosContext, c.Marshal())
}

// RunTalosList prints the configured talos contexts.
func RunTalosList(ctx context.Context, scopeID string, anyTags, noTags []string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	contexts, err := loadTalosContexts(s, scopeID)
	if err != nil {
		return err
	}
	contexts = filterTalosContexts(contexts, anyTags, noTags)
	talosctx.SortContexts(contexts)
	if len(contexts) == 0 {
		stderrln("no talos contexts")
		return nil
	}
	for _, c := range contexts {
		extras := []string{}
		if c.Role != "" {
			extras = append(extras, c.Role)
		}
		if len(c.Tags) > 0 {
			extras = append(extras, "tags=["+strings.Join(c.Tags, ",")+"]")
		}
		extraStr := ""
		if len(extras) > 0 {
			extraStr = "  " + strings.Join(extras, "  ")
		}
		fmt.Printf("%-24s  %-30s  scope=%s%s\n",
			c.Name,
			firstEndpoint(c.Endpoints),
			scopeName(s, c.Scope),
			extraStr,
		)
	}
	return nil
}

// RunTalosShow prints a single talos context with detail.
func RunTalosShow(ctx context.Context, scopeID, name string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	c, err := lookupTalosContext(s, scopeID, name)
	if err != nil {
		return err
	}
	fmt.Println("name        :", c.Name)
	fmt.Println("scope       :", scopeName(s, c.Scope))
	fmt.Println("endpoints   :", strings.Join(c.Endpoints, ", "))
	if len(c.Nodes) > 0 {
		fmt.Println("nodes       :", strings.Join(c.Nodes, ", "))
	}
	if c.Role != "" {
		fmt.Println("role        :", c.Role)
	}
	if c.Description != "" {
		fmt.Println("description :", c.Description)
	}
	if len(c.Tags) > 0 {
		fmt.Println("tags        :", strings.Join(c.Tags, ", "))
	}
	fmt.Println("ca          : <" + lenDesc(c.CA) + " base64>")
	fmt.Println("crt         : <" + lenDesc(c.Crt) + " base64>")
	fmt.Println("key         : <" + lenDesc(c.Key) + " base64> (hidden)")
	return nil
}

// RunTalosRemove tombstones a talos context.
func RunTalosRemove(ctx context.Context, scopeID, name string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	target, err := lookupTalosContext(s, scopeID, name)
	if err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, target.Scope, talosNamePrefix+target.Name); err != nil {
		return err
	}
	stderrln("✓ removed talos context %q from scope %s", target.Name, scopeName(s, target.Scope))
	return renderAndAutoMergeTalos(s)
}

// RunTalosMove moves a context between scopes (you must own both).
// Now refuses to silently overwrite an existing context at the
// destination — same class of bug as RunTalosAdd's preflight, just
// in the move path. Use --force at the CLI to override.
func RunTalosMove(ctx context.Context, name, fromScope, toScope string, force bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	r, err := s.GetTypedSecret(fromScope, talosNamePrefix+name)
	if err != nil {
		return err
	}
	c, err := decodeTalosContext(*r)
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
	// Destination preflight — without this, an existing context in
	// the destination scope gets silently overwritten. Same bug
	// class as the original T2 finding, just in the move path.
	if err := ensureNoDuplicate(s, to, talosNamePrefix, name, force); err != nil {
		return err
	}
	c.Scope = to
	if err := storeTalosContext(ctx, s, to, c); err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, r.ScopeID, r.Name); err != nil {
		// Destination write succeeded but the secret now lives in
		// BOTH scopes. Tell the user the exact clean-up command —
		// vague "re-run to clean up" is misleading (re-running the
		// move command hits ensureNoDuplicate now and refuses).
		return fmt.Errorf("moved talos %q to %s but failed to remove from %s: %w (clean up with: fd0 talos rm %s --scope %s)",
			name, scopeName(s, to), scopeName(s, r.ScopeID), err, name, scopeName(s, r.ScopeID))
	}
	stderrln("✓ moved talos %q: %s → %s", name, scopeName(s, r.ScopeID), scopeName(s, to))
	return renderAndAutoMergeTalos(s)
}

func RunTalosEnable(ctx context.Context, merge bool) error {
	if err := RunTalosSync(ctx, merge); err != nil {
		return err
	}
	if err := setProjectionConfig("talos", true, merge); err != nil {
		return err
	}
	stderrln("✓ talos auto-refresh enabled")
	if merge {
		stderrln("✓ talos auto-merge enabled")
	}
	return nil
}

func RunTalosDisable(_ context.Context) error {
	if err := setProjectionConfig("talos", false, false); err != nil {
		return err
	}
	stderrln("✓ talos auto-refresh disabled")
	stderrln("  generated config left at %s", talosconfPath())
	return nil
}

// RunTalosSync re-renders ~/.talos/config.fd0 from the current vault
// state. When `merge` is true, folds the rendered file into
// ~/.talos/config via the pure-Go structural merge
// (mergeTalosconfigFile) — no talosctl required.
//
// The render happens under the session flock; the merge runs after the
// session is closed so a slow / read-only filesystem can't block every
// other fd0 command competing for the lock.
func RunTalosSync(ctx context.Context, merge bool) error {
	{
		s, err := Open(ctx)
		if err != nil {
			return err
		}
		if err := renderAndWarnTalos(s); err != nil {
			s.Close()
			return err
		}
		s.Close()
	}
	if merge {
		if err := mergeTalosconfigFile(talosconfPath(), userTalosconfigPath()); err != nil {
			return err
		}
		stderrln("✓ merged into %s", userTalosconfigPath())
		if err := setProjectionConfig("talos", true, true); err != nil {
			return err
		}
	}
	return nil
}

// renderAndWarnTalos renders the talosconfig from the current vault
// state to ~/.talos/config.fd0. It never touches the user's primary
// config — the optional fold-in is RunTalosSync(merge=true)'s pure-Go
// mergeTalosconfigFile.
func renderAndWarnTalos(s *Session) error {
	contexts, err := loadTalosContexts(s, "")
	if err != nil {
		return err
	}
	bytes, warnings := talosctx.Render(talosctx.RenderInput{
		Contexts: contexts,
		Now:      nowFunc(),
	})
	for _, w := range warnings {
		stderrln("⚠ %s", w)
	}
	return writeManagedFile(talosconfPath(), bytes, "contexts", len(contexts))
}

func renderAndAutoMergeTalos(s *Session) error {
	if err := renderAndWarnTalos(s); err != nil {
		return err
	}
	autoMergeTalosIfEnabled()
	return nil
}

func loadTalosContexts(s *Session, scopeID string) ([]*talosctx.TalosContext, error) {
	rows, err := s.ListTypedSecrets(scopeID, talosctx.TypeTalosContext)
	if err != nil {
		return nil, err
	}
	out := make([]*talosctx.TalosContext, 0, len(rows))
	for _, r := range rows {
		c, err := decodeTalosContext(r)
		if err != nil {
			stderrln("  ! malformed talos context %q in scope %s: %v",
				r.Name, scopeName(s, r.ScopeID), err)
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

func filterTalosContexts(cc []*talosctx.TalosContext, anyTags, noTags []string) []*talosctx.TalosContext {
	if len(anyTags) == 0 && len(noTags) == 0 {
		return cc
	}
	var out []*talosctx.TalosContext
next:
	for _, c := range cc {
		for _, t := range anyTags {
			if !c.HasTag(t) {
				continue next
			}
		}
		for _, t := range noTags {
			if c.HasTag(t) {
				continue next
			}
		}
		out = append(out, c)
	}
	return out
}

func decodeTalosContext(r TypedRecord) (*talosctx.TalosContext, error) {
	raw, err := r.PayloadJSON()
	if err != nil {
		return nil, err
	}
	c, err := talosctx.Unmarshal(raw)
	if err != nil {
		return nil, fmt.Errorf("decode talos %q: %w", r.Name, err)
	}
	c.Scope = r.ScopeID
	// Read-time Validate: prevent a poisoned peer-pushed record from
	// landing in ~/.talos/config.fd0. Mirror of decodeHost.
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("decode talos %q: untrusted payload: %w", r.Name, err)
	}
	return c, nil
}

func lookupTalosContext(s *Session, scopeID, name string) (*talosctx.TalosContext, error) {
	contexts, err := loadTalosContexts(s, scopeID)
	if err != nil {
		return nil, err
	}
	var match []*talosctx.TalosContext
	for _, c := range contexts {
		if c.Name == name {
			match = append(match, c)
		}
	}
	switch len(match) {
	case 0:
		if scopeID != "" {
			return nil, fmt.Errorf("no talos context %q in scope %s", name, scopeName(s, scopeID))
		}
		return nil, fmt.Errorf("no talos context %q in any scope", name)
	case 1:
		return match[0], nil
	default:
		return nil, fmt.Errorf("talos context %q is ambiguous across multiple scopes — use --scope", name)
	}
}

func firstEndpoint(ee []string) string {
	if len(ee) == 0 {
		return "(no endpoints)"
	}
	return ee[0]
}

func lenDesc(b64 string) string {
	if b64 == "" {
		return "0 bytes"
	}
	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Sprintf("%d chars (invalid)", len(b64))
	}
	return fmt.Sprintf("%d bytes", len(dec))
}
