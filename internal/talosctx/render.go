package talosctx

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RenderInput is the pure-function input for the rendered
// ~/.talos/config.fd0. The output is deterministic for any given
// input — same input bytes, same output bytes.
type RenderInput struct {
	// Contexts is the set of contexts to emit. Caller is responsible
	// for filtering / cross-scope dedup before invoking Render.
	Contexts []*TalosContext

	// ActiveContext, if non-empty and matching a context in the
	// list, is emitted as the `context:` top-level pointer.
	ActiveContext string

	// Now is injected so the header timestamp is reproducible
	// from tests.
	Now time.Time
}

// Render returns a deterministic YAML blob safe to write to
// ~/.talos/config.fd0. It also surfaces a list of warnings (e.g.
// cross-scope name collisions) so the caller can print them to
// stderr without aborting.
func Render(in RenderInput) (data []byte, warnings []string) {
	contexts := append([]*TalosContext(nil), in.Contexts...)
	SortContexts(contexts)

	// Detect cross-scope name collisions. Same logic as sshhost.
	seen := map[string]*TalosContext{}
	emit := make([]*TalosContext, 0, len(contexts))
	for _, c := range contexts {
		if prev, ok := seen[c.Name]; ok {
			warnings = append(warnings,
				fmt.Sprintf("context name %q exists in both scope %q and %q — first-by-sort wins",
					c.Name, prev.Scope, c.Scope))
			continue
		}
		seen[c.Name] = c
		emit = append(emit, c)
	}

	// Build the on-wire struct, then yaml.Marshal so quoting + key
	// ordering follow standard rules. Map ordering inside go-yaml
	// is alphabetical for maps; we then post-process to inject the
	// fd0 header.
	out := rawTalosconfig{
		Contexts: map[string]*rawContext{},
	}
	if in.ActiveContext != "" && seen[in.ActiveContext] != nil {
		out.Context = in.ActiveContext
	}
	for _, c := range emit {
		out.Contexts[c.Name] = &rawContext{
			Endpoints: c.Endpoints,
			Nodes:     c.Nodes,
			CA:        c.CA,
			Crt:       c.Crt,
			Key:       c.Key,
		}
	}

	body, err := yaml.Marshal(out)
	if err != nil {
		// yaml.Marshal of well-typed structs doesn't fail; if it
		// does we still want to be deterministic.
		return []byte(fmt.Sprintf("# render error: %v\n", err)), warnings
	}

	// Header — same shape as ~/.ssh/fd0.conf. Includes the per-
	// scope inventory so the operator can grep without opening
	// the vault.
	header := renderHeader(emit, in.Now, warnings)
	return append([]byte(header), body...), warnings
}

func renderHeader(cc []*TalosContext, now time.Time, warnings []string) string {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "# fd0 — managed talosconfig. Do not edit by hand.")
	fmt.Fprintln(&buf, "#")
	fmt.Fprintln(&buf, "# Regenerate with `fd0 talos sync`. The original ~/.talos/config")
	fmt.Fprintln(&buf, "# is left alone — this file is meant to be merged via")
	fmt.Fprintln(&buf, "#   talosctl --talosconfig ~/.talos/config.fd0 \\")
	fmt.Fprintln(&buf, "#            config merge ~/.talos/config.fd0")
	fmt.Fprintln(&buf, "# (`fd0 talos sync --merge` does this automatically).")
	fmt.Fprintln(&buf, "#")
	fmt.Fprintf(&buf,  "# Rendered at %s · %d context(s)\n",
		now.UTC().Format("2006-01-02 15:04:05 UTC"), len(cc))

	// Inventory grouped by scope. Helpful for `cat ~/.talos/config.fd0 | head`.
	byScope := map[string][]*TalosContext{}
	for _, c := range cc {
		byScope[c.Scope] = append(byScope[c.Scope], c)
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
		for _, c := range byScope[s] {
			suffix := ""
			if c.Role != "" {
				suffix = " (" + c.Role + ")"
			}
			names = append(names, c.Name+suffix)
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
