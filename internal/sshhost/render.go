package sshhost

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RenderInput drives Render. Hosts are emitted in (Scope, Alias) order;
// SocketPath is written into IdentityAgent so the ssh client always
// resolves through fd0-agent. KnownKeys is keyed by vault and key
// name — names are only unique inside one vault, so resolving them
// globally could silently attach another vault's key.
type KeyRef struct {
	Scope string
	Name  string
}

type RenderInput struct {
	Hosts      []*Host
	SocketPath string
	KnownKeys  map[KeyRef]bool
	// PubKeyDir, when non-empty, is the directory holding the
	// per-host public-key selector files (<alias>.pub). For each host
	// with a resolvable fd0 key the renderer emits
	// `IdentityFile <PubKeyDir>/<alias>.pub` so OpenSSH can pick the
	// matching agent identity under `IdentitiesOnly yes`. The CLI
	// writes those files; the renderer only references them.
	PubKeyDir string
	// Now is injected for deterministic tests. Caller passes
	// time.Now() in production; tests pass a fixed value.
	Now time.Time
}

// Render produces the contents of ~/.ssh/fd0.conf as a byte slice.
// Pure function: same input → same output, suitable for diffing
// against the on-disk file before writing.
//
// The output is:
//
//	# Managed by fd0 — do not edit by hand; changes are overwritten.
//	# Generated: <RFC3339 timestamp>
//	# Include this from ~/.ssh/config to take effect.
//
//	# scope: <scope-name>
//	#@fd0:scope=<scope-name>
//	#@fd0:tags=<csv>
//	#@fd0:desc=<text>
//	Host <alias>
//	    HostName <hostname>
//	    User <user>
//	    Port <port>
//	    ProxyJump <jump>
//	    IdentityAgent <socket-path>
//	    IdentityFile <pub-key-dir>/<alias>.pub   (only if key resolves)
//	    IdentitiesOnly yes                        (only with IdentityFile)
//	    <Option> <Value>
//
// Cross-scope alias collisions emit a `# WARN` comment block at the
// top so the operator sees them; the FIRST occurrence (by sort order)
// wins per SSH first-match rules.
func Render(in RenderInput) ([]byte, error) {
	var b strings.Builder
	ts := in.Now.UTC().Format(time.RFC3339)

	b.WriteString("# Managed by fd0 — do not edit by hand; changes are overwritten.\n")
	b.WriteString("# Generated: ")
	b.WriteString(ts)
	b.WriteString("\n")
	b.WriteString("# Include this file from your ~/.ssh/config:\n")
	b.WriteString("#     Include ~/.ssh/fd0.conf\n")
	b.WriteString("# fd0 will warn on every render until that line is in place.\n")
	b.WriteString("\n")

	hosts := append([]*Host(nil), in.Hosts...)
	SortHosts(hosts)

	// Detect alias collisions across scopes (within-scope is enforced at
	// add-time). Surface them at the top so the user sees the conflict
	// before scrolling through the body.
	dupes := findAliasDupes(hosts)
	if len(dupes) > 0 {
		b.WriteString("# ─── WARNING: alias collisions across scopes ─────────────\n")
		for _, d := range dupes {
			fmt.Fprintf(&b, "#   alias %q defined in scopes [%s] — %q wins by sort order\n",
				d.Alias, strings.Join(d.Scopes, ", "), d.Scopes[0])
		}
		b.WriteString("# Use `fd0 ssh edit` to rename or move one of the conflicting hosts.\n")
		b.WriteString("\n")
	}

	currentScope := ""
	emittedAliases := map[string]bool{}
	for _, h := range hosts {
		if err := h.Validate(); err != nil {
			return nil, fmt.Errorf("render host %q: %w", h.Alias, err)
		}
		options, err := SharedOptions(h.Options)
		if err != nil {
			return nil, fmt.Errorf("render host %q: %w", h.Alias, err)
		}
		// Suppress duplicate aliases — first wins per SSH semantics.
		if emittedAliases[h.Alias] {
			continue
		}
		emittedAliases[h.Alias] = true

		if h.Scope != currentScope {
			currentScope = h.Scope
			fmt.Fprintf(&b, "# ─── scope: %s ────────────────────────────────\n", currentScope)
		}

		// Metadata comments — invisible to ssh, queryable by external
		// tooling (sshclick-style #@fd0: prefix).
		fmt.Fprintf(&b, "#@fd0:scope=%s\n", currentScope)
		if len(h.Tags) > 0 {
			fmt.Fprintf(&b, "#@fd0:tags=%s\n", strings.Join(h.Tags, ","))
		}
		if h.Description != "" {
			fmt.Fprintf(&b, "#@fd0:desc=%s\n", oneLine(h.Description))
		}

		// Warn on missing key references (the host stays valid; SSH
		// will fall back to whatever the agent serves).
		keyRef := KeyRef{Scope: h.Scope, Name: h.KeyName}
		if h.KeyName != "" && in.KnownKeys != nil && !in.KnownKeys[keyRef] {
			fmt.Fprintf(&b, "# WARN: host %q references missing key %q\n", h.Alias, h.KeyName)
		}

		fmt.Fprintf(&b, "Host %s\n", h.Alias)
		fmt.Fprintf(&b, "    HostName %s\n", h.Hostname)
		if h.User != "" {
			fmt.Fprintf(&b, "    User %s\n", h.User)
		}
		if h.Port != 0 && h.Port != 22 {
			fmt.Fprintf(&b, "    Port %d\n", h.Port)
		}
		if h.ProxyJump != "" {
			fmt.Fprintf(&b, "    ProxyJump %s\n", h.ProxyJump)
		}
		if in.SocketPath != "" {
			socketPath, err := sshConfigPath(in.SocketPath)
			if err != nil {
				return nil, fmt.Errorf("render identity agent: %w", err)
			}
			fmt.Fprintf(&b, "    IdentityAgent %s\n", socketPath)

			// IdentitiesOnly is only safe to set when we also pin an
			// IdentityFile: it tells OpenSSH to offer ONLY identities
			// matching a configured file. With a per-host public-key
			// selector, ssh picks the right agent key deterministically.
			// Without one (host has no fd0 key), emitting IdentitiesOnly
			// would suppress the user's own ~/.ssh keys too — so for
			// keyless hosts we emit IdentityAgent alone.
			hasKey := h.KeyName != "" && in.KnownKeys != nil && in.KnownKeys[keyRef]
			if hasKey && in.PubKeyDir != "" {
				pub := filepath.Join(in.PubKeyDir, h.Alias+".pub")
				pubPath, err := sshConfigPath(pub)
				if err != nil {
					return nil, fmt.Errorf("render identity file: %w", err)
				}
				fmt.Fprintf(&b, "    IdentityFile %s\n", pubPath)
				fmt.Fprintf(&b, "    IdentitiesOnly yes\n")
			}
		}
		for _, option := range options {
			fmt.Fprintf(&b, "    %s %s\n", option.Name, option.Value)
		}
		b.WriteString("\n")
	}

	return []byte(b.String()), nil
}

// sshConfigPath keeps filesystem paths as one OpenSSH argument. Normal Unix
// paths stay unchanged; paths with whitespace or quoting characters are
// double-quoted and escaped.
func sshConfigPath(path string) (string, error) {
	if strings.ContainsAny(path, "\x00\r\n") {
		return "", fmt.Errorf("path contains an invalid control character")
	}
	if !strings.ContainsAny(path, " \t\"\\") {
		return path, nil
	}
	escaped := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
	).Replace(path)
	return `"` + escaped + `"`, nil
}

// dupeRow is one entry in the cross-scope collision report.
type dupeRow struct {
	Alias  string
	Scopes []string
}

// findAliasDupes scans for aliases defined in more than one scope.
// Returns a sorted slice of (alias, scopes) pairs.
func findAliasDupes(hosts []*Host) []dupeRow {
	byAlias := map[string]map[string]bool{}
	for _, h := range hosts {
		if byAlias[h.Alias] == nil {
			byAlias[h.Alias] = map[string]bool{}
		}
		byAlias[h.Alias][h.Scope] = true
	}
	var out []dupeRow
	for alias, scopes := range byAlias {
		if len(scopes) <= 1 {
			continue
		}
		s := make([]string, 0, len(scopes))
		for sc := range scopes {
			s = append(s, sc)
		}
		sort.Strings(s)
		out = append(out, dupeRow{Alias: alias, Scopes: s})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// oneLine collapses any newlines in a description to a space. The
// renderer relies on each metadata comment fitting on one line so the
// host block boundaries stay scannable.
func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}
