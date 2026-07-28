package cli

// `fd0 ssh` host-management commands. Hosts are typed secrets with
// Name `host:<alias>` and Type `fd0-host`. The renderer emits a
// scope-scoped ssh_config snippet to ~/.ssh/fd0.conf (default;
// overridable via FD0_SSH_CONFIG_PATH). Every mutating command
// re-renders before returning so users never have to think about
// "fd0 ssh sync" — there is no such command on purpose.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
)

// hostNamePrefix is the convention for host secret names — see also
// keyNamePrefix in cli/key.go. The renderer strips it before emitting
// the SSH `Host` directive.
const hostNamePrefix = "host:"

// HostAddOpts bundles every flag `fd0 ssh add` understands. The
// command in cmd/fd0/main.go wires kong flags into this struct.
type HostAddOpts struct {
	Alias       string // `fd0 ssh add Alias ...`
	ConnString  string // optional `[user@]host[:port]`
	Hostname    string // overrides ConnString.host
	User        string // overrides ConnString.user
	Port        int    // overrides ConnString.port
	KeyName     string // existing fd0 key to reference
	WithKey     bool   // generate a new key (name = Alias unless WithKeyName)
	WithKeyName string // custom name for the generated key
	ProxyJump   string // SSH alias to jump through
	Tags        []string
	Description string
	Options     map[string]string
	Scope       string
	Force       bool // overwrite an existing host (and auto-generated key) with the same name
}

// RunHostAdd creates a new host in the given scope. If WithKey is set,
// generates a fresh ed25519 key inside the same scope first and
// references it.
func RunHostAdd(ctx context.Context, o HostAddOpts) error {
	if o.Alias == "" {
		return errors.New("ssh add: ALIAS required")
	}

	// Parse the conn-string into typed fields; explicit flags win.
	u, h, p, err := sshhost.ParseConnString(o.ConnString)
	if err != nil {
		return err
	}
	if o.Hostname == "" {
		o.Hostname = h
	}
	if o.User == "" {
		o.User = u
	}
	if o.Port == 0 {
		o.Port = p
	}
	if o.Hostname == "" {
		return errors.New("ssh add: hostname required (positional `[user@]HOST[:port]` or --user/--port)")
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

	// Per-scope uniqueness check via the typed-sentinel preflight so
	// a transient vault error can't silently turn into "no duplicate".
	if err := ensureNoDuplicate(s, scope, hostNamePrefix, o.Alias, o.Force); err != nil {
		return err
	}

	// `--with-key` generates a key and links by name. Name defaults
	// to the host alias unless --with-key=NAME is given.
	if o.WithKey {
		keyName := o.WithKeyName
		if keyName == "" {
			keyName = o.Alias
		}
		if o.KeyName != "" && o.KeyName != keyName {
			return errors.New("ssh add: cannot use --key and --with-key together")
		}
		if err := ensureNoDuplicate(s, scope, keyNamePrefix, keyName, o.Force); err != nil {
			return err
		}
		k, err := sshkey.NewEd25519(keyName, "")
		if err != nil {
			return fmt.Errorf("ssh add --with-key: %w", err)
		}
		if err := s.SetTypedSecret(ctx, scope, keyNamePrefix+keyName, string(k.Type), k.Marshal()); err != nil {
			return err
		}
		o.KeyName = keyName
		stderrln("✓ generated key %q (ed25519, scope: %s, %s)", keyName, scopeName(s, scope), k.Fingerprint())
		fmt.Println()
		fmt.Println(k.AuthorizedKeyLine())
		fmt.Println()
	}

	if o.KeyName != "" {
		_, err := s.GetTypedSecret(scope, keyNamePrefix+o.KeyName)
		if err != nil {
			// Surface "really not found" cleanly; pass other lookup
			// errors verbatim so the user sees the underlying cause.
			if errors.Is(err, ErrTypedSecretNotFound) {
				return fmt.Errorf("ssh add: --key %q not found in scope %s", o.KeyName, scopeName(s, scope))
			}
			return err
		}
	}

	host := &sshhost.Host{
		Alias:       o.Alias,
		Hostname:    o.Hostname,
		User:        o.User,
		Port:        o.Port,
		KeyName:     o.KeyName,
		ProxyJump:   o.ProxyJump,
		Tags:        o.Tags,
		Description: o.Description,
		Options:     o.Options,
		Scope:       scope,
	}
	if err := host.Validate(); err != nil {
		return err
	}

	if err := s.SetTypedSecret(ctx, scope, hostNamePrefix+host.Alias, sshhost.TypeHost, host.Marshal()); err != nil {
		return err
	}
	stderrln("✓ host %q added to %s", host.Alias, scopeName(s, scope))

	// Re-render immediately + warn if Include is missing.
	if err := renderAndWarn(s); err != nil {
		stderrln("⚠ render: %v", err)
	}
	hintSyncForPeers()
	return nil
}

// hostListRow is the machine-readable shape of one host.
//
// A host record holds no secret material — the key it names lives in its own
// record and only ever leaves through the SSH agent — so the row is the whole
// connection metadata. It is spelled out rather than marshalled from
// sshhost.Host so a future field cannot join a public interface unreviewed.
type hostListRow struct {
	Alias       string            `json:"alias"`
	Hostname    string            `json:"hostname"`
	User        string            `json:"user,omitempty"`
	Port        int               `json:"port,omitempty"`
	KeyName     string            `json:"keyName,omitempty"`
	ProxyJump   string            `json:"proxyJump,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
	Scope       string            `json:"scope,omitempty"`
	ScopeID     string            `json:"scopeId"`
}

// RunHostList prints every fd0-managed SSH host. Tag-filtering
// supports AND (`--tag prod --tag db` requires both) and exclusion
// (`--no-tag deprecated`).
func RunHostList(ctx context.Context, scopeID string, anyTags, noTags []string, jsonOut bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	hosts, err := loadHosts(s, scopeID)
	if err != nil {
		return err
	}
	hosts = filterHosts(hosts, anyTags, noTags)
	if jsonOut {
		sshhost.SortHosts(hosts)
		rows := make([]hostListRow, 0, len(hosts))
		for _, h := range hosts {
			rows = append(rows, hostListRow{
				Alias:       h.Alias,
				Hostname:    h.Hostname,
				User:        h.User,
				Port:        h.Port,
				KeyName:     h.KeyName,
				ProxyJump:   h.ProxyJump,
				Description: h.Description,
				Tags:        h.Tags,
				Options:     h.Options,
				Scope:       scopeLabelOf(s, h.Scope),
				ScopeID:     h.Scope,
			})
		}
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	if len(hosts) == 0 {
		stderrln("no hosts")
		return nil
	}
	sshhost.SortHosts(hosts)
	for _, h := range hosts {
		extra := h.Hostname
		if h.User != "" {
			extra = h.User + "@" + extra
		}
		if h.ProxyJump != "" {
			extra += "  jump=" + h.ProxyJump
		}
		fmt.Printf("%-20s  %-12s  %s\n", h.Alias, scopeName(s, h.Scope), extra)
		if len(h.Tags) > 0 {
			fmt.Printf("%-20s  %-12s  #%s\n", "", "", strings.Join(h.Tags, " #"))
		}
		if h.Description != "" {
			fmt.Printf("%-20s  %-12s  %s\n", "", "", h.Description)
		}
	}
	return nil
}

// RunHostShow prints one host's full record + the ssh_config snippet
// it renders to. Useful for verifying changes before scope-syncing.
func RunHostShow(ctx context.Context, scopeID, alias string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(scopeID, hostNamePrefix+alias)
	if err != nil {
		return err
	}
	h, err := decodeHost(*r)
	if err != nil {
		return err
	}
	fmt.Printf("%s  [scope: %s]\n", h.Alias, scopeName(s, r.ScopeID))
	fmt.Printf("  hostname  %s\n", h.Hostname)
	if h.User != "" {
		fmt.Printf("  user      %s\n", h.User)
	}
	if h.Port != 0 {
		fmt.Printf("  port      %d\n", h.Port)
	}
	if h.KeyName != "" {
		fmt.Printf("  key       %s\n", h.KeyName)
	}
	if h.ProxyJump != "" {
		fmt.Printf("  jump      %s\n", h.ProxyJump)
	}
	if len(h.Tags) > 0 {
		fmt.Printf("  tags      %s\n", strings.Join(h.Tags, ", "))
	}
	if h.Description != "" {
		fmt.Printf("  desc      %s\n", h.Description)
	}
	if len(h.Options) > 0 {
		keys := make([]string, 0, len(h.Options))
		for k := range h.Options {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %s %s\n", k, h.Options[k])
		}
	}
	fmt.Println()
	fmt.Println("ssh_config render:")
	keysSet := map[sshhost.KeyRef]bool{}
	if rows, err := s.ListTypedSecrets("", ""); err == nil {
		for _, r := range rows {
			if strings.HasPrefix(r.Type, "ssh-") {
				keysSet[sshhost.KeyRef{Scope: r.ScopeID, Name: strings.TrimPrefix(r.Name, keyNamePrefix)}] = true
			}
		}
	}
	out, err := sshhost.Render(sshhost.RenderInput{
		Hosts: []*sshhost.Host{h}, SocketPath: SSHSocketPathForRender(), KnownKeys: keysSet, Now: nowFunc(),
	})
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// RunHostRemove tombstones the host. The next render drops the entry.
func RunHostRemove(ctx context.Context, scopeID, alias string, yes bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(scopeID, hostNamePrefix+alias)
	if err != nil {
		return err
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove SSH host %q from %s?", alias, scopeName(s, r.ScopeID))); err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, r.ScopeID, r.Name); err != nil {
		return err
	}
	stderrln("✓ removed host %q from %s", alias, scopeName(s, r.ScopeID))
	if err := renderAndWarn(s); err != nil {
		stderrln("⚠ render: %v", err)
	}
	hintSyncForPeers()
	return nil
}

// RunHostTag mutates the tag list on an existing host without
// requiring `host edit` for the common case. Add and Remove are
// mutually exclusive at call time (the CLI enforces that with kong
// constraints).
func RunHostTag(ctx context.Context, scopeID, alias string, add, remove []string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(scopeID, hostNamePrefix+alias)
	if err != nil {
		return err
	}
	h, err := decodeHost(*r)
	if err != nil {
		return err
	}
	tagSet := map[string]bool{}
	for _, t := range h.Tags {
		tagSet[t] = true
	}
	for _, t := range remove {
		delete(tagSet, t)
	}
	for _, t := range add {
		tagSet[t] = true
	}
	h.Tags = h.Tags[:0]
	for t := range tagSet {
		h.Tags = append(h.Tags, t)
	}
	sort.Strings(h.Tags)
	if err := s.SetTypedSecret(ctx, r.ScopeID, r.Name, sshhost.TypeHost, h.Marshal()); err != nil {
		return err
	}
	stderrln("✓ tags for %q: %s", alias, strings.Join(h.Tags, ", "))
	if err := renderAndWarn(s); err != nil {
		stderrln("⚠ render: %v", err)
	}
	hintSyncForPeers()
	return nil
}

// RunHostMove relocates a host between scopes. Same idea as RunKeyMove.
func RunHostMove(ctx context.Context, alias, fromScope, toScope string, force bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.MoveItem(ctx, KindHost, alias, fromScope, toScope, force)
}

// ----- helpers -----

// loadHosts pulls every host secret out of the vault and rehydrates
// them into the concrete sshhost.Host shape. Used by the list/render
// paths.
func loadHosts(s *Session, scopeID string) ([]*sshhost.Host, error) {
	rows, err := s.ListTypedSecrets(scopeID, sshhost.TypeHost)
	if err != nil {
		return nil, err
	}
	var out []*sshhost.Host
	for _, r := range rows {
		h, err := decodeHost(r)
		if err != nil {
			stderrln("  ! malformed host %q in scope %s: %v", r.Name, scopeName(s, r.ScopeID), err)
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

// filterHosts applies tag-filtering. anyTags is AND semantics (host
// must carry every tag in the list); noTags excludes (host must
// carry NONE of these). Empty filters pass everything through.
func filterHosts(hosts []*sshhost.Host, anyTags, noTags []string) []*sshhost.Host {
	if len(anyTags) == 0 && len(noTags) == 0 {
		return hosts
	}
	var out []*sshhost.Host
nextHost:
	for _, h := range hosts {
		for _, t := range anyTags {
			if !h.HasTag(t) {
				continue nextHost
			}
		}
		for _, t := range noTags {
			if h.HasTag(t) {
				continue nextHost
			}
		}
		out = append(out, h)
	}
	return out
}

// decodeHost is the dual of host.Marshal — reads the JSON-encoded
// payload back into the typed Host shape. Scope is filled from the
// surrounding TypedRecord since it's not part of the JSON value.
//
// Validate() runs again here, even though every Add path already
// validates at write time. A malicious or buggy sync peer could push
// a TypedRecord with a poisoned Hostname/User/ProxyJump/Tag that
// bypasses the write-time guard; without the load-time check, the
// renderer would emit the injection verbatim into ssh_config. Read-
// time Validate makes the threat model symmetric.
func decodeHost(r TypedRecord) (*sshhost.Host, error) {
	raw, err := r.PayloadJSON()
	if err != nil {
		return nil, err
	}
	var j sshhost.JSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("decode host %q: %w", r.Name, err)
	}
	h, err := sshhost.Unmarshal(j)
	if err != nil {
		return nil, err
	}
	h.Scope = r.ScopeID
	if err := h.Validate(); err != nil {
		return nil, fmt.Errorf("decode host %q: untrusted payload: %w", r.Name, err)
	}
	return h, nil
}

// renderAndWarn re-renders ~/.ssh/fd0.conf and emits the Include
// warning to stderr if the user's ssh_config doesn't reference our
// path. Idempotent — same vault state = same bytes on disk.
func renderAndWarn(s *Session) error {
	return renderSSHConfig(s, true)
}

func renderSSHForConnect(s *Session) error {
	return renderSSHConfig(s, false)
}

func renderSSHConfig(s *Session, warnInclude bool) error {
	hosts, err := loadHosts(s, "")
	if err != nil {
		return err
	}
	// Load keys once: presence (for the missing-reference warning)
	// plus the public-key line (for the per-host selector files).
	known := map[sshhost.KeyRef]bool{}
	keyPub := map[sshhost.KeyRef][]byte{}
	if rows, err := s.ListTypedSecrets("", ""); err == nil {
		for _, r := range rows {
			if !strings.HasPrefix(r.Type, "ssh-") {
				continue
			}
			ref := sshhost.KeyRef{Scope: r.ScopeID, Name: strings.TrimPrefix(r.Name, keyNamePrefix)}
			known[ref] = true
			if k, err := decodeKey(r); err == nil {
				keyPub[ref] = k.Public
			}
		}
	}

	pubDir := SSHPubKeyDir()
	if err := syncPubKeyFiles(pubDir, hosts, keyPub); err != nil {
		return err
	}

	bytes, err := sshhost.Render(sshhost.RenderInput{
		Hosts:      hosts,
		SocketPath: SSHSocketPathForRender(),
		KnownKeys:  known,
		PubKeyDir:  pubDir,
		Now:        nowFunc(),
	})
	if err != nil {
		return err
	}
	target := SSHConfPath()
	if err := writeManagedFile(target, bytes, "hosts", len(hosts)); err != nil {
		return err
	}
	if warnInclude {
		checkInclude(target)
	}
	return nil
}

// syncPubKeyFiles writes one public-key selector file (<alias>.pub)
// per host that has a resolvable fd0 key, and prunes any stale *.pub
// left behind by removed hosts or rotated-away keys. These are local
// render artifacts — fully regenerable from vault state — so the whole
// directory is fd0-managed. Public keys only; no private material ever
// touches disk.
func syncPubKeyFiles(dir string, hosts []*sshhost.Host, keyPub map[sshhost.KeyRef][]byte) error {
	wanted := map[string]bool{}
	for _, h := range hosts {
		if h.KeyName == "" {
			continue
		}
		pub := keyPub[sshhost.KeyRef{Scope: h.Scope, Name: h.KeyName}]
		if len(pub) == 0 {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		// authorized_keys lines are stored without a trailing newline;
		// ssh tolerates either, but a newline keeps the file tidy.
		if pub[len(pub)-1] != '\n' {
			pub = append(append([]byte(nil), pub...), '\n')
		}
		name := h.Alias + ".pub"
		if err := writeFileAtomic(filepath.Join(dir, name), pub, 0o600); err != nil {
			return err
		}
		wanted[name] = true
	}

	// Prune stale selector files. ReadDir on a missing dir is fine —
	// nothing was written, nothing to prune.
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".pub") || wanted[n] {
			continue
		}
		_ = os.Remove(filepath.Join(dir, n))
	}
	return nil
}

// checkInclude emits the missing-Include warning if applicable. It
// never errors — the warning is advisory.
func checkInclude(fd0ConfPath string) {
	userCfg := sshhost.DefaultUserConfigPath()
	ok, err := sshhost.HasInclude(userCfg, fd0ConfPath)
	if err != nil {
		stderrln("⚠ couldn't check %s: %v", userCfg, err)
		return
	}
	if ok {
		return
	}
	stderrln("")
	stderrln("⚠ %s doesn't include %s — `ssh <alias>` won't work yet.", userCfg, fd0ConfPath)
	stderrln("  Add this line to the TOP of %s:", userCfg)
	stderrln("      Include %s", fd0ConfPath)
	stderrln("  Or run: fd0 ssh enable")
	stderrln("")
}

// writeFileAtomic writes data to a temporary file in the same
// directory, fsyncs, then renames over the target — survives crash
// without partial-write corruption.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := parentDir(path)
	f, err := os.CreateTemp(dir, ".fd0.conf-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parentDir(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[:i]
	}
	return "."
}

// HostEditOpts patches an existing host. Every field is a pointer so that
// "flag not given" stays distinguishable from "flag set to empty" — clearing a
// jump host or a description is a real edit, not a no-op.
type HostEditOpts struct {
	Alias       string
	Scope       string
	Hostname    *string
	User        *string
	Port        *int
	KeyName     *string
	ProxyJump   *string
	Description *string
	Tags        *[]string
	Options     map[string]string
	// ClearOptions empties the option map; merging cannot express removal.
	ClearOptions bool
}

// RunHostEdit changes only the fields the user named, leaving the rest alone.
func RunHostEdit(ctx context.Context, o HostEditOpts) error {
	if o.Alias == "" {
		return errors.New("ssh edit: ALIAS required")
	}
	return EditItem(ctx, KindHost, o.Scope, o.Alias,
		decodeHost,
		func(h *sshhost.Host) (bool, error) {
			changed := false
			setString(&h.Hostname, o.Hostname, &changed)
			setString(&h.User, o.User, &changed)
			setInt(&h.Port, o.Port, &changed)
			setString(&h.KeyName, o.KeyName, &changed)
			setString(&h.ProxyJump, o.ProxyJump, &changed)
			setString(&h.Description, o.Description, &changed)
			setStrings(&h.Tags, o.Tags, &changed)
			if o.ClearOptions && len(h.Options) > 0 {
				h.Options = nil
				changed = true
			}
			for name, value := range o.Options {
				if h.Options == nil {
					h.Options = map[string]string{}
				}
				if h.Options[name] != value {
					h.Options[name] = value
					changed = true
				}
			}
			return changed, nil
		},
		func(h *sshhost.Host) error { return h.Validate() },
		func(h *sshhost.Host) (string, any) { return sshhost.TypeHost, h.Marshal() },
	)
}

// RunHostRename renames a host. The alias is both the record name and a field
// inside the record, so the stored copy is rewritten to match.
func RunHostRename(ctx context.Context, scopeID, oldAlias, newAlias string, force bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.RenameItem(ctx, KindHost, scopeID, oldAlias, newAlias, force,
		func(payload []byte, newName string) ([]byte, error) {
			var wire sshhost.JSON
			if err := json.Unmarshal(payload, &wire); err != nil {
				return nil, err
			}
			h, err := sshhost.Unmarshal(wire)
			if err != nil {
				return nil, err
			}
			h.Alias = newName
			if err := h.Validate(); err != nil {
				return nil, err
			}
			return json.Marshal(h.Marshal())
		},
	)
}
