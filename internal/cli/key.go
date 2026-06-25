package cli

// `fd0 key` commands. Keys are top-level objects stored as typed
// secrets in scopes: name format `ssh:<keyname>`, Type set to the
// algorithm string (e.g. ssh-ed25519), Payload is the JSON-marshalled
// sshkey.JSON. The SSH agent socket lists every typed secret whose
// Type starts with "ssh-".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/sshkey"
)

// keyNamePrefix is the convention for SSH-key secret names. Keeping
// the prefix means a user-set string secret named "deploy" never
// shadows an SSH key also named "deploy" — they live in different
// names ("deploy" vs "ssh:deploy") inside the same scope.
const keyNamePrefix = "ssh:"

// KeyOpts bundles the flags shared between `fd0 key add` and
// `fd0 key add --import` so the command wiring in cmd/fd0/main.go
// stays minimal.
type KeyOpts struct {
	Name       string
	Scope      string
	Type       string // "ed25519" for new; empty defers to import path
	Comment    string
	ImportPath string // when non-empty, import from this path
	Passphrase string // for encrypted import; rarely used non-interactively
	Force      bool   // overwrite an existing key with the same name
}

// RunKeyAdd generates a new ed25519 key or imports an existing
// OpenSSH-format private key, then stores the result as a typed secret
// in scopeID. Defaults: type ed25519, scope = first active.
func RunKeyAdd(ctx context.Context, o KeyOpts) error {
	if o.Name == "" {
		return errors.New("key add: NAME required")
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

	// Refuse duplicate names within the scope — same convention as
	// regular secrets but checked up-front so users see the error
	// before the keygen happens. Uses the typed-sentinel preflight
	// so a transient vault error doesn't silently turn into "no
	// duplicate, proceed".
	if err := ensureNoDuplicate(s, scope, keyNamePrefix, o.Name, o.Force); err != nil {
		return err
	}

	var k *sshkey.Key
	switch {
	case o.ImportPath != "":
		pem, err := os.ReadFile(o.ImportPath)
		if err != nil {
			return fmt.Errorf("key add --import: read %s: %w", o.ImportPath, err)
		}
		k, err = sshkey.ImportOpenSSH(pem, []byte(o.Passphrase), o.Name)
		if err != nil {
			return fmt.Errorf("key add --import: %w", err)
		}
		stderrln("✓ imported %s key %q (scope: %s, %s)",
			string(k.Type), o.Name, scopeName(s, scope), k.Fingerprint())
	default:
		if o.Type != "" && o.Type != "ed25519" {
			return fmt.Errorf("key add: only --type=ed25519 is supported for generation (got %q)", o.Type)
		}
		k, err = sshkey.NewEd25519(o.Name, o.Comment)
		if err != nil {
			return fmt.Errorf("key add: %w", err)
		}
		stderrln("✓ generated ed25519 key %q (scope: %s, %s)",
			o.Name, scopeName(s, scope), k.Fingerprint())
	}

	if err := s.SetTypedSecret(ctx, scope, keyNamePrefix+o.Name, string(k.Type), k.Marshal()); err != nil {
		return err
	}
	if err := renderSSHWithSessionIfEnabled(s); err != nil {
		stderrln("⚠ ssh render: %v", err)
	}

	// Print the public-key line right after add — the user's next
	// step is almost always to copy this to a remote authorized_keys.
	fmt.Println()
	fmt.Println(k.AuthorizedKeyLine())
	fmt.Println()

	return nil
}

// RunKeyList prints every fd0-managed SSH key. Filters by scope and
// optionally a list of tags (AND semantics across multiple --tag).
func RunKeyList(ctx context.Context, scopeID string, _ []string, _ []string) error {
	// Tags aren't currently stored on key secrets — we keep the
	// parameter for parity with `fd0 ssh ls` and future tagging.
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	rows, err := s.ListTypedSecrets(scopeID, "")
	if err != nil {
		return err
	}
	// Filter to typed secrets representing SSH keys (Type starts with "ssh-").
	var keys []TypedRecord
	for _, r := range rows {
		if !strings.HasPrefix(r.Type, "ssh-") {
			continue
		}
		keys = append(keys, r)
	}
	if len(keys) == 0 {
		stderrln("no keys")
		return nil
	}
	for _, r := range keys {
		k, err := decodeKey(r)
		if err != nil {
			stderrln("  ! malformed key %q in scope %s: %v", r.Name, scopeName(s, r.ScopeID), err)
			continue
		}
		name := strings.TrimPrefix(r.Name, keyNamePrefix)
		fmt.Printf("%-20s  %-12s  %s  %s\n", name, k.Type, scopeName(s, r.ScopeID), k.Fingerprint())
	}
	return nil
}

// RunKeyShow prints either the typed-secret JSON or the public key
// line depending on the `pub` flag. The default is the human-friendly
// summary; --pub prints the bare authorized_keys line for piping.
func RunKeyShow(ctx context.Context, scopeID, name string, pubOnly bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(scopeID, keyNamePrefix+name)
	if err != nil {
		return err
	}
	k, err := decodeKey(*r)
	if err != nil {
		return err
	}
	if pubOnly {
		fmt.Println(k.AuthorizedKeyLine())
		return nil
	}
	fmt.Printf("%s  [scope: %s]\n", name, scopeName(s, r.ScopeID))
	fmt.Printf("  type        %s\n", k.Type)
	fmt.Printf("  fingerprint %s\n", k.Fingerprint())
	fmt.Printf("  comment     %s\n", k.Comment)
	fmt.Println()
	fmt.Println(k.AuthorizedKeyLine())
	return nil
}

// RunKeyRemove tombstones the key secret. Sibling host secrets
// referencing the key by name keep their KeyName field; the renderer
// emits a "missing key" warning until the host is also rmd or its
// key reference is changed.
func RunKeyRemove(ctx context.Context, scopeID, name string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(scopeID, keyNamePrefix+name)
	if err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, r.ScopeID, r.Name); err != nil {
		return err
	}
	stderrln("✓ removed key %q from %s", name, scopeName(s, r.ScopeID))
	if err := renderSSHWithSessionIfEnabled(s); err != nil {
		stderrln("⚠ ssh render: %v", err)
	}
	return nil
}

// RunKeyMove relocates a key between scopes by removing it from the
// source and re-adding it to the destination. The fingerprint stays
// the same; downstream consumers re-discover via their next sync.
func RunKeyMove(ctx context.Context, name, fromScope, toScope string, force bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(fromScope, keyNamePrefix+name)
	if err != nil {
		return err
	}
	k, err := decodeKey(*r)
	if err != nil {
		return err
	}
	dest, err := s.resolveScopeID(toScope)
	if err != nil {
		return err
	}
	if r.ScopeID == dest {
		return fmt.Errorf("source and destination scopes are the same: %s", scopeName(s, dest))
	}
	if err := ensureNoDuplicate(s, dest, keyNamePrefix, name, force); err != nil {
		return err
	}
	if err := s.SetTypedSecret(ctx, dest, r.Name, string(k.Type), k.Marshal()); err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, r.ScopeID, r.Name); err != nil {
		return fmt.Errorf("moved key %q to %s but failed to remove from %s: %w (clean up with: fd0 key rm %s --scope %s)",
			name, scopeName(s, dest), scopeName(s, r.ScopeID), err, name, scopeName(s, r.ScopeID))
	}
	stderrln("✓ moved key %q: %s → %s", name, scopeName(s, r.ScopeID), scopeName(s, dest))
	if err := renderSSHWithSessionIfEnabled(s); err != nil {
		stderrln("⚠ ssh render: %v", err)
	}
	return nil
}

// CollectKeyEntries snapshots every available SSH key across every
// subscribed scope into the KeyEntry shape the agent socket expects.
// Used by the fd0-agent SSH-socket consumer (sshagent.KeyProvider).
func CollectKeyEntries(s *Session) (out []KeyEntry, err error) {
	rows, err := s.ListTypedSecrets("", "")
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if !strings.HasPrefix(r.Type, "ssh-") {
			continue
		}
		k, err := decodeKey(r)
		if err != nil {
			continue
		}
		out = append(out, KeyEntry{
			Key:     k,
			Comment: k.Comment,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Comment < out[j].Comment })
	return out, nil
}

// KeyEntry mirrors sshagent.KeyEntry so cli/key.go can build the slice
// without depending on the sshagent package (avoids an import cycle —
// sshagent depends on sshkey, cli/key depends on both).
type KeyEntry struct {
	Key     *sshkey.Key
	Comment string
}

// decodeKey converts a TypedRecord whose Payload is the JSON-encoded
// sshkey.JSON back into a Key.
func decodeKey(r TypedRecord) (*sshkey.Key, error) {
	raw, err := r.PayloadJSON()
	if err != nil {
		return nil, err
	}
	var j sshkey.JSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("decode key %q: %w", r.Name, err)
	}
	return sshkey.Unmarshal(j)
}

// PublicKeyAuthLine fetches one key and returns the authorized_keys
// line. Exposed for `fd0 key show --pub` and the ssh-host
// `--with-key` post-add prompt.
func PublicKeyAuthLine(ctx context.Context, scopeID, name string) (string, error) {
	s, err := Open(ctx)
	if err != nil {
		return "", err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(scopeID, keyNamePrefix+name)
	if err != nil {
		return "", err
	}
	k, err := decodeKey(*r)
	if err != nil {
		return "", err
	}
	return k.AuthorizedKeyLine(), nil
}
