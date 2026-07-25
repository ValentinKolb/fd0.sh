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
	hintSyncForPeers()

	return nil
}

// keyListRow is the machine-readable shape of one key.
//
// Public material only, by construction: the row has no field the private half
// could be assigned to, so a listing cannot become an exfiltration path even if
// sshkey.JSON grows. The private key leaves the vault through `fd0 get` and the
// SSH agent, nowhere else.
type keyListRow struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	Comment     string `json:"comment,omitempty"`
	Scope       string `json:"scope,omitempty"`
	ScopeID     string `json:"scopeId"`
}

// RunKeyList prints every fd0-managed SSH key. Filters by scope and
// optionally a list of tags (AND semantics across multiple --tag).
func RunKeyList(ctx context.Context, scopeID string, _ []string, _ []string, jsonOut bool) error {
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
	if jsonOut {
		rows := make([]keyListRow, 0, len(keys))
		for _, r := range keys {
			k, err := decodeKey(r)
			if err != nil {
				stderrln("  ! malformed key %q in scope %s: %v", r.Name, scopeName(s, r.ScopeID), err)
				continue
			}
			rows = append(rows, keyListRow{
				Name:        strings.TrimPrefix(r.Name, keyNamePrefix),
				Type:        string(k.Type),
				Fingerprint: k.Fingerprint(),
				PublicKey:   k.AuthorizedKeyLine(),
				Comment:     k.Comment,
				Scope:       scopeLabelOf(s, r.ScopeID),
				ScopeID:     r.ScopeID,
			})
		}
		return json.NewEncoder(os.Stdout).Encode(rows)
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
func RunKeyRemove(ctx context.Context, scopeID, name string, yes bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	r, err := s.GetTypedSecret(scopeID, keyNamePrefix+name)
	if err != nil {
		return err
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove key %q from %s?", name, scopeName(s, r.ScopeID))); err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, r.ScopeID, r.Name); err != nil {
		return err
	}
	stderrln("✓ removed key %q from %s", name, scopeName(s, r.ScopeID))
	if err := renderSSHWithSessionIfEnabled(s); err != nil {
		stderrln("⚠ ssh render: %v", err)
	}
	hintSyncForPeers()
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
	return s.MoveItem(ctx, KindKey, name, fromScope, toScope, force)
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

// KeyEditOpts patches an existing key. Only metadata is listed here: the
// private material, its algorithm and the fingerprint derived from it are what
// makes a key *that* key, so changing them would silently swap a different
// credential under the same name rather than edit this one.
type KeyEditOpts struct {
	Name    string
	Scope   string
	Comment *string
}

// RunKeyEdit changes only the fields the user named, leaving the rest alone.
func RunKeyEdit(ctx context.Context, o KeyEditOpts) error {
	if o.Name == "" {
		return errors.New("key edit: NAME required")
	}
	return EditItem(ctx, KindKey, o.Scope, o.Name,
		decodeKey,
		func(k *sshkey.Key) (bool, error) {
			changed := false
			setString(&k.Comment, o.Comment, &changed)
			return changed, nil
		},
		func(k *sshkey.Key) error {
			// The comment is printed verbatim as the tail of an
			// authorized_keys line; a newline in it would forge a second
			// entry in whatever file the user pastes the line into.
			if strings.ContainsAny(k.Comment, "\n\r") {
				return errors.New("key edit: comment cannot contain newlines")
			}
			return nil
		},
		func(k *sshkey.Key) (string, any) { return string(k.Type), k.Marshal() },
	)
}

// RunKeyRename renames a key. Unlike a host, a key has no name inside its own
// payload — the record name is the only name it has — so there is nothing to
// retitle. Hosts referencing the old name keep pointing at it and the renderer
// starts warning about the missing key until they are repointed.
func RunKeyRename(ctx context.Context, scopeID, oldName, newName string, force bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.RenameItem(ctx, KindKey, scopeID, oldName, newName, force, nil)
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
