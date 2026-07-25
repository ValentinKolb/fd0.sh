package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// typed_inventory.go holds cross-domain helpers used by every typed-
// secret feature (keys, hosts, talos, kube):
//
//   - ensureNoDuplicate  — duplicate-name preflight using a typed
//                          sentinel (errors.Is on
//                          ErrTypedSecretNotFound), not a string
//                          heuristic. Refuses unresolved scopes so
//                          callers can't accidentally skip the check.
//   - safeReadConfigFile — bounded, kind-checked --from-config read
//                          with strict post-read enforcement of the
//                          size cap.
//   - writeManagedFile   — the shared "ensure dir 0700 + atomic write
//                          + log" path for fd0-rendered config files.

// errDuplicateSecret is the sentinel the duplicate-preflight returns
// when a name is already in use. Surfaced via errors.Is for callers
// that want to ask "should I retry with --force?".
var errDuplicateSecret = errors.New("typed inventory: name already in use")

// ensureNoDuplicate returns nil if `<prefix><name>` doesn't exist in
// `scopeID`, an errDuplicateSecret-wrapped error if it does, and any
// other lookup error verbatim. Callers pass `force=true` to skip the
// check — used by `--force` CLI flags.
//
// scopeID MUST be a resolved scope id (e.g. via s.resolveScopeID()).
// An empty scopeID is rejected with an explicit programmer error
// rather than silently falling through to "all scopes" — that
// fallthrough was the source of a silent-overwrite regression in the
// original implementation.
func ensureNoDuplicate(s *Session, scopeID, prefix, name string, force bool) error {
	if scopeID == "" {
		if force {
			// Nothing to look up, and the caller has already said "replace".
			// Preserves the pre-existing contract that --force never depends
			// on a resolved scope.
			return nil
		}
		return errors.New("ensureNoDuplicate: internal: empty scopeID — caller must resolve first")
	}
	r, err := s.GetTypedSecret(scopeID, prefix+name)
	if err != nil {
		// Distinguish "doesn't exist" (success path) from real
		// lookup errors. Typed sentinel keeps this brittle-free.
		if errors.Is(err, ErrTypedSecretNotFound) {
			return nil
		}
		if force {
			// A lookup failure must not block an explicit overwrite; the
			// write itself will surface any real problem.
			return nil
		}
		return err
	}
	if r == nil {
		return nil
	}
	if force {
		// --force replaces the record outright: every field the command did
		// not set goes back to its zero value. That is almost never what
		// someone reaching for it wants, so say so rather than doing it
		// quietly.
		stderrln("⚠ replacing existing %s%s — fields you did not pass are reset%s",
			prefix, name, forceWarning(prefix, name))
		return nil
	}
	return fmt.Errorf("%w: %s%s in scope %s%s\n  to replace it outright:      add --force",
		errDuplicateSecret, prefix, name, scopeName(s, r.ScopeID), editHint(prefix, name))
}

// editHint names the command that changes one field without touching the rest.
// Derived from the kind table so it cannot drift from the real prefixes.
func editHint(prefix, name string) string {
	for _, kind := range itemKinds {
		if kind.Prefix != "" && kind.Prefix == prefix {
			return fmt.Sprintf("\n  to change individual fields: fd0 %s edit %s", kind.Command, name)
		}
	}
	return ""
}

// forceWarning is the same hint phrased for an overwrite that is already
// happening.
func forceWarning(prefix, name string) string {
	for _, kind := range itemKinds {
		if kind.Prefix != "" && kind.Prefix == prefix {
			return fmt.Sprintf(" — use `fd0 %s edit %s` to change one field instead", kind.Command, name)
		}
	}
	return ""
}

// MaxConfigFile is the byte cap shared by every `--from-config`
// ingestion path. Plenty for hand-written ssh_config-grade files
// without inviting denial-of-service.
const MaxConfigFile = 1 << 20 // 1 MiB

// safeReadConfigFile is the bounded, kind-checked read used by every
// `--from-config` ingestion path. The previous os.ReadFile path
// followed symlinks and had no size cap, so a planted symlink or a
// 500 MB file was consumed under the vault flock before the parse
// step could surface the error.
//
// Properties:
//   - Lstat (no symlink follow) — refuses symlinks at the leaf so
//     callers can't be tricked via a planted link. Parent-path
//     symlinks remain trusted (fd0's threat model treats the
//     operator's own filesystem as trusted).
//   - Regular files only — directories, devices, pipes refuse.
//   - Bounded read — Stat caps at maxSize, plus an io.LimitReader of
//     maxSize+1 followed by a strict length check so a file that grew
//     between Lstat and Open is still refused.
//   - Empty-file detection so callers can return a clear error
//     instead of "no contexts found in file".
func safeReadConfigFile(path string, maxSize int64) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	mode := fi.Mode()
	if mode&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink — pass the resolved path explicitly (try `readlink -f`)", path)
	}
	if !mode.IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (mode %s)", path, mode)
	}
	if fi.Size() == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	if fi.Size() > maxSize {
		return nil, fmt.Errorf("%s is %d bytes; limit is %d", path, fi.Size(), maxSize)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Strict enforcement: io.LimitReader at maxSize+1 means a file
	// that grew between Lstat and Open returns one more byte than
	// allowed. Refuse explicitly — the +1 belt only matters if we
	// check it.
	if int64(len(b)) > maxSize {
		return nil, fmt.Errorf("%s grew past %d bytes during read", path, maxSize)
	}
	return b, nil
}

// writeManagedFile is the shared "make parent dir + atomic write +
// log" path for every render target (~/.ssh/fd0.conf,
// ~/.talos/config.fd0, ~/.kube/config.fd0). Three callers had the
// same lines drift-copied; collapsing them keeps the file-mode
// (0600) and dir-mode (0700) policy in one place.
//
// If the parent directory already exists with looser permissions
// (e.g. a stock ~/.talos created by talosctl at 0755), we tighten
// it to 0700 explicitly — MkdirAll alone is a no-op on existing
// dirs and the comment "0700 story in one place" would otherwise
// be a lie.
func writeManagedFile(target string, data []byte, label string, count int) error {
	parent := parentDir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	// Tighten an existing parent that the user (or another tool)
	// might have left at 0755. We only do this for directories WE
	// own (caller home).
	if fi, err := os.Stat(parent); err == nil && fi.IsDir() {
		if mode := fi.Mode().Perm(); mode != 0o700 {
			_ = os.Chmod(parent, 0o700)
		}
	}
	if err := writeFileAtomic(target, data, 0o600); err != nil {
		return err
	}
	stderrln("✓ rendered %s (%d %s)", target, count, label)
	return nil
}

// parentDir is defined in ssh.go; re-asserting here so importers can
// follow the call graph. Kept as a local for now — promoting to a
// public helper isn't worth the churn.
var _ = filepath.Dir // keep `path/filepath` imported even if every
// caller uses parentDir from ssh.go.
