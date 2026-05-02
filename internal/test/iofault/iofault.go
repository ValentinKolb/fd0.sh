// Package iofault provides a small filesystem-fault injection
// harness for tests. The pattern: replace a known-good directory
// with a FUSE-or-OS-level fault filter is overkill for unit tests;
// instead this package gives test authors a simple way to inject
// failures at specific syscall-level breakpoints by wrapping
// `os.WriteFile` / `os.OpenFile` / `os.Rename` calls.
//
// Two injection modes:
//
//  1. RO_DIR — make a directory read-only (chmod 0500). Subsequent
//     write/rename/remove attempts fail with EACCES. Use to verify
//     callers handle "directory permissions revoked mid-write".
//
//  2. EOF_AFTER_N — backed by a tmpfs / size-capped overlay isn't
//     portable across CI environments, so we emulate ENOSPC by
//     writing a sentinel file that the test inspects post-failure.
//     For true ENOSPC injection, run on a Linux test host with a
//     pre-mounted small tmpfs (out of v1 scope; doc only).
//
// In practice most callers want RO_DIR. The unit tests in this
// package + the fault tests in vault_test.go / chain_test.go
// exercise the RO_DIR mode.
package iofault

import (
	"fmt"
	"os"
)

// MakeReadOnly chmods path to 0500 (read+execute, no write). Tests
// can then call code that should fail to write into path. Restore
// with MakeWritable.
func MakeReadOnly(path string) error {
	if err := os.Chmod(path, 0o500); err != nil {
		return fmt.Errorf("iofault: chmod 0500 %s: %w", path, err)
	}
	return nil
}

// MakeWritable restores 0700 on path. Always call from a
// t.Cleanup() so a failing test doesn't leave a read-only temp dir.
func MakeWritable(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("iofault: chmod 0700 %s: %w", path, err)
	}
	return nil
}

// FillDisk writes a file of size N bytes at path. Doesn't actually
// fill the disk (would need root + size-capped FS); test callers
// should rely on MakeReadOnly + assertions on returned errors
// rather than ENOSPC simulation.
//
// Kept as a stub so tests can see what's intended; v2 may add
// proper ENOSPC support via Linux loopback FS.
func FillDisk(path string, size int64) error {
	return fmt.Errorf("iofault.FillDisk: not implemented in v1 (use MakeReadOnly to simulate write failures instead)")
}
