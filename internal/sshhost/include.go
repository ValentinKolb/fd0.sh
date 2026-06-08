package sshhost

import (
	"bufio"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// HasInclude reports whether the SSH config at sshConfigPath contains
// an `Include` directive pointing at includedPath. The check is
// tolerant: leading whitespace is ignored, case is ignored on the
// directive name, and we expand `~` to the user's home both in the
// scanned file's path and in includedPath. Comment lines (starting
// with #) are skipped.
//
// Returns (false, nil) if the file simply doesn't exist; the caller
// can treat that the same as "no include line yet" and surface the
// usual warning. Returns (false, err) only on permission / IO errors
// that the operator should see.
func HasInclude(sshConfigPath, includedPath string) (bool, error) {
	want, err := expandHome(includedPath)
	if err != nil {
		return false, err
	}
	cfgPath, err := expandHome(sshConfigPath)
	if err != nil {
		return false, err
	}
	f, err := os.Open(cfgPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// First token must be Include (case-insensitive).
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !strings.EqualFold(fields[0], "Include") {
			continue
		}
		// Multiple paths per Include are allowed; any token matching
		// our target satisfies.
		for _, raw := range fields[1:] {
			path, err := expandHome(strings.Trim(raw, "\"'"))
			if err != nil {
				continue
			}
			if path == want {
				return true, nil
			}
		}
	}
	return false, sc.Err()
}

// expandHome turns a leading `~/` or `~` into the user's home dir.
// Anything else passes through. We use os.UserHomeDir rather than
// $HOME so the behaviour matches OpenSSH's own expansion (which also
// consults /etc/passwd on Unix).
func expandHome(p string) (string, error) {
	if p == "" {
		return p, nil
	}
	if p == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return p, err
		}
		return home, nil
	}
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return p, err
		}
		return filepath.Join(home, p[2:]), nil
	}
	return p, nil
}

// DefaultUserConfigPath returns the conventional SSH config path,
// typically ~/.ssh/config. Pulled out so tests can override.
func DefaultUserConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/.ssh/config"
	}
	return filepath.Join(home, ".ssh", "config")
}

// DefaultFD0ConfPath returns the path fd0 renders into,
// typically ~/.ssh/fd0.conf. Operators can override via config.
func DefaultFD0ConfPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/.ssh/fd0.conf"
	}
	return filepath.Join(home, ".ssh", "fd0.conf")
}
