package cli

// `fd0 ssh enable` and `fd0 ssh disable` — one-time setup that wires
// the user's shell and SSH config into the fd0 agent socket and
// fd0.conf render path. Both are interactive when stdin is a TTY and
// fall back to printed instructions otherwise. `fd0 ssh disable`
// reverses what enable did.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/sshhost"
)

const includeMarker = "# fd0 — managed Include line; remove this line and the next to disable"

// RunSSHEnable performs the interactive setup flow. Steps:
//  1. Render an empty fd0.conf if none exists, so the Include target
//     is valid even before the first host is added.
//  2. Offer to append the `Include` line to ~/.ssh/config.
//  3. Print the shell rc hint for SSH_AUTH_SOCK.
//
// Idempotent — re-running when already enabled prints "already set up"
// without modifying anything.
func RunSSHEnable(ctx context.Context) error {
	confPath := SSHConfPath()
	userCfg := sshhost.DefaultUserConfigPath()

	if err := ensureEmptyFD0Conf(confPath); err != nil {
		return err
	}

	already, _ := sshhost.HasInclude(userCfg, confPath)
	if already {
		fmt.Println("✓ ~/.ssh/config already includes", confPath)
	} else {
		if err := offerAddInclude(userCfg, confPath); err != nil {
			return err
		}
	}

	// Re-render now so users see the current state immediately. We
	// open a session for it; if locked, just skip with a hint.
	if s, err := Open(ctx); err == nil {
		_ = renderAndWarn(s)
		s.Close()
	} else {
		stderrln("(vault locked — `fd0 unlock` and add a host to populate %s)", confPath)
	}

	fmt.Println()
	fmt.Println("To route SSH through fd0-agent, add to your shell rc:")
	fmt.Printf("    export SSH_AUTH_SOCK=\"$(fd0 ssh sock)\"\n")
	fmt.Println()

	return nil
}

// RunSSHDisable removes everything `enable` set up. The fd0.conf
// itself is left in place by default — operator can `rm` it manually
// if they want to be thorough.
func RunSSHDisable(ctx context.Context) error {
	userCfg := sshhost.DefaultUserConfigPath()
	confPath := SSHConfPath()

	removed, err := removeIncludeLine(userCfg, confPath)
	if err != nil {
		return err
	}
	if removed {
		fmt.Printf("✓ removed Include line from %s\n", userCfg)
	} else {
		fmt.Printf("(no fd0-managed Include line in %s)\n", userCfg)
	}
	fmt.Println()
	fmt.Println("Note: fd0.conf is left at", confPath)
	fmt.Println("      Remove it manually if you want to fully detach.")
	return nil
}

// RunSSHSock prints the agent socket path. Designed for shell rc
// usage: `export SSH_AUTH_SOCK="$(fd0 ssh sock)"`.
func RunSSHSock(_ context.Context) error {
	fmt.Println(SSHSocketPathForRender())
	return nil
}

// renderSSHIfEnabled refreshes the generated ssh_config after sync, but
// only for users who already opted in by including fd0.conf from
// ~/.ssh/config. Sync should not create surprise SSH artifacts for users
// who only store SSH inventory inside fd0.
func renderSSHIfEnabled(ctx context.Context) error {
	confPath := SSHConfPath()
	enabled, err := sshhost.HasInclude(sshhost.DefaultUserConfigPath(), confPath)
	if err != nil {
		return fmt.Errorf("check ssh include: %w", err)
	}
	if !enabled {
		return nil
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return renderAndWarn(s)
}

// ensureEmptyFD0Conf creates a placeholder fd0.conf if none exists,
// so `Include ~/.ssh/fd0.conf` doesn't error when ssh parses it
// before the first render.
func ensureEmptyFD0Conf(p string) error {
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	stub := "# Managed by fd0 — populated on first `fd0 ssh add`.\n"
	return writeFileAtomic(p, []byte(stub), 0o600)
}

// offerAddInclude interactively appends the Include line to
// ~/.ssh/config. In non-TTY environments it prints the line to add
// rather than mutating the file silently.
func offerAddInclude(userCfg, confPath string) error {
	line := "Include " + confPath
	prompt := fmt.Sprintf("Add `%s` to the TOP of %s? [Y/n]: ", line, userCfg)

	if !isInteractive() {
		fmt.Println("Non-interactive — add this to the TOP of", userCfg+":")
		fmt.Println("    " + includeMarker)
		fmt.Println("    " + line)
		return nil
	}
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	resp, _ := r.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp == "n" || resp == "no" {
		fmt.Println("Skipped. Add manually when ready:")
		fmt.Println("    " + line)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(userCfg), 0o700); err != nil {
		return err
	}
	prev, err := os.ReadFile(userCfg)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	body := includeMarker + "\n" + line + "\n\n" + string(prev)
	if err := writeFileAtomic(userCfg, []byte(body), 0o600); err != nil {
		return err
	}
	fmt.Println("✓ added to", userCfg)
	return nil
}

// removeIncludeLine strips the marker + Include line we added on
// enable. Returns (true, nil) if anything was removed.
func removeIncludeLine(userCfg, confPath string) (bool, error) {
	data, err := os.ReadFile(userCfg)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	lines := strings.Split(string(data), "\n")
	target := "Include " + confPath
	out := make([]string, 0, len(lines))
	removed := false
	skipNext := false
	for _, ln := range lines {
		if skipNext {
			// Skip the Include line right after the marker.
			if strings.TrimSpace(ln) == target {
				skipNext = false
				continue
			}
			// Marker not followed by our Include — keep both.
			out = append(out, includeMarker)
			skipNext = false
		}
		if strings.TrimSpace(ln) == includeMarker {
			skipNext = true
			removed = true
			continue
		}
		out = append(out, ln)
	}
	if !removed {
		return false, nil
	}
	return true, writeFileAtomic(userCfg, []byte(strings.Join(out, "\n")), 0o600)
}

// isInteractive reports whether stdin is a TTY. Mirrors IsTTY in
// translog.go but keeps this file self-contained.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
