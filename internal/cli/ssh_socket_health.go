package cli

import (
	"fmt"
	"net"
	"time"
)

func checkSSHAgentSocket(path string) error {
	if path == "" {
		return fmt.Errorf("empty socket path")
	}
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func sshAgentSocketUnavailable(path string, err error) error {
	return fmt.Errorf("fd0 SSH agent socket unavailable at %s: %w (restart it with `fd0 lock` then `fd0 unlock`; if that does not help, stop fd0-agent and unlock again)", path, err)
}
