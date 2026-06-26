package cli

import (
	"fmt"
	"net"
	"os"
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
	return fmt.Errorf("fd0 SSH agent socket unavailable at %s: %w (%s)", path, err, restartAgentHint())
}

func sshAgentSocketDisabledByEnv() bool {
	v, ok := os.LookupEnv("FD0_SSH_SOCK")
	return ok && v == ""
}

func restartAgentHint() string {
	return "run `fd0 agent restart`"
}
