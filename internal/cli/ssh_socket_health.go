package cli

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
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
	paths, err := fdhome.Resolve()
	if err != nil {
		return "restart fd0-agent, then run `fd0 unlock`"
	}
	return fmt.Sprintf("restart fd0-agent with `kill \"$(cat %s)\" 2>/dev/null; fd0 unlock`; `fd0 lock && fd0 unlock` is not enough because it does not restart the agent process", paths.AgentPID)
}
