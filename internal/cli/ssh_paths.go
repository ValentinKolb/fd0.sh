package cli

// Shared paths + clock for the SSH integration. Centralised so tests
// can override and so the `enable / disable / render / agent` paths
// don't drift in their assumptions about where things live.

import (
	"os"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/sshagent"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
)

// nowFunc is the clock used by the renderer; tests can swap it for a
// deterministic value.
var nowFunc = time.Now

// SSHConfPath returns the on-disk path fd0 renders into. Honours
// FD0_SSH_CONFIG_PATH for tests + power users; falls back to the
// conventional ~/.ssh/fd0.conf.
func SSHConfPath() string {
	if p := os.Getenv("FD0_SSH_CONFIG_PATH"); p != "" {
		return p
	}
	return sshhost.DefaultFD0ConfPath()
}

// SSHSocketPathForRender returns the SSH-agent socket path that gets
// embedded into each Host's IdentityAgent directive in fd0.conf.
// Honours FD0_SSH_SOCK for tests / non-default deployments.
func SSHSocketPathForRender() string {
	if p := os.Getenv("FD0_SSH_SOCK"); p != "" {
		return p
	}
	return sshagent.DefaultSocketPath()
}
