package cli

// Shared paths + clock for the SSH integration. Centralised so tests
// can override and so the `enable / disable / render / agent` paths
// don't drift in their assumptions about where things live.

import (
	"os"
	"path/filepath"
	"strings"
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

// SSHPubKeyDir returns the directory holding the per-host public-key
// selector files (<alias>.pub). Derived from SSHConfPath so that
// FD0_SSH_CONFIG_PATH automatically isolates the .pub files alongside
// the rendered config — the whole tree is one fd0-managed location.
// Default: ~/.ssh/fd0.d/ (sibling of ~/.ssh/fd0.conf).
func SSHPubKeyDir() string {
	conf := SSHConfPath()
	base := filepath.Base(conf)
	name := strings.TrimSuffix(base, filepath.Ext(base)) // fd0.conf -> fd0
	return filepath.Join(filepath.Dir(conf), name+".d")
}

// SSHConnectConfigPath is the composite OpenSSH config used by
// `fd0 ssh <alias>` when the user's ~/.ssh/config has not opted into
// fd0 with `fd0 ssh enable`. It is fully regenerable.
func SSHConnectConfigPath() string {
	conf := SSHConfPath()
	base := filepath.Base(conf)
	name := strings.TrimSuffix(base, filepath.Ext(base)) // fd0.conf -> fd0
	return filepath.Join(filepath.Dir(conf), name+".connect.conf")
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
