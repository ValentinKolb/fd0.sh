package agent

// SSH-agent socket integration. fd0-agent serves the standard
// ssh-agent protocol on a second Unix socket (XDG_RUNTIME_DIR by
// default; see internal/sshagent.DefaultSocketPath) so any ssh
// client (ssh, scp, git, ...) can transparently use keys held in the
// fd0 vault.
//
// Trust model:
//   - Vault must be unlocked to enumerate or sign; locked vault
//     returns the empty identity list (industry-standard "no
//     identities" — ssh client tries the next method).
//   - No per-sign approval prompt. Vault unlock is the consent.
//   - Sign + List only (Bitwarden minimalism); add/remove/lock at
//     the protocol level are explicitly refused.
//
// Concurrency:
//   - The fd0-agent main IPC and the SSH agent socket run on
//     separate goroutines. Every list/sign operation re-fetches the
//     current key set so lock and expiry revoke already-open SSH
//     connections immediately.

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/valentinkolb/fd0.sh/internal/sshagent"
	"golang.org/x/crypto/ssh/agent"
)

// SSHKeyFetcher is what the agent uses to enumerate available SSH
// keys. The concrete implementation lives in cmd/fd0-agent so it can
// import cli.CollectKeyEntries without the agent package taking a cli
// dependency (which would be a cycle).
type SSHKeyFetcher func() ([]sshagent.KeyEntry, error)

// liveSSHProvider re-fetches keys for every SSH-agent operation. A provider
// captured at connection time would retain private signing material after the
// vault is locked.
type liveSSHProvider struct {
	log     *slog.Logger
	fetcher SSHKeyFetcher
}

func (p *liveSSHProvider) Keys() ([]sshagent.KeyEntry, error) {
	keys, err := p.fetcher()
	if err != nil {
		p.log.Debug("ssh-agent: fetch failed, serving empty", "err", err)
		return nil, err
	}
	return keys, nil
}

// StartSSHSocket launches the SSH-agent socket listener. The fetcher
// is called for every list/sign operation and MUST be safe to call
// concurrently. Returns a stop function the caller invokes at shutdown.
func StartSSHSocket(ctx context.Context, log *slog.Logger, socketPath string, fetcher SSHKeyFetcher) (func(), error) {
	l, err := sshagent.Listen(socketPath)
	if err != nil {
		return nil, err
	}
	log.Info("ssh-agent socket listening", "sock", socketPath)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Warn("ssh-agent accept", "err", err)
				continue
			}
			go handleSSHConn(log, conn, fetcher)
		}
	}()
	stop := func() {
		_ = l.Close()
		wg.Wait()
	}
	return stop, nil
}

// handleSSHConn serves the connection against live vault state. On a locked
// vault the fetcher returns an empty list (or an error which the protocol
// adapter treats as empty for List), so stale connections lose signing
// authority without requiring the client to reconnect.
func handleSSHConn(log *slog.Logger, conn net.Conn, fetcher SSHKeyFetcher) {
	defer conn.Close()
	a := sshagent.New(&liveSSHProvider{log: log, fetcher: fetcher})
	if err := agent.ServeAgent(a, conn); err != nil {
		// Common: connection closed by client (ssh.EOF). Logged at
		// debug because every successful auth tears the connection.
		log.Debug("ssh-agent: serve finished", "err", err)
	}
}
