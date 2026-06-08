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
//     separate goroutines and contend for the vault flock when they
//     need to read state. We snapshot the key set at SSH connect
//     time and release the flock immediately afterward — the
//     in-process Signer objects don't need the flock to sign.

import (
	"context"
	"log/slog"
	"net"
	"sync"

	"github.com/valentinkolb/fd0.sh/internal/sshagent"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"golang.org/x/crypto/ssh/agent"
)

// SSHKeyFetcher is what the agent uses to enumerate available SSH
// keys. The concrete implementation lives in cmd/fd0-agent so it can
// import cli.CollectKeyEntries without the agent package taking a cli
// dependency (which would be a cycle).
type SSHKeyFetcher func() ([]sshagent.KeyEntry, error)

// SnapshotProvider is a sshagent.KeyProvider whose key set is fixed
// at construction time. We use it to give each SSH agent connection
// a static identity list captured at connect — the SSH client gets a
// consistent view for the lifetime of its connection and we don't
// hold the vault lock while signing.
type SnapshotProvider struct {
	keys []sshagent.KeyEntry
}

// Keys returns the snapshot.
func (p *SnapshotProvider) Keys() ([]sshagent.KeyEntry, error) { return p.keys, nil }

// StartSSHSocket launches the SSH-agent socket listener. The fetcher
// is called once per accepted connection — it MUST be safe to call
// concurrently (we serialise inside it if necessary via the vault
// flock). Returns a stop function the caller invokes at shutdown.
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

// handleSSHConn snapshots the current key set and serves the
// connection against that snapshot. On a locked vault the fetcher
// returns an empty list (or an error which we treat the same) — the
// client sees "no identities".
func handleSSHConn(log *slog.Logger, conn net.Conn, fetcher SSHKeyFetcher) {
	defer conn.Close()
	keys, err := fetcher()
	if err != nil {
		// Empty list rather than agent-protocol error: a wire error
		// causes ssh clients to abort the session noisily; an empty
		// list degrades gracefully ("no identities, try next method").
		log.Debug("ssh-agent: fetch failed, serving empty", "err", err)
		keys = nil
	}
	snap := &SnapshotProvider{keys: keys}
	a := sshagent.New(snap)
	if err := agent.ServeAgent(a, conn); err != nil {
		// Common: connection closed by client (ssh.EOF). Logged at
		// debug because every successful auth tears the connection.
		log.Debug("ssh-agent: serve finished", "err", err)
	}
}

// noKeysFetcher is the default fetcher used until the operator wires
// the real one from cmd/fd0-agent. It always returns an empty list.
// Kept as a separate function so the test for StartSSHSocket can use
// it without importing the real fetcher.
func noKeysFetcher() ([]sshagent.KeyEntry, error) { return nil, nil }

// (unused) helper to silence importable-but-unused warnings on
// platforms where the test build doesn't reach sshkey.
var _ = sshkey.TypeEd25519
