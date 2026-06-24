package cli

// Server resolution + the single-primary sync entry point.
//
// fd0 writes and reads to exactly ONE primary server per client
// (REPLICATION.md, model A1). A scope has a single ordering authority,
// so replicas can never fork — the multi-push model (push every scope to
// every server) is gone: it could leave independent logs divergent, and
// any auto-merge would discard a conflicting write, violating the prime
// directive (never lose data). Redundancy is a server-side DR backup
// (FD0_REPLICATE_FROM), not a second write target.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

// ResolveServers picks the effective server list for this invocation,
// honouring CLI/env precedence on top of the config file.
//
// Precedence (highest first):
//  1. --server flag value (when non-empty)
//  2. FD0_SERVER env var (when non-empty)
//  3. [sync].servers in config.toml
//  4. [sync].server (singular) in config.toml
//  5. fdhome.DefaultServers
//
// 1 and 2 always collapse to a single server. The single-primary
// invariant (at most one server) is enforced by RunSyncAll, not here.
func ResolveServers(flagServer string) []string {
	if flagServer != "" {
		return []string{flagServer}
	}
	if env := os.Getenv("FD0_SERVER"); env != "" {
		return []string{env}
	}
	paths, _ := fdhome.Resolve()
	cfg, _ := fdhome.LoadConfig(paths.Config)
	return cfg.Sync.ResolvedServers()
}

// RunSyncAll is the single-primary sync entry point. It enforces the A1
// invariant — exactly one configured server — then runs the sync and,
// on success, compacts the local chain (safe because that one server is
// the sole authority and now holds the tip).
//
// More than one configured server is a hard error: multi-push is removed
// because it can diverge. The message tells the operator how to get
// redundancy the safe way.
func RunSyncAll(ctx context.Context, servers []string) error {
	switch {
	case len(servers) == 0:
		return errors.New("no server configured (--server, FD0_SERVER, [sync].server, or [sync].servers)")
	case len(servers) > 1:
		return fmt.Errorf(
			"fd0 syncs to a single primary server, but %d are configured (%s).\n"+
				"List exactly one in [sync].server. For redundancy run a server-side DR\n"+
				"backup (FD0_REPLICATE_FROM) instead of a second write target — see docs/HOSTING.md.",
			len(servers), strings.Join(servers, ", "))
	}
	if err := RunSync(ctx, servers[0]); err != nil {
		return err
	}
	// One server == one authority: it now holds this tip, so dropping
	// superseded events from the local chain is safe (see CompactScopes).
	_ = CompactScopes(ctx)
	return nil
}
