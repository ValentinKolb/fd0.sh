package cli

// Server resolution + the single-primary sync entry point.
//
// fd0 writes and reads to exactly ONE primary server per client
// (REPLICATION.md, model A1). A scope has a single ordering authority, so
// replicas can never fork — the multi-push model (and the [sync].servers
// array) is gone: it could leave independent logs divergent, and any
// auto-merge would discard a conflicting write, violating the prime
// directive (never lose data). Redundancy is a server-side DR backup
// (FD0_REPLICATE_FROM), not a second write target.

import (
	"context"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

// ResolvePrimary returns the single primary server URL, honouring
// precedence (highest first):
//
//  1. --server flag value (when non-empty)
//  2. FD0_SERVER env var (when non-empty)
//  3. [sync].server in config.toml
//  4. fdhome.DefaultServer
//
// A pre-A1 [sync].servers array is a hard error (config.ResolvedServer)
// with migration guidance — never a silent fallback.
func ResolvePrimary(flagServer string) (string, error) {
	if flagServer != "" {
		return flagServer, nil
	}
	if env := os.Getenv("FD0_SERVER"); env != "" {
		return env, nil
	}
	paths, _ := fdhome.Resolve()
	cfg, _ := fdhome.LoadConfig(paths.Config)
	return cfg.Sync.ResolvedServer()
}

// RunSyncPrimary is the single-primary sync entry point: resolve the one
// primary, run a sync against it, and — on success — compact the local
// chain (safe because that one server is the sole authority and now holds
// the tip).
func RunSyncPrimary(ctx context.Context, flagServer string) error {
	server, err := ResolvePrimary(flagServer)
	if err != nil {
		return err
	}
	if err := RunSync(ctx, server); err != nil {
		return err
	}
	_ = CompactScopes(ctx)
	return nil
}
