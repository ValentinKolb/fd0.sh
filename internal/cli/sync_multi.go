package cli

// Multi-server dispatch wraps the existing single-server RunSync so the
// CLI and the agent can sync against every configured server in one
// invocation. The per-server inner loop is the v1 RunSync verbatim —
// idempotent push (events are content-addressed, server-side dedups),
// per-URL TOFU pin, per-URL witness cross-check.
//
// Semantics:
//
//   - Iterate servers in config order. Each iteration calls RunSync
//     with that server's URL.
//   - Success is recorded per server. The overall call returns nil if
//     AT LEAST ONE server succeeded (some replication beats none); the
//     stderr summary lists which ones failed so the operator sees the
//     degradation. If EVERY server failed, the call returns an error
//     that names every server and its cause.
//   - This is the v0.0.4 transitional shape. Once the server-side
//     gossip work (PROTOCOL.md §11, "Peer Replication") lands, a single
//     push will be enough — but until then, multi-push is what gives
//     replicas the same event set.
//
// Why not parallelise the servers? Vault re-seal happens during
// RunSync (push-floor advance, scope tip update). Two concurrent
// RunSync calls would race on the vault lock — sequential is the only
// correct shape today. With 2 servers the wall-clock impact is a few
// seconds, well within tolerance for a manual `fd0 sync` and below the
// agent's idle-sync cadence.

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
//  4. [sync].server (singular, legacy) in config.toml
//  5. fdhome.DefaultServers
//
// 1 and 2 collapse the call to a single server intentionally — they
// are the "operator override" path (CI scripts targeting one specific
// server, ad-hoc testing). Multi-server is config-only.
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

// RunSyncAll runs RunSync against every entry in servers and returns
// nil iff at least one succeeded. The summary is printed to stderr so
// the operator sees per-server outcomes even when the aggregate is OK.
//
// Empty server list is treated as a configuration error — the
// CLI/agent layer is responsible for ensuring at least the defaults
// are present before calling here.
func RunSyncAll(ctx context.Context, servers []string) error {
	if len(servers) == 0 {
		return errors.New("no server configured (--server, FD0_SERVER, [sync].servers, or [sync].server)")
	}
	if len(servers) == 1 {
		// Single-server path: skip the per-server header so the output
		// is unchanged from the v0.0.3 single-target shape.
		return RunSync(ctx, servers[0])
	}
	type result struct {
		server string
		err    error
	}
	results := make([]result, 0, len(servers))
	successes := 0
	for i, srv := range servers {
		fmt.Fprintf(os.Stderr, "→ sync %d/%d: %s\n", i+1, len(servers), srv)
		err := RunSync(ctx, srv)
		results = append(results, result{server: srv, err: err})
		if err == nil {
			successes++
		} else {
			fmt.Fprintf(os.Stderr, "  ✗ %s\n", err)
		}
	}
	if successes == 0 {
		// Aggregate every cause into one error so the operator sees
		// which servers misbehaved without scrolling stderr.
		parts := make([]string, 0, len(results))
		for _, r := range results {
			parts = append(parts, fmt.Sprintf("%s: %v", r.server, r.err))
		}
		return fmt.Errorf("sync: all %d servers failed:\n  %s",
			len(servers), strings.Join(parts, "\n  "))
	}
	if successes < len(servers) {
		fmt.Fprintf(os.Stderr, "✓ sync ok on %d/%d servers (replicas may be out of date until next sync)\n",
			successes, len(servers))
	}
	return nil
}
