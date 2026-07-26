// Command fd0-test-compact-scope-chain reproduces the output of the retired
// v1 scope compactor: genesis kept verbatim, the last N events kept verbatim,
// everything between deleted.
//
// It exists so the integration suite can create the exact on-disk state a
// pre-migration client left behind, without shipping the compactor itself
// (chain.CompactScope is disabled precisely because it produces this).
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: fd0-test-compact-scope-chain <scope-chain> <keep-tail>")
		os.Exit(2)
	}
	path := os.Args[1]
	keep, err := strconv.Atoi(os.Args[2])
	if err != nil || keep < 1 {
		fatal(fmt.Errorf("keep-tail must be a positive integer, got %q", os.Args[2]))
	}
	events, err := chain.ReadScopeEvents(path)
	if err != nil {
		fatal(err)
	}
	// Need at least one event strictly between genesis and the retained
	// window, otherwise the rewrite would be a no-op rather than a gap.
	if len(events) < keep+2 {
		fatal(fmt.Errorf("need at least %d events to leave a gap, got %d", keep+2, len(events)))
	}
	kept := make([][]byte, 0, keep+1)
	indices := append([]int{0}, tailIndices(len(events), keep)...)
	for _, index := range indices {
		raw, err := proto.Marshal(events[index])
		if err != nil {
			fatal(err)
		}
		kept = append(kept, raw)
	}
	if err := chain.WriteAll(path, kept); err != nil {
		fatal(err)
	}
	cls, err := chain.ClassifyScopeChain(path)
	if err != nil {
		fatal(err)
	}
	if cls.Shape != chain.ScopeShapeLegacyCompacted {
		fatal(fmt.Errorf("rewritten chain classified as %q (%s), want legacy-compacted", cls.Shape, cls.Reason))
	}
	fmt.Printf("compacted to genesis + seq %d..%d (dropped seq 1..%d)\n",
		cls.RetainedFrom, cls.Tip.Seq, cls.RetainedFrom-1)
}

func tailIndices(total, keep int) []int {
	out := make([]int, 0, keep)
	for i := total - keep; i < total; i++ {
		out = append(out, i)
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
