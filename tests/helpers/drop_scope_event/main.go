package main

import (
	"fmt"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fd0-test-drop-scope-event <scope-chain>")
		os.Exit(2)
	}
	path := os.Args[1]
	events, err := chain.ReadScopeEvents(path)
	if err != nil {
		fatal(err)
	}
	if len(events) < 4 {
		fatal(fmt.Errorf("need at least four events, got %d", len(events)))
	}
	drop := len(events) - 2
	if events[drop].SignedPrefix.Kind != proto.KindSecretSet {
		fatal(fmt.Errorf("penultimate event is %q, want %q", events[drop].SignedPrefix.Kind, proto.KindSecretSet))
	}
	kept := make([][]byte, 0, len(events)-1)
	for index, event := range events {
		if index == drop {
			continue
		}
		raw, err := proto.Marshal(event)
		if err != nil {
			fatal(err)
		}
		kept = append(kept, raw)
	}
	if err := chain.WriteAll(path, kept); err != nil {
		fatal(err)
	}
	fmt.Printf("dropped seq %d\n", events[drop].SignedPrefix.Seq)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
