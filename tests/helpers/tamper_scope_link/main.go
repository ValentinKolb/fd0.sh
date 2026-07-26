package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fd0-test-tamper-scope-link <scope-chain>")
		os.Exit(2)
	}
	path := os.Args[1]
	events, err := chain.ReadScopeEvents(path)
	if err != nil {
		fatal(err)
	}
	if len(events) < 3 {
		fatal(fmt.Errorf("need at least three events, got %d", len(events)))
	}
	tamper := len(events) - 2
	events[tamper].SignedPrefix.PrevHash = bytes.Repeat([]byte{0x11}, 32)

	raws := make([][]byte, 0, len(events))
	for _, event := range events {
		raw, err := proto.Marshal(event)
		if err != nil {
			fatal(err)
		}
		raws = append(raws, raw)
	}
	if err := chain.WriteAll(path, raws); err != nil {
		fatal(err)
	}
	fmt.Printf("tampered prev_hash at seq %d\n", events[tamper].SignedPrefix.Seq)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
