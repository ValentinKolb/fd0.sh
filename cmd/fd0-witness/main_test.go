package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestPromObserverDoesNotCreatePerChainSeries(t *testing.T) {
	reg := prometheus.NewRegistry()
	o := newPromObserver(reg)
	for i := 0; i < 5000; i++ {
		chain := "scope:s_" + string(rune(i))
		o.OnPoll("https://server.example", chain, "ok")
		o.OnTreeSize("https://server.example", chain, uint64(i))
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		switch family.GetName() {
		case "fd0_witness_polls_total", "fd0_witness_tree_size":
			if len(family.Metric) != 1 {
				t.Fatalf("%s has %d series, want 1", family.GetName(), len(family.Metric))
			}
		}
	}
}
