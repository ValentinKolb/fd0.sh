package store

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func TestScopesForMemberPageTraversesAllRows(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fd0.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	member := bytes.Repeat([]byte{7}, 32)
	for i := 0; i < 300; i++ {
		chainID := fmt.Sprintf("scope:s_%04d", i)
		if _, err := s.db.Exec(
			`INSERT INTO chains (chain_id, tip_seq, tip_hash) VALUES (?, 0, ?)`,
			chainID,
			bytes.Repeat([]byte{byte(i)}, 32),
		); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(
			`INSERT INTO scope_members (chain_id, member_pub) VALUES (?, ?)`,
			chainID,
			member,
		); err != nil {
			t.Fatal(err)
		}
	}

	after := ""
	seen := map[string]bool{}
	for {
		rows, nextAfter, err := s.ScopesForMemberPage(context.Background(), member, after, 64)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if seen[row.ID] {
				t.Fatalf("duplicate scope %q", row.ID)
			}
			seen[row.ID] = true
		}
		if nextAfter == "" {
			break
		}
		after = nextAfter
	}
	if len(seen) != 300 {
		t.Fatalf("got %d scopes, want 300", len(seen))
	}
}

func TestListChainIDsPageTraversesAllRows(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fd0.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := 0; i < 1100; i++ {
		if _, err := s.db.Exec(
			`INSERT INTO chains (chain_id, tip_seq, tip_hash) VALUES (?, 0, ?)`,
			fmt.Sprintf("scope:s_%04d", i),
			bytes.Repeat([]byte{byte(i)}, 32),
		); err != nil {
			t.Fatal(err)
		}
	}

	after := ""
	seen := map[string]bool{}
	for {
		ids, nextAfter, err := s.ListChainIDsPage(context.Background(), after, 128)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			if seen[id] {
				t.Fatalf("duplicate chain %q", id)
			}
			seen[id] = true
		}
		if nextAfter == "" {
			break
		}
		after = nextAfter
	}
	if len(seen) != 1100 {
		t.Fatalf("got %d chains, want 1100", len(seen))
	}
}

func TestEventsSinceInclusiveBudgetStopsBeforeOverflow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fd0.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	sizes := []int{4, 5, 6}
	var previousTip []byte
	for seq, size := range sizes {
		newTip := bytes.Repeat([]byte{byte(seq + 1)}, 32)
		if err := s.Append(ctx, AppendOpts{
			ChainID:    "scope:s_budget",
			Kind:       KindScope,
			Genesis:    seq == 0,
			Seq:        uint64(seq),
			NewTipHash: newTip,
			Event: Event{
				EventID:  fmt.Sprintf("event-%d", seq),
				Kind:     "secret.set",
				PrevHash: previousTip,
				CBOR:     bytes.Repeat([]byte{byte(seq + 1)}, size),
			},
		}); err != nil {
			t.Fatal(err)
		}
		previousTip = newTip
	}

	events, used, next, err := s.EventsSinceInclusiveBudget(
		ctx,
		"scope:s_budget",
		0,
		10,
		true,
		9,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || used != 9 || next != 6 {
		t.Fatalf("events=%d used=%d next=%d, want 2/9/6", len(events), used, next)
	}
}
