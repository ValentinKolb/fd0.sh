package witness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/translog"
)

func TestSummaryForServerFiltersBeforeAggregation(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	insertSummarySTH(t, s, "https://one.example", "scope:s_one", 1)
	insertSummarySTH(t, s, "https://two.example", "scope:s_two", 1)

	got, err := s.SummaryForServer(context.Background(), "https://one.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ServerURL != "https://one.example" {
		t.Fatalf("unexpected summary rows: %+v", got)
	}
}

func TestSummaryForServerIncludesEquivocationAndConsistencyCounts(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	const serverURL = "https://one.example"
	const chainID = "scope:s_one"
	insertSummarySTH(t, s, serverURL, chainID, 1)
	fork := translog.STH{
		Head: translog.TreeHead{
			ChainID:   chainID,
			TreeSize:  1,
			RootHash:  bytes.Repeat([]byte{9}, 32),
			Timestamp: 2,
		},
		Signature: bytes.Repeat([]byte{2}, 64),
	}
	if _, err := s.Insert(context.Background(), serverURL, fork, 2, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordConsistencyFailure(
		context.Background(),
		serverURL,
		chainID,
		1,
		bytes.Repeat([]byte{1}, 32),
		2,
		bytes.Repeat([]byte{2}, 32),
		"test",
		3,
	); err != nil {
		t.Fatal(err)
	}

	got, err := s.SummaryForServer(context.Background(), serverURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].HasEquivAt || got[0].ConsistencyFailureCount != 1 {
		t.Fatalf("summary lost archive signals: %+v", got)
	}
}

func TestSummaryForServerRejectsAggregateOverflow(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := 0; i <= maxObservedSummaryRows; i++ {
		insertSummarySTH(t, s, "https://many.example", fmt.Sprintf("scope:s_%04d", i), 1)
	}
	_, err = s.SummaryForServer(context.Background(), "https://many.example")
	if !errors.Is(err, ErrSummaryLimit) {
		t.Fatalf("expected ErrSummaryLimit, got %v", err)
	}
}

func TestSummaryPageTraversesAllRows(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for i := 0; i < 300; i++ {
		insertSummarySTH(t, s, "https://many.example", fmt.Sprintf("scope:s_%04d", i), 1)
	}

	afterServer := ""
	afterChain := ""
	seen := map[string]bool{}
	for {
		rows, nextServer, nextChain, err := s.SummaryPage(
			context.Background(),
			afterServer,
			afterChain,
			64,
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if seen[row.ChainID] {
				t.Fatalf("duplicate summary row %q", row.ChainID)
			}
			seen[row.ChainID] = true
		}
		if nextServer == "" {
			break
		}
		afterServer = nextServer
		afterChain = nextChain
	}
	if len(seen) != 300 {
		t.Fatalf("got %d summary rows, want 300", len(seen))
	}
}

func TestOpenBackfillsSummaryIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	insertSummarySTH(t, s, "https://one.example", "scope:s_one", 3)
	if _, err := s.db.Exec(`DELETE FROM witness_chain_summary`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM witness_schema_state WHERE key = 'summary_version'`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	rows, err := s.SummaryForServer(context.Background(), "https://one.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].MaxTreeSize != 3 || rows[0].RowCount != 1 {
		t.Fatalf("summary index was not backfilled: %+v", rows)
	}
}

func insertSummarySTH(t *testing.T, s *Store, serverURL, chainID string, size uint64) {
	t.Helper()
	sth := translog.STH{
		Head: translog.TreeHead{
			ChainID:   chainID,
			TreeSize:  size,
			RootHash:  bytes.Repeat([]byte{byte(size)}, 32),
			Timestamp: size,
		},
		Signature: bytes.Repeat([]byte{1}, 64),
	}
	if _, err := s.Insert(context.Background(), serverURL, sth, 1, nil); err != nil {
		t.Fatal(err)
	}
}
