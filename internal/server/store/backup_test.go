package store

import (
	"bytes"
	"context"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/translog"
)

func openBackupTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/b.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestBackupAppendEventsRejectsSameSeqDifferentBytes is the sensitivity
// test for the DR backup conflict guard (review blind spot): re-storing
// an IDENTICAL event is idempotent, but a DIFFERENT event at the same
// (source, chain, seq) — a fork or corruption from the source — must be a
// hard error, never silently swallowed. (Mutation reviewer found the old
// INSERT OR IGNORE swallowed this with no failing test.)
func TestBackupAppendEventsRejectsSameSeqDifferentBytes(t *testing.T) {
	s := openBackupTestStore(t)
	ctx := context.Background()
	src := bytes.Repeat([]byte{0xab}, 32)
	e := Event{ChainID: "scope:s_x", Seq: 0, EventID: "ev1", Kind: "secret.set", CBOR: []byte("one"), StoredAt: 1}

	if err := s.BackupAppendEvents(ctx, src, []Event{e}); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// Identical re-store is idempotent.
	if err := s.BackupAppendEvents(ctx, src, []Event{e}); err != nil {
		t.Fatalf("idempotent re-store should not error: %v", err)
	}
	// Same slot, different bytes -> hard error, and nothing is overwritten.
	conflict := e
	conflict.EventID = "ev2"
	conflict.CBOR = []byte("two")
	if err := s.BackupAppendEvents(ctx, src, []Event{conflict}); err == nil {
		t.Fatal("expected conflict error for differing bytes at same (source,chain,seq), got nil")
	}
	got, err := s.BackupEvents(ctx, src, "scope:s_x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].EventID != "ev1" || !bytes.Equal(got[0].CBOR, []byte("one")) {
		t.Fatalf("original event must be preserved on conflict, got %+v", got)
	}
}

func TestBackupPutSTHRejectsSameSizeDifferentRoot(t *testing.T) {
	s := openBackupTestStore(t)
	ctx := context.Background()
	src := bytes.Repeat([]byte{0xcd}, 32)
	sth := translog.STH{
		Head: translog.TreeHead{
			ChainID:   "scope:s_x",
			TreeSize:  4,
			RootHash:  bytes.Repeat([]byte{1}, 32),
			Timestamp: 10,
		},
		Signature: bytes.Repeat([]byte{2}, 64),
	}
	if err := s.BackupPutSTH(ctx, src, sth.Head.ChainID, sth); err != nil {
		t.Fatalf("first put: %v", err)
	}

	sameRoot := sth
	sameRoot.Head.Timestamp++
	sameRoot.Signature = bytes.Repeat([]byte{3}, 64)
	if err := s.BackupPutSTH(ctx, src, sth.Head.ChainID, sameRoot); err != nil {
		t.Fatalf("same root must be idempotent: %v", err)
	}
	if err := s.BackupPutSTH(ctx, src, "scope:s_other", sth); err == nil {
		t.Fatal("STH chain substitution accepted")
	}

	conflict := sth
	conflict.Head.RootHash = bytes.Repeat([]byte{9}, 32)
	if err := s.BackupPutSTH(ctx, src, sth.Head.ChainID, conflict); err == nil {
		t.Fatal("expected conflicting root at same tree size to fail")
	}
	got, err := s.BackupCurrentSTH(ctx, src, sth.Head.ChainID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Head.RootHash, sth.Head.RootHash) {
		t.Fatal("conflicting STH replaced the archived root")
	}
}

// TestIsPeerPub covers the auth-source for peer replication: only a row
// in the peers table authorises a pull.
func TestIsPeerPub(t *testing.T) {
	s := openBackupTestStore(t)
	ctx := context.Background()
	pub := bytes.Repeat([]byte{7}, 32)
	if ok, _ := s.IsPeerPub(ctx, pub); ok {
		t.Fatal("unpinned pub must not be authorised")
	}
	if err := s.UpsertPeer(ctx, "https://peer.example", pub, "p"); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.IsPeerPub(ctx, pub); err != nil || !ok {
		t.Fatalf("pinned pub must be authorised (ok=%v err=%v)", ok, err)
	}
}
