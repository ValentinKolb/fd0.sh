package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestScopesForMemberUsesUpdatedIndex(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "fd0.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	alice := bytes.Repeat([]byte{1}, 32)
	bob := bytes.Repeat([]byte{2}, 32)
	meta, err := proto.Marshal(scopeMemberMetadata{Members: [][]byte{alice}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Append(ctx, AppendOpts{
		ChainID:     "scope:s_indexed",
		Kind:        KindScope,
		Genesis:     true,
		Seq:         0,
		NewTipHash:  bytes.Repeat([]byte{3}, 32),
		NewMetadata: meta,
		Event:       Event{EventID: "event-index-0", Kind: "member.change", CBOR: []byte{1}},
	}); err != nil {
		t.Fatal(err)
	}

	if got, err := s.ScopesForMember(ctx, alice); err != nil || len(got) != 1 {
		t.Fatalf("alice index lookup: len=%d err=%v", len(got), err)
	}
	if got, err := s.ScopesForMember(ctx, bob); err != nil || len(got) != 0 {
		t.Fatalf("bob must not discover scope: len=%d err=%v", len(got), err)
	}
}

func TestOpenBackfillsScopeMemberIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fd0.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	members := make([][]byte, proto.MaxScopeMembers+1)
	for i := range members {
		sum := sha256.Sum256([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		members[i] = sum[:]
	}
	member := members[len(members)-1]
	meta, err := proto.Marshal(scopeMemberMetadata{Members: members})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(
		`INSERT INTO chains (chain_id, tip_seq, tip_hash, metadata) VALUES (?, 0, ?, ?)`,
		"scope:s_legacy", bytes.Repeat([]byte{8}, 32), meta,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM schema_state WHERE key = 'scope_members_version'`); err != nil {
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
	got, err := s.ScopesForMember(context.Background(), member)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "scope:s_legacy" {
		t.Fatalf("legacy index was not backfilled: %+v", got)
	}
}
