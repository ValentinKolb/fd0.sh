package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/server/store"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestReplicatorRejectsForgedSTH is the sensitivity test for the
// verify-STH-before-archive guard (review blind spot): a malicious/buggy
// primary that serves a validly-shaped but WRONGLY-SIGNED STH must NOT
// have it archived — the backup STH is the DR integrity anchor. A fake
// primary serves real-looking events plus a garbage-signed STH; the
// replicator must refuse to store that STH.
func TestReplicatorRejectsForgedSTH(t *testing.T) {
	ctx := context.Background()
	pubA, privA, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	info, err := translog.SignServerInfo(privA, 1, "fake", nil)
	if err != nil {
		t.Fatal(err)
	}
	const chainID = "scope:s_forge"
	forged := translog.STH{
		Head:      translog.TreeHead{ChainID: chainID, TreeSize: 1, RootHash: bytes.Repeat([]byte{0xAA}, 32), Timestamp: 1},
		Signature: bytes.Repeat([]byte{0xFF}, 64), // not a real signature
	}
	// Sanity: the forged STH genuinely fails verification under pubA.
	if translog.VerifySTH(pubA, forged) == nil {
		t.Fatal("test setup: forged STH unexpectedly verifies")
	}
	writeCBOR := func(w http.ResponseWriter, v any) {
		b, err := proto.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(b)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/server-info", func(w http.ResponseWriter, r *http.Request) { writeCBOR(w, info) })
	mux.HandleFunc("/v1/chains", func(w http.ResponseWriter, r *http.Request) {
		writeCBOR(w, map[string]any{"chains": []string{chainID}})
	})
	mux.HandleFunc("/v1/peer/chain", func(w http.ResponseWriter, r *http.Request) {
		writeCBOR(w, peerChainResp{
			Events: []peerEventWire{{ChainID: chainID, Seq: 0, EventID: "e0", Kind: "secret.set", CBOR: []byte("x"), StoredAt: 1}},
			STH:    &forged,
		})
	})
	fake := httptest.NewServer(mux)
	defer fake.Close()

	stB, err := store.Open(t.TempDir() + "/b.db")
	if err != nil {
		t.Fatal(err)
	}
	defer stB.Close()
	primaryURL, _ := canon.ParseURL(fake.URL)
	r := &replicator{primary: primaryURL, store: stB, client: fake.Client(), log: discardLog()}
	_ = r.cycle(ctx) // per-chain failure is logged, not returned

	if _, err := stB.BackupCurrentSTH(ctx, pubA, chainID); err == nil {
		t.Fatal("forged STH was archived — verify-before-archive guard is not effective")
	}
}

// TestReplicatorRefusesPrimaryIdentityRotation is the sensitivity test for
// the TOFU pin on the primary's identity (review blind spot): once the
// replica has pinned the primary's translog pubkey, a later cycle that
// sees a DIFFERENT pubkey (rotation / DNS-TLS misroute / wrong target)
// must refuse, not silently re-namespace the backup.
func TestReplicatorRefusesPrimaryIdentityRotation(t *testing.T) {
	srv, pts := newTestServer(t)
	primaryURL, err := canon.ParseURL(pts.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := &replicator{
		primary:   primaryURL,
		store:     srv.Store(),
		client:    pts.Client(),
		log:       discardLog(),
		pinnedSrc: bytes.Repeat([]byte{0x9}, 32), // pinned to a DIFFERENT identity
	}
	err = r.cycle(context.Background())
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("expected primary-identity-change refusal, got %v", err)
	}
}

// TestPrunePeersRevokesUnconfigured is the sensitivity test for peer
// authorization revocation (review blind spot): a peer removed from
// FD0_PEERS must lose its replication-pull authorization on the next boot,
// while a still-configured peer is retained. Uses lowercase hosts so
// canonicalisation is identity.
func TestPrunePeersRevokesUnconfigured(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := func(peers []string) Config {
		return Config{
			DBPath:            dir + "/s.db",
			TranslogKeyPath:   dir + "/s.key",
			RateLimitDisabled: true,
			Logger:            discardLog(),
			Peers:             peers,
		}
	}
	pubKeep := bytes.Repeat([]byte{1}, 32)
	pubGone := bytes.Repeat([]byte{2}, 32)

	s1, err := New(cfg([]string{"https://keep.example"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Store().UpsertPeer(ctx, "https://keep.example", pubKeep, "keep"); err != nil {
		t.Fatal(err)
	}
	if err := s1.Store().UpsertPeer(ctx, "https://gone.example", pubGone, "gone"); err != nil {
		t.Fatal(err)
	}
	_ = s1.Close()

	// Reboot with "gone" removed from the configured set.
	s2, err := New(cfg([]string{"https://keep.example"}))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if ok, _ := s2.Store().IsPeerPub(ctx, pubKeep); !ok {
		t.Fatal("still-configured peer was wrongly revoked")
	}
	if ok, _ := s2.Store().IsPeerPub(ctx, pubGone); ok {
		t.Fatal("unconfigured peer was NOT revoked — stale authorization persists")
	}
}

// TestPeerEndpointRejectsUnpinnedSigner is the sensitivity test for the
// peer-pull authorization (review blind spot): a validly-signed request
// from a key that is NOT a pinned peer must get 403 at the HTTP handler,
// not be served. (The store-level IsPeerPub check was tested; the handler
// path was not.)
func TestPeerEndpointRejectsUnpinnedSigner(t *testing.T) {
	srv, pts := newTestServer(t)
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// pub is neither a registered user nor a pinned peer.
	req, _ := http.NewRequest("GET", pts.URL+"/v1/peer/chain?id=scope:s_x&since=0", nil)
	signRequest(t, srv, req, nil, pub.Bytes(), priv.Bytes())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unpinned peer signer must get 403, got %d: %s", resp.StatusCode, b)
	}
}

// TestPhase0BackupReplication is the REPLICATION.md Phase 0 acceptance
// test: a standby mirrors a primary's chains into its local backup
// archive, byte-for-byte, including the primary's signed STH — and never
// touches its own live tables.
func TestPhase0BackupReplication(t *testing.T) {
	ctx := context.Background()

	// ── Primary: register a user and push several scope chains. ──────
	primary, pts := newTestServer(t)
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Store().RegisterUser(ctx, pub.Bytes(), "primary_user"); err != nil {
		t.Fatal(err)
	}
	push := make([]any, 0, 3)
	for i := 0; i < 3; i++ {
		ev, _, _, err := chain.BuildScopeGenesis(chain.LocalSigner{Priv: priv}, pub.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		// A genesis push carries an EMPTY scope frame; the server derives
		// scope_id from the event and assigns it (API.md §2.4).
		push = append(push, map[string]any{"scope": "", "event": ev})
	}
	body, _ := proto.Marshal(map[string]any{
		"pull": map[string]any{"scopes": map[string]any{}, "limit_per_scope": uint64(0)},
		"push": push,
	})
	req, _ := http.NewRequest("POST", pts.URL+"/v1/sync", bytes.NewReader(body))
	signRequest(t, primary, req, body, pub.Bytes(), priv.Bytes())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("seed push: %s", resp.Status)
	}

	primaryPub := primary.Store().TranslogPub()
	chains, err := primary.Store().ListChainIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) == 0 {
		t.Fatal("primary has no chains after seed push")
	}

	// ── Replica: a second server (for its own translog key + store). ─
	replica, _ := newTestServer(t)
	// The primary must pin the replica's pubkey to authorise the peer
	// pull (production: via FD0_PEERS; here: seed the peers table).
	if err := primary.Store().UpsertPeer(ctx, "http://replica.test", replica.Store().TranslogPub(), "replica"); err != nil {
		t.Fatal(err)
	}

	// ── Run ONE replication cycle deterministically (no ticker). ─────
	primaryURL, err := canon.ParseURL(pts.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := &replicator{
		primary: primaryURL,
		store:   replica.Store(),
		client:  pts.Client(),
		log:     replica.log,
	}
	if err := r.cycle(ctx); err != nil {
		t.Fatalf("replication cycle: %v", err)
	}

	// ── INVARIANT: every primary chain is mirrored byte-identically. ─
	for _, cid := range chains {
		want, err := primary.Store().EventsSinceInclusive(ctx, cid, 0, 10000, true)
		if err != nil {
			t.Fatalf("primary events %s: %v", cid, err)
		}
		got, err := replica.Store().BackupEvents(ctx, primaryPub, cid)
		if err != nil {
			t.Fatalf("backup events %s: %v", cid, err)
		}
		if len(got) != len(want) {
			t.Fatalf("chain %s: backup has %d events, primary has %d", cid, len(got), len(want))
		}
		for i := range want {
			if got[i].EventID != want[i].EventID || !bytes.Equal(got[i].CBOR, want[i].CBOR) {
				t.Fatalf("chain %s seq %d: backup event differs from primary", cid, want[i].Seq)
			}
		}
		// STH archived and byte-identical (verbatim, primary-signed).
		wantSTH, err := primary.Store().CurrentSTH(ctx, cid)
		if err != nil {
			t.Fatalf("primary STH %s: %v", cid, err)
		}
		gotSTH, err := replica.Store().BackupCurrentSTH(ctx, primaryPub, cid)
		if err != nil {
			t.Fatalf("backup STH %s: %v", cid, err)
		}
		if gotSTH.Head.TreeSize != wantSTH.Head.TreeSize ||
			!bytes.Equal(gotSTH.Head.RootHash, wantSTH.Head.RootHash) ||
			!bytes.Equal(gotSTH.Signature, wantSTH.Signature) {
			t.Fatalf("chain %s: backup STH differs from primary's signed STH", cid)
		}
	}

	// ── SAFETY: the replica's LIVE tables are untouched (it only ever
	// wrote the backup archive). Mirroring must never create a
	// locally-anchored chain. ──────────────────────────────────────
	liveChains, err := replica.Store().ListChainIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(liveChains) != 0 {
		t.Fatalf("replica live tables polluted by replication: %v", liveChains)
	}

	// Idempotency: a second cycle changes nothing and does not error.
	if err := r.cycle(ctx); err != nil {
		t.Fatalf("second replication cycle: %v", err)
	}
	for _, cid := range chains {
		got, _ := replica.Store().BackupEvents(ctx, primaryPub, cid)
		want, _ := primary.Store().EventsSinceInclusive(ctx, cid, 0, 10000, true)
		if len(got) != len(want) {
			t.Fatalf("chain %s: not idempotent (%d vs %d after 2nd cycle)", cid, len(got), len(want))
		}
	}

	// ── Peer auth: an UNPINNED signer must be refused. ───────────────
	otherPub, _, _ := crypto.GenerateIdentity()
	isPeer, err := primary.Store().IsPeerPub(ctx, otherPub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if isPeer {
		t.Fatal("unpinned pubkey wrongly authorised as peer")
	}
}
