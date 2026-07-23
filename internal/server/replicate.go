package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/server/store"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// Server-to-server replication, pulling side (REPLICATION.md Phase 0).
//
// When configured with a primary URL, a server runs this background loop:
// on each cycle it learns the primary's translog identity, enumerates the
// primary's chains, and mirrors each chain's new event suffix + current
// STH into the local backup archive (store.Backup*). The archive is
// write-once and never served — it exists so that if the primary's disk
// dies, no (encrypted) event is lost. Promotion of the standby is a
// separate, operator-driven restore (REPLICATION.md §5 Phase 3).
//
// This loop touches ONLY the backup tables. It never appends to, signs,
// or serves the live chains — so it cannot create a second anchor for a
// chain the primary anchors (the one-anchor invariant, §2).

const defaultReplicateInterval = 30 * time.Second

type replicator struct {
	primary canon.URL
	store   *store.Store
	client  *http.Client
	log     *slog.Logger

	pinnedSrc []byte // TOFU-pinned primary translog pub (refuse rotation)
}

// startReplication launches the background mirror loop until ctx is done.
// interval <= 0 uses the default.
func (s *Server) startReplication(ctx context.Context, primary canon.URL, interval time.Duration) {
	if interval <= 0 {
		interval = defaultReplicateInterval
	}
	r := &replicator{
		primary: primary,
		store:   s.store,
		client:  &http.Client{Timeout: 60 * time.Second},
		log:     s.log,
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		r.cycleSafe(ctx) // one cycle immediately on boot
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.cycleSafe(ctx)
			}
		}
	}()
}

func (r *replicator) cycleSafe(ctx context.Context) {
	if err := r.cycle(ctx); err != nil {
		r.log.Warn("replication cycle failed", "primary", r.primary.String(), "err", err)
	}
}

// cycle mirrors every chain the primary currently has. It is best-effort
// and idempotent: a failure on one chain logs and is retried next cycle;
// already-stored events are skipped (INSERT OR IGNORE).
func (r *replicator) cycle(ctx context.Context) error {
	srcPub, err := r.primaryPub(ctx)
	if err != nil {
		return fmt.Errorf("resolve primary identity: %w", err)
	}
	// TOFU-pin the primary's identity: refuse to keep mirroring if its
	// translog pubkey changes under us (rotation, DNS/TLS misroute, or a
	// reconfigured target). A silent identity change would re-namespace
	// the backup under a new pub and break DR continuity. An intentional
	// rotation requires restarting the standby (which re-pins).
	if r.pinnedSrc == nil {
		r.pinnedSrc = append([]byte(nil), srcPub...)
	} else if !bytes.Equal(r.pinnedSrc, srcPub) {
		return fmt.Errorf("primary identity changed: pinned %x, got %x — refusing to mirror (restart to re-pin)", r.pinnedSrc[:8], srcPub[:8])
	}
	ids, err := r.listChains(ctx)
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}
	var mirrored, failed int
	for _, id := range ids {
		if err := r.mirrorChain(ctx, srcPub, id); err != nil {
			r.log.Warn("mirror chain failed", "chain", id, "err", err)
			failed++
			continue
		}
		mirrored++
	}
	r.log.Info("replication cycle", "primary", r.primary.String(),
		"chains", len(ids), "mirrored", mirrored, "failed", failed)
	return nil
}

// primaryPub fetches and verifies the primary's /v1/server-info and
// returns its translog pubkey, which namespaces the backup archive.
func (r *replicator) primaryPub(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.primary.String()+"/v1/server-info", nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server-info: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var info translog.ServerInfo
	if err := proto.Unmarshal(body, &info); err != nil {
		return nil, err
	}
	if err := translog.VerifyServerInfo(info); err != nil {
		return nil, fmt.Errorf("server-info self-signature: %w", err)
	}
	if len(info.ServerPub) != 32 {
		return nil, fmt.Errorf("server-info: bad server_pub length %d", len(info.ServerPub))
	}
	return info.ServerPub, nil
}

// listChains fetches the primary's chain ids (unauthenticated /v1/chains).
func (r *replicator) listChains(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.primary.String()+"/v1/chains", nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chains: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<24))
	if err != nil {
		return nil, err
	}
	var out struct {
		Chains []string `cbor:"chains"`
	}
	if err := proto.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Chains, nil
}

// mirrorChain pulls the new suffix (and STH) for one chain into the
// backup archive, looping until the chain is fully caught up.
func (r *replicator) mirrorChain(ctx context.Context, srcPub []byte, chainID string) error {
	archived, err := r.store.BackupEvents(ctx, srcPub, chainID)
	if err != nil {
		return err
	}
	leafHashes := make([][]byte, 0, len(archived))
	var prevHash []byte
	for i, e := range archived {
		hash, leaf, err := validateReplicatedEvent(chainID, uint64(i), prevHash, e)
		if err != nil {
			return fmt.Errorf("chain %s: invalid archived event: %w", chainID, err)
		}
		prevHash = hash
		leafHashes = append(leafHashes, leaf)
	}

	expectedSeq := uint64(len(archived))
	pending := make([]store.Event, 0)
	var finalSTH *translog.STH
	for {
		resp, err := r.peerGetChain(ctx, srcPub, chainID, expectedSeq)
		if err != nil {
			return err
		}
		if resp.STH == nil {
			return fmt.Errorf("chain %s: primary omitted STH", chainID)
		}
		if err := translog.VerifySTH(srcPub, *resp.STH); err != nil {
			return fmt.Errorf("chain %s: primary STH failed verification under its own key: %w", chainID, err)
		}
		if resp.STH.Head.ChainID != chainID {
			return fmt.Errorf("chain %s: primary returned STH for %s", chainID, resp.STH.Head.ChainID)
		}
		if finalSTH != nil && resp.STH.Head.TreeSize < finalSTH.Head.TreeSize {
			return fmt.Errorf("chain %s: primary tree shrank during replication (%d to %d)",
				chainID, finalSTH.Head.TreeSize, resp.STH.Head.TreeSize)
		}
		finalSTH = resp.STH

		for _, wire := range resp.Events {
			if wire.ChainID != chainID {
				return fmt.Errorf("chain %s: primary returned event for %s", chainID, wire.ChainID)
			}
			e := storeEventFromWire(wire)
			hash, leaf, err := validateReplicatedEvent(chainID, expectedSeq, prevHash, e)
			if err != nil {
				return fmt.Errorf("chain %s: invalid replicated event: %w", chainID, err)
			}
			pending = append(pending, e)
			prevHash = hash
			leafHashes = append(leafHashes, leaf)
			expectedSeq++
		}

		switch {
		case expectedSeq == finalSTH.Head.TreeSize:
			goto verified
		case expectedSeq > finalSTH.Head.TreeSize:
			return fmt.Errorf("chain %s: received %d events for tree size %d",
				chainID, expectedSeq, finalSTH.Head.TreeSize)
		case len(resp.Events) < peerPullLimit:
			return fmt.Errorf("chain %s: incomplete page ended at seq %d before tree size %d",
				chainID, expectedSeq, finalSTH.Head.TreeSize)
		}
	}

verified:
	root := translog.MerkleTreeHash(leafHashes)
	if !bytes.Equal(root, finalSTH.Head.RootHash) {
		return fmt.Errorf("chain %s: archived events do not match signed tree root", chainID)
	}
	if err := r.store.BackupAppendEvents(ctx, srcPub, pending); err != nil {
		return err
	}
	return r.store.BackupPutSTH(ctx, srcPub, chainID, *finalSTH)
}

// validateReplicatedEvent binds the archive metadata and canonical event bytes
// to one exact chain position and returns the hashes needed for chain and
// transparency-log verification.
func validateReplicatedEvent(chainID string, expectedSeq uint64, expectedPrev []byte, e store.Event) ([]byte, []byte, error) {
	if e.ChainID != chainID {
		return nil, nil, fmt.Errorf("event chain %s does not match requested chain", e.ChainID)
	}
	if e.Seq != expectedSeq {
		return nil, nil, fmt.Errorf("event seq %d, want %d", e.Seq, expectedSeq)
	}

	var (
		seq       uint64
		prev      []byte
		kind      string
		prevInput []byte
		err       error
	)
	switch {
	case strings.HasPrefix(chainID, "scope:"):
		var ev proto.ScopeEvent
		if err := proto.Unmarshal(e.CBOR, &ev); err != nil {
			return nil, nil, fmt.Errorf("decode scope event: %w", err)
		}
		seq = ev.SignedPrefix.Seq
		prev = ev.SignedPrefix.PrevHash
		kind = ev.SignedPrefix.Kind
		prevInput, err = ev.PrevHashInput()
		scopeID := strings.TrimPrefix(chainID, "scope:")
		if seq == 0 {
			if ev.SignedPrefix.Scope != nil {
				return nil, nil, fmt.Errorf("genesis event has scope")
			}
			if got := proto.DeriveScopeID(proto.EventID(prevInput)).String(); got != scopeID {
				return nil, nil, fmt.Errorf("genesis derives scope %s, want %s", got, scopeID)
			}
		} else if ev.SignedPrefix.Scope == nil || *ev.SignedPrefix.Scope != scopeID {
			return nil, nil, fmt.Errorf("event scope does not match %s", scopeID)
		}
	case strings.HasPrefix(chainID, "user:"):
		var ev proto.UserEvent
		if err := proto.Unmarshal(e.CBOR, &ev); err != nil {
			return nil, nil, fmt.Errorf("decode user event: %w", err)
		}
		seq = ev.Seq
		prev = ev.PrevHash
		kind = ev.Kind
		prevInput, err = ev.PrevHashInput()
	default:
		return nil, nil, fmt.Errorf("unsupported chain id %q", chainID)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("canonical event input: %w", err)
	}
	if seq != e.Seq || kind != e.Kind || !bytes.Equal(prev, e.PrevHash) {
		return nil, nil, fmt.Errorf("event metadata does not match canonical bytes")
	}
	if expectedSeq == 0 {
		if len(prev) != 0 {
			return nil, nil, fmt.Errorf("genesis prev_hash is not empty")
		}
	} else if !bytes.Equal(prev, expectedPrev) {
		return nil, nil, fmt.Errorf("event prev_hash does not match seq %d", expectedSeq-1)
	}
	if got := proto.EventID(prevInput); got != e.EventID {
		return nil, nil, fmt.Errorf("event id %s does not match canonical bytes", e.EventID)
	}
	hash := proto.HashPrefix(prevInput)
	return append([]byte(nil), hash[:]...), translog.LeafHash(hash[:]), nil
}

// peerGetChain performs a signed GET /v1/peer/chain?id=&since= against
// the primary, signing with this server's translog key bound to the
// primary's translog pubkey (server_pub) for cross-server replay
// resistance — the same scheme clients use.
func (r *replicator) peerGetChain(ctx context.Context, srcPub []byte, chainID string, since uint64) (*peerChainResp, error) {
	q := url.Values{"id": {chainID}, "since": {strconv.FormatUint(since, 10)}}
	endpoint := r.primary.String() + "/v1/peer/chain?" + q.Encode()
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	qmap := map[string]string{}
	for k, vs := range u.Query() {
		qmap[k] = vs[0]
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ts := uint64(time.Now().Unix())
	si, err := proto.HTTPSignedInput("GET", u.Path, qmap, ts, nonce, nil, srcPub)
	if err != nil {
		return nil, err
	}
	sig := r.store.TranslogSign(si)
	if sig == nil {
		return nil, fmt.Errorf("no translog key to sign peer request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization",
		"fd0-sig v1 pk="+base64.StdEncoding.EncodeToString(r.store.TranslogPub())+
			", nonce="+base64.StdEncoding.EncodeToString(nonce)+
			", ts="+strconv.FormatUint(ts, 10)+
			", sig="+base64.StdEncoding.EncodeToString(sig))
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<26))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer chain %s: %s: %s", chainID, resp.Status, string(body))
	}
	var out peerChainResp
	if err := proto.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
