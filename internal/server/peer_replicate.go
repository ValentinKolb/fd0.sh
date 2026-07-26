package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/server/store"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// Server-to-server replication serving side (REPLICATION.md Phase 0).
//
// A replica pulls a verbatim copy of this server's chains for disaster
// recovery. The data is encrypted (zero-knowledge) so serving it does not
// expose secret values, but it does reveal scope existence/membership
// events, so the endpoint is restricted to TOFU-pinned PEERS (not
// anonymous callers and not arbitrary registered users).
//
// Auth reuses the client `fd0-sig` scheme (server_pub-bound, so a request
// signed for server A can't be replayed against server B), but authorises
// the signer as a pinned peer instead of a registered user. There is no
// nonce table: these are idempotent GETs returning data the peer is
// entitled to mirror, so replay is harmless.

// peerPullLimit caps events returned per peer-chain request; the
// replicator loops until caught up.
const peerPullLimit = 1000

// peerEventWire is the verbatim on-wire form of a stored event. The
// replica reconstructs store.Event from it byte-for-byte.
type peerEventWire struct {
	ChainID  string `cbor:"chain_id"`
	Seq      uint64 `cbor:"seq"`
	EventID  string `cbor:"event_id"`
	PrevHash []byte `cbor:"prev_hash,omitempty"`
	Kind     string `cbor:"kind"`
	CBOR     []byte `cbor:"cbor"`
	StoredAt int64  `cbor:"stored_at"`
}

// peerChainResp is the GET /v1/peer/chain/{chainId} response: the
// requested suffix of events plus the current STH (so the replica
// archives the source's signed tree head alongside the events).
type peerChainResp struct {
	Events []peerEventWire `cbor:"events"`
	STH    *translog.STH   `cbor:"sth,omitempty"`
}

// verifyPeerSig authenticates a server-to-server replication request: the
// signer must be a TOFU-pinned peer. Mirrors verifyHTTPSig's parsing and
// the server_pub binding, minus the nonce/replay table (idempotent GET).
func (s *Server) verifyPeerSig(r *http.Request) ([]byte, int, error) {
	if s.rl != nil {
		if d := s.rl.AcquireAuthAttempt(s.clientIP(r)); !d.Allow {
			return nil, http.StatusTooManyRequests, rateLimitedError{retry: d.Retry}
		}
	}
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "fd0-sig v1") {
		return nil, http.StatusUnauthorized, errors.New("bad scheme")
	}
	params := parseSigParams(strings.TrimSpace(strings.TrimPrefix(hdr, "fd0-sig v1")))
	pk, err := b64dec(params["pk"])
	if err != nil || len(pk) != 32 {
		return nil, http.StatusUnauthorized, errors.New("bad pk")
	}
	nonce, err := b64dec(params["nonce"])
	if err != nil || len(nonce) != 16 {
		return nil, http.StatusUnauthorized, errors.New("bad nonce")
	}
	ts, err := strconv.ParseInt(params["ts"], 10, 64)
	if err != nil {
		return nil, http.StatusUnauthorized, errors.New("bad ts")
	}
	sig, err := b64dec(params["sig"])
	if err != nil || len(sig) != 64 {
		return nil, http.StatusUnauthorized, errors.New("bad sig")
	}
	if absDelta(time.Now().Unix(), ts) > int64(maxClockSkew.Seconds()) {
		return nil, http.StatusUnauthorized, errors.New("stale_ts")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	r.Body.Close()
	qmap := map[string]string{}
	for k, vs := range r.URL.Query() {
		if len(vs) > 1 {
			return nil, http.StatusBadRequest, errors.New("multi-value query key")
		}
		qmap[k] = vs[0]
	}
	si, err := proto.HTTPSignedInput(r.Method, r.URL.Path, qmap, uint64(ts), nonce, body, []byte(s.store.TranslogPub()))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if !crypto.VerifyBytes(pk, si, sig) {
		return nil, http.StatusUnauthorized, errors.New("bad_sig")
	}
	isPeer, err := s.store.IsPeerPub(r.Context(), pk)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !isPeer {
		return nil, http.StatusForbidden, errors.New("not_a_peer")
	}
	return pk, http.StatusOK, nil
}

// handlePeerChain serves GET /v1/peer/chain?id=<chainId>&since=N to a
// pinned peer: events with seq >= N (N = the first seq the replica still
// needs) plus the chain's current STH. The replica calls it repeatedly,
// advancing `since`, until caught up. The chain id is a query param (not
// a path segment) so its ":" round-trips cleanly through request signing.
func (s *Server) handlePeerChain(w http.ResponseWriter, r *http.Request) {
	if _, status, err := s.verifyPeerSig(r); err != nil {
		writeErr(w, status, "peer_auth", err.Error())
		return
	}
	chainID := r.URL.Query().Get("id")
	if !validChainID(chainID) {
		writeErr(w, http.StatusBadRequest, "bad_chain_id", "")
		return
	}
	var since uint64
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_since", "")
			return
		}
		since = n
	}
	evs, err := s.store.EventsSinceInclusive(r.Context(), chainID, since, peerPullLimit, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	resp := peerChainResp{Events: make([]peerEventWire, 0, len(evs))}
	for _, e := range evs {
		resp.Events = append(resp.Events, peerEventWire{
			ChainID:  e.ChainID,
			Seq:      e.Seq,
			EventID:  e.EventID,
			PrevHash: e.PrevHash,
			Kind:     e.Kind,
			CBOR:     e.CBOR,
			StoredAt: e.StoredAt,
		})
	}
	if sth, err := s.store.CurrentSTH(r.Context(), chainID); err == nil {
		resp.STH = &sth
	} else if !errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeCBOR(w, http.StatusOK, resp)
}

// storeEventFromWire reconstructs a store.Event from its wire form.
func storeEventFromWire(e peerEventWire) store.Event {
	return store.Event{
		ChainID:  e.ChainID,
		Seq:      e.Seq,
		EventID:  e.EventID,
		PrevHash: e.PrevHash,
		Kind:     e.Kind,
		CBOR:     e.CBOR,
		StoredAt: e.StoredAt,
	}
}
