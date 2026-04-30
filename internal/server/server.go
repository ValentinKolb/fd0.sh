// Package server implements the fd0 HTTP API (API.md). It is a thin layer
// over store + validate.
package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/server/store"
	"github.com/valentinkolb/fd0.sh/internal/server/validate"
)

// Config configures the server.
type Config struct {
	Bind     string // e.g. ":4048"
	DBPath   string // path to SQLite file
	Version  string // server version reported by /version
	MaxBytes int64  // max request body
	Logger   *slog.Logger
}

// Server is the HTTP service. New constructs it; ServeHTTP routes requests.
type Server struct {
	cfg   Config
	store *store.Store
	mux   *http.ServeMux
	log   *slog.Logger
}

// New initialises the store and routes.
func New(cfg Config) (*Server, error) {
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 8 * 1024 * 1024
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: st, mux: http.NewServeMux(), log: cfg.Logger}
	s.routes()
	go s.noncePruner()
	return s, nil
}

// Close releases resources.
func (s *Server) Close() error { return s.store.Close() }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBytes)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /version", s.handleVersion)
	s.mux.HandleFunc("POST /users", s.handleRegister)
	s.mux.HandleFunc("GET /users/{shortId}/events", s.handleFetchUser)
	s.mux.HandleFunc("POST /users/{shortId}/events", s.handleAppendUser)
	s.mux.HandleFunc("POST /sync", s.handleSync)
}

// ---- handlers ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"server_version": s.cfg.Version,
		"api_version":    "v1",
	})
}

// POST /users — accept genesis auth.set, assign shortId.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	var req struct {
		Event proto.UserEvent `cbor:"event"`
	}
	if err := proto.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	if err := validate.UserEvent(&req.Event, nil, nil, 0); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_event", err.Error())
		return
	}
	// Allocate a fresh shortId. Retry on collision (extremely unlikely).
	var sid string
	for tries := 0; tries < 8; tries++ {
		sid = newShortID()
		if _, err := s.store.GetChain(r.Context(), store.ChainID(store.KindUser, sid)); errors.Is(err, store.ErrNotFound) {
			break
		}
	}
	prefix, err := req.Event.PrevHashInput()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	tipHash := proto.HashPrefix(prefix)
	meta, err := proto.Marshal(validate.UserMeta{SuperPub: req.Event.UserSuperPub, ShortID: sid})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	cb, err := proto.Marshal(&req.Event)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	eventID := proto.EventID(prefix)
	err = s.store.Append(r.Context(), store.AppendOpts{
		ChainID:     store.ChainID(store.KindUser, sid),
		Kind:        store.KindUser,
		Genesis:     true,
		Seq:         0,
		NewTipHash:  tipHash[:],
		NewMetadata: meta,
		Event: store.Event{
			Seq:      0,
			EventID:  eventID,
			PrevHash: nil,
			Kind:     proto.KindAuthSet,
			CBOR:     cb,
		},
	})
	if errors.Is(err, store.ErrDuplicate) {
		writeErr(w, http.StatusConflict, "dup", "event_id collision")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeCBOR(w, http.StatusCreated, map[string]any{"shortId": sid, "event_id": eventID})
}

// GET /users/<shortId>/events
func (s *Server) handleFetchUser(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("shortId")
	chainID := store.ChainID(store.KindUser, sid)
	c, err := s.store.GetChain(r.Context(), chainID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var meta validate.UserMeta
	if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
		writeErr(w, http.StatusInternalServerError, "bad_meta", err.Error())
		return
	}
	q := r.URL.Query()
	if q.Get("latest") == "true" {
		ev, err := s.store.LatestEvent(r.Context(), chainID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		var dec proto.UserEvent
		if err := proto.Unmarshal(ev.CBOR, &dec); err != nil {
			writeErr(w, http.StatusInternalServerError, "bad_event", err.Error())
			return
		}
		writeCBOR(w, http.StatusOK, map[string]any{
			"user_super_pub": meta.SuperPub,
			"event":          dec,
			"chain_tip_seq":  c.TipSeq,
			"chain_tip_hash": c.TipHash,
		})
		return
	}
	since := uint64(0)
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_since", err.Error())
			return
		}
		since = n
	}
	rows, err := s.store.EventsSince(r.Context(), chainID, since, 1000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]proto.UserEvent, 0, len(rows))
	for _, e := range rows {
		var d proto.UserEvent
		if err := proto.Unmarshal(e.CBOR, &d); err != nil {
			writeErr(w, http.StatusInternalServerError, "bad_event", err.Error())
			return
		}
		out = append(out, d)
	}
	writeCBOR(w, http.StatusOK, map[string]any{
		"user_super_pub": meta.SuperPub,
		"events":         out,
		"chain_tip_seq":  c.TipSeq,
		"chain_tip_hash": c.TipHash,
	})
}

// POST /users/<shortId>/events — authenticated append to user chain.
func (s *Server) handleAppendUser(w http.ResponseWriter, r *http.Request) {
	auth, code, err := s.verifyHTTPSig(r.Context(), r)
	if err != nil {
		writeErr(w, code, "auth", err.Error())
		return
	}
	sid := r.PathValue("shortId")
	chainID := store.ChainID(store.KindUser, sid)
	c, err := s.store.GetChain(r.Context(), chainID)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var meta validate.UserMeta
	if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
		writeErr(w, http.StatusInternalServerError, "bad_meta", err.Error())
		return
	}
	if !equalBytes(meta.SuperPub, auth.Pub) {
		writeErr(w, http.StatusForbidden, "not_authorized", "pk != chain owner")
		return
	}
	var req struct {
		Event proto.UserEvent `cbor:"event"`
	}
	if err := proto.Unmarshal(auth.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	if err := validate.UserEvent(&req.Event, &meta, c.TipHash, c.TipSeq); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_event", err.Error())
		return
	}
	prefix, err := req.Event.PrevHashInput()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	tipHash := proto.HashPrefix(prefix)
	cb, err := proto.Marshal(&req.Event)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	eventID := proto.EventID(prefix)
	err = s.store.Append(r.Context(), store.AppendOpts{
		ChainID:     chainID,
		Kind:        store.KindUser,
		Genesis:     false,
		Seq:         req.Event.Seq,
		NewTipHash:  tipHash[:],
		NewMetadata: c.Metadata, // unchanged (super_pub fixed; shortId fixed)
		Event: store.Event{
			Seq:      req.Event.Seq,
			EventID:  eventID,
			PrevHash: req.Event.PrevHash,
			Kind:     proto.KindAuthSet,
			CBOR:     cb,
		},
	})
	switch {
	case errors.Is(err, store.ErrDivergence):
		writeCBOR(w, http.StatusConflict, map[string]any{
			"reason":           "divergence",
			"current_tip_seq":  c.TipSeq,
			"current_tip_hash": c.TipHash,
		})
		return
	case errors.Is(err, store.ErrDuplicate):
		writeErr(w, http.StatusConflict, "dup", "")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeCBOR(w, http.StatusOK, map[string]any{"event_id": eventID, "seq": req.Event.Seq})
}

// ---- /sync ----

// SyncReq mirrors API.md §2.4.
type SyncReq struct {
	Pull syncPull   `cbor:"pull"`
	Push []pushItem `cbor:"push"`
}
type syncPull struct {
	Scopes              map[string]syncCursor `cbor:"scopes"`
	LimitPerScope       uint64                `cbor:"limit_per_scope"`
	DiscoverMemberships bool                  `cbor:"discover_memberships"`
}
type syncCursor struct {
	Cursor cursorPos `cbor:"cursor"`
}
type cursorPos struct {
	Seq  uint64 `cbor:"seq"`
	Hash []byte `cbor:"hash"`
}
type pushItem struct {
	Scope string           `cbor:"scope"` // "" for genesis
	Event proto.ScopeEvent `cbor:"event"`
}

// SyncResp is the response shape.
type SyncResp struct {
	Pull        map[string]pullScope `cbor:"pull"`
	Memberships []membership         `cbor:"memberships,omitempty"`
	Push        []pushResult         `cbor:"push"`
}
type pullScope struct {
	Tip           tipPos             `cbor:"tip"`
	OEKVersionMax uint64             `cbor:"oek_version_max"`
	Events        []proto.ScopeEvent `cbor:"events"`
	// Denied is set when the caller is not (or no longer) a member; the
	// client interprets this as "you've been removed; drop locally".
	Denied bool `cbor:"denied,omitempty"`
}
type tipPos struct {
	Seq  uint64 `cbor:"seq"`
	Hash []byte `cbor:"hash"`
}
type membership struct {
	ScopeID     string `cbor:"scope_id"`
	AdmitEvent  string `cbor:"admit_event"`
	OEKVersion  uint64 `cbor:"oek_version"`
}
type pushResult struct {
	Accepted             bool   `cbor:"accepted"`
	EventID              string `cbor:"event_id,omitempty"`
	Seq                  uint64 `cbor:"seq,omitempty"`
	ScopeID              string `cbor:"scope_id,omitempty"`
	Reason               string `cbor:"reason,omitempty"`
	CurrentTipEventID    string `cbor:"current_tip_event_id,omitempty"`
	CurrentTipHash       []byte `cbor:"current_tip_hash,omitempty"`
	CurrentOEKVersionMax uint64 `cbor:"current_oek_version_max,omitempty"`
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	auth, code, err := s.verifyHTTPSig(r.Context(), r)
	if err != nil {
		writeErr(w, code, "auth", err.Error())
		return
	}
	var req SyncReq
	if err := proto.Unmarshal(auth.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_body", err.Error())
		return
	}
	resp := SyncResp{Pull: map[string]pullScope{}}
	limit := int(req.Pull.LimitPerScope)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	// Pull. Caller must be in the scope's auth_list to receive any events.
	// Three response states per scope:
	//   served (Events filled)                 → normal apply
	//   denied=true                            → caller no longer authorised
	//   absent from resp.Pull                  → server doesn't have the scope yet
	for sid, cur := range req.Pull.Scopes {
		fresh := len(cur.Cursor.Hash) == 0 && cur.Cursor.Seq == 0
		ps, err := s.pullScope(r.Context(), sid, cur.Cursor.Seq, limit, auth.Pub, fresh)
		if err != nil {
			if errors.Is(err, errNotMember) {
				resp.Pull[sid] = pullScope{Denied: true}
			}
			s.log.Debug("pull scope refused", "scope", sid, "err", err)
			continue
		}
		resp.Pull[sid] = ps
	}
	// Discover.
	if req.Pull.DiscoverMemberships {
		ms, err := s.discoverMemberships(r.Context(), auth.Pub)
		if err == nil {
			resp.Memberships = ms
		}
	}
	// Push.
	for _, p := range req.Push {
		resp.Push = append(resp.Push, s.applyPush(r.Context(), auth.Pub, p))
	}
	writeCBOR(w, http.StatusOK, resp)
}

func (s *Server) pullScope(ctx context.Context, scopeID string, since uint64, limit int, callerPub []byte, fresh bool) (pullScope, error) {
	chainID := store.ChainID(store.KindScope, scopeID)
	c, err := s.store.GetChain(ctx, chainID)
	if err != nil {
		return pullScope{}, err
	}
	var meta validate.ScopeMeta
	if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
		return pullScope{}, err
	}
	isMember := false
	for _, m := range meta.Members {
		if equalBytes(m, callerPub) {
			isMember = true
			break
		}
	}
	if !isMember {
		return pullScope{}, errNotMember
	}
	rows, err := s.store.EventsSinceInclusive(ctx, chainID, since, limit, fresh)
	if err != nil {
		return pullScope{}, err
	}
	out := pullScope{
		Tip:           tipPos{Seq: c.TipSeq, Hash: c.TipHash},
		OEKVersionMax: meta.OEKVersionMax,
		Events:        make([]proto.ScopeEvent, 0, len(rows)),
	}
	for _, e := range rows {
		var d proto.ScopeEvent
		if err := proto.Unmarshal(e.CBOR, &d); err != nil {
			return pullScope{}, err
		}
		out.Events = append(out.Events, d)
	}
	return out, nil
}

func (s *Server) discoverMemberships(ctx context.Context, pk []byte) ([]membership, error) {
	scopes, err := s.store.ScopesForMember(ctx, pk)
	if err != nil {
		return nil, err
	}
	var out []membership
	for _, c := range scopes {
		var meta validate.ScopeMeta
		if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
			continue
		}
		isMember := false
		for _, m := range meta.Members {
			if equalBytes(m, pk) {
				isMember = true
				break
			}
		}
		if !isMember {
			continue
		}
		// Find the admit event (latest member.change op=add of pk). For v1
		// simplicity we report the genesis event ID by scanning.
		// scope_id is the suffix after "scope:".
		scopeID := strings.TrimPrefix(c.ID, "scope:")
		out = append(out, membership{
			ScopeID:    scopeID,
			AdmitEvent: "", // optional in v1; clients can pull from cursor=0
			OEKVersion: meta.OEKVersionMax,
		})
	}
	return out, nil
}

func (s *Server) applyPush(ctx context.Context, authorPub []byte, p pushItem) pushResult {
	sp := &p.Event.SignedPrefix
	// Author == auth principal.
	if !equalBytes(sp.Author, authorPub) {
		return pushResult{Accepted: false, Reason: "bad_author"}
	}
	// Genesis push: scope_id is empty; we derive it.
	if len(sp.PrevHash) == 0 && sp.Seq == 0 && p.Scope == "" {
		prefix, _ := p.Event.PrevHashInput()
		eventID := proto.EventID(prefix)
		scopeID := proto.ScopeID(eventID)
		if exists, _ := s.eventExists(ctx, eventID); exists {
			return pushResult{Accepted: false, Reason: "dup", EventID: eventID, ScopeID: scopeID}
		}
		newMeta, err := validate.ScopeEvent(&p.Event, nil, nil, 0)
		if err != nil {
			return pushResult{Accepted: false, Reason: pushReasonFor(err)}
		}
		// store. Note: scope_id MUST be set in the event's signed prefix at
		// this point only if the client built it that way. Per PROTOCOL.md
		// the genesis event's `scope` field is nil. We use the derived ID for
		// the chain row only.
		mb, _ := proto.Marshal(*newMeta)
		cb, _ := proto.Marshal(&p.Event)
		tipHash := proto.HashPrefix(prefix)
		err = s.store.Append(ctx, store.AppendOpts{
			ChainID:     store.ChainID(store.KindScope, scopeID),
			Kind:        store.KindScope,
			Genesis:     true,
			Seq:         0,
			NewTipHash:  tipHash[:],
			NewMetadata: mb,
			Event: store.Event{
				Seq: 0, EventID: eventID, PrevHash: nil,
				Kind: proto.KindMemberChange, CBOR: cb,
			},
		})
		if errors.Is(err, store.ErrDuplicate) {
			return pushResult{Accepted: false, Reason: "dup"}
		}
		if err != nil {
			return pushResult{Accepted: false, Reason: "internal"}
		}
		return pushResult{Accepted: true, EventID: eventID, Seq: 0, ScopeID: scopeID}
	}
	// Successor push.
	chainID := store.ChainID(store.KindScope, p.Scope)
	c, err := s.store.GetChain(ctx, chainID)
	if err != nil {
		return pushResult{Accepted: false, Reason: "not_found", ScopeID: p.Scope}
	}
	// Early dup check.
	prefix, _ := p.Event.PrevHashInput()
	eventID := proto.EventID(prefix)
	if exists, _ := s.eventExists(ctx, eventID); exists {
		return pushResult{Accepted: false, Reason: "dup", EventID: eventID, ScopeID: p.Scope}
	}
	var meta validate.ScopeMeta
	if err := proto.Unmarshal(c.Metadata, &meta); err != nil {
		return pushResult{Accepted: false, Reason: "internal", ScopeID: p.Scope}
	}
	newMeta, err := validate.ScopeEvent(&p.Event, &meta, c.TipHash, c.TipSeq)
	if err != nil {
		return pushResult{Accepted: false, Reason: pushReasonFor(err), ScopeID: p.Scope}
	}
	tipHash := proto.HashPrefix(prefix)
	mb, _ := proto.Marshal(*newMeta)
	cb, _ := proto.Marshal(&p.Event)
	err = s.store.Append(ctx, store.AppendOpts{
		ChainID:     chainID,
		Kind:        store.KindScope,
		Genesis:     false,
		Seq:         sp.Seq,
		NewTipHash:  tipHash[:],
		NewMetadata: mb,
		Event: store.Event{
			Seq: sp.Seq, EventID: eventID, PrevHash: sp.PrevHash,
			Kind: sp.Kind, CBOR: cb,
		},
	})
	switch {
	case errors.Is(err, store.ErrDivergence):
		return pushResult{
			Accepted:             false,
			Reason:               "divergence",
			ScopeID:              p.Scope,
			CurrentTipHash:       c.TipHash,
			CurrentOEKVersionMax: meta.OEKVersionMax,
		}
	case errors.Is(err, store.ErrDuplicate):
		return pushResult{Accepted: false, Reason: "dup", ScopeID: p.Scope, EventID: eventID}
	case err != nil:
		return pushResult{Accepted: false, Reason: "internal", ScopeID: p.Scope}
	}
	return pushResult{Accepted: true, EventID: eventID, Seq: sp.Seq, ScopeID: p.Scope}
}

// pushReasonFor maps validate errors to API.md §2.4 reason strings.
func pushReasonFor(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "bad signature"):
		return "bad_sig"
	case strings.Contains(msg, "oek_version"):
		if strings.Contains(msg, "want") || strings.Contains(msg, "expected") {
			return "stale_oek_version"
		}
		return "future_oek_version"
	case strings.Contains(msg, "key_deliveries"):
		return "invalid_key_deliveries"
	case strings.Contains(msg, "prev_hash"),
		strings.Contains(msg, "seq=") && strings.Contains(msg, "expected"):
		return "divergence"
	default:
		return "bad_kind"
	}
}

// ---- helpers ----

func writeCBOR(w http.ResponseWriter, code int, v any) {
	b, err := proto.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func writeErr(w http.ResponseWriter, code int, reason, detail string) {
	writeCBOR(w, code, map[string]string{"reason": reason, "detail": detail})
}

var errNotMember = errors.New("not a member")

// eventExists is a tiny shortcut against the events table. Used by applyPush
// for early dup detection (cheaper than running the full validator against
// stale prior state).
func (s *Server) eventExists(ctx context.Context, eventID string) (bool, error) {
	return s.store.EventExists(ctx, eventID)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// newShortID returns 8 chars of Crockford-base32. v1 uses standard base32
// with the same charset minus padding; we lower-case and remap I/O/L to keep
// human-readability.
func newShortID() string {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure
	}
	const charset = "0123456789abcdefghjkmnpqrstvwxyz" // Crockford
	out := make([]byte, 8)
	bits := uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	for i := 0; i < 8; i++ {
		out[i] = charset[bits&31]
		bits >>= 5
	}
	return string(out)
}

// noncePruner runs once a minute and trims expired auth_nonces.
func (s *Server) noncePruner() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := s.store.PruneNonces(ctx, nonceTTLSecs); err != nil {
			s.log.Warn("prune nonces", "err", err)
		}
		cancel()
	}
}

// Run starts an http.Server bound to cfg.Bind and blocks.
func Run(s *Server) error {
	srv := &http.Server{
		Addr:              s.cfg.Bind,
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	s.log.Info("fd0-server listening", "bind", s.cfg.Bind, "version", s.cfg.Version)
	return srv.ListenAndServe()
}

