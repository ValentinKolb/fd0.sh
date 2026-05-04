package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// Config tunes the agent.
type Config struct {
	IdleTimeout time.Duration // default 5m
	MaxLifetime time.Duration // default 8h
	Logger      *slog.Logger
	// Scheduler is optional. When set, the agent runs auto-sync per its
	// configuration and triggers an immediate sync after every unlock.
	Scheduler *Scheduler
}

// Server is the running agent. Construct with Listen.
type Server struct {
	cfg     Config
	paths   fdhome.Paths
	listener  net.Listener
	scheduler *Scheduler
	log       *slog.Logger

	mu           sync.Mutex
	superPriv    *crypto.Secret // 64 B Ed25519
	x25519Priv   *crypto.Secret // 32 B
	unlockKey    *crypto.Secret // 32 B K_unlock for the active wrap (used to derive payloadKey + AddWrap source)
	payloadKey   *crypto.Secret // 32 B stable across re-seals; needed by SaveBody/AddWrap/RemoveWrap
	unlockMID    string         // method_id of the active wrap
	unlockMType  string         // method_type of the active wrap
	unlockPP     []byte         // public_params of the active wrap
	userSuperPub []byte
	redactedBody []byte // cached cbor(VaultBody) with super_priv zeroed
	unlockedAt   time.Time
	lastReq      time.Time
}

// Listen creates ~/.fd0/agent.sock and accepts connections. The directory
// must already exist with mode 0700; we additionally chmod the socket to 0600.
func Listen(paths fdhome.Paths, cfg Config) (*Server, error) {
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.MaxLifetime == 0 {
		cfg.MaxLifetime = 8 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := paths.VerifyTight(); err != nil {
		return nil, err
	}
	// Refuse to start if another agent is already serving this home: the
	// previous behaviour silently rebound the socket, leaving the original
	// agent running but unreachable (orphan process holding super_priv
	// mlocked, plus duplicate-state confusion). Detect via PID file +
	// liveness check; only proceed if the prior agent is truly gone.
	if alive, oldPID := isPriorAgentAlive(paths.AgentPID); alive {
		return nil, fmt.Errorf("agent: already running as pid %d (delete %s if you're sure it's dead)", oldPID, paths.AgentPID)
	}
	// SECURITY (codex audit 🔴 server.go:82): if the PID file is
	// missing/corrupt/stale BUT an old agent is still listening
	// on the socket, the previous code would silently unlink the
	// socket and bind a new listener — orphaning the old agent
	// (still holding super_priv mlocked) AND starting a duplicate.
	// Probe the socket; fail if anything answers.
	if probeAgentSocket(paths.AgentSock) {
		return nil, fmt.Errorf("agent: another process is listening on %s but %s is missing/stale; remove the socket only if you're sure no agent is running",
			paths.AgentSock, paths.AgentPID)
	}
	// Stale socket from a crashed agent: safe to unlink (no listener).
	_ = os.Remove(paths.AgentSock)
	l, err := net.Listen("unix", paths.AgentSock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(paths.AgentSock, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	// SECURITY (codex audit 🟡 server.go:92): treat PID file write
	// failure as fatal. Without it, future agent invocations
	// can't detect we're running and may start duplicates (which
	// hits the orphan-agent bug above). Cleanup listener+socket
	// on failure so we don't leave them dangling.
	if err := os.WriteFile(paths.AgentPID, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		l.Close()
		_ = os.Remove(paths.AgentSock)
		return nil, fmt.Errorf("agent: write PID file %s: %w", paths.AgentPID, err)
	}
	s := &Server{
		cfg:       cfg,
		paths:     paths,
		listener:  l,
		scheduler: cfg.Scheduler,
		log:       cfg.Logger,
		lastReq:   time.Now(),
	}
	return s, nil
}

// Serve runs the accept loop. Returns when ctx is done or the listener fails.
func (s *Server) Serve(ctx context.Context) error {
	go s.lifecycleTimer(ctx)
	if s.scheduler != nil {
		go s.scheduler.Run(ctx)
	}
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

// Close stops accepting and zeroizes secrets.
func (s *Server) Close() {
	_ = s.listener.Close()
	_ = os.Remove(s.paths.AgentSock)
	_ = os.Remove(s.paths.AgentPID)
	s.lock()
}

// lifecycleTimer expires the unlocked state after idle/max-lifetime.
func (s *Server) lifecycleTimer(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			if s.superPriv == nil {
				s.mu.Unlock()
				continue
			}
			now := time.Now()
			idle := now.Sub(s.lastReq)
			alive := now.Sub(s.unlockedAt)
			s.mu.Unlock()
			if idle > s.cfg.IdleTimeout {
				s.log.Info("agent: idle timeout, locking")
				s.lock()
			}
			if alive > s.cfg.MaxLifetime {
				s.log.Info("agent: max lifetime, locking")
				s.lock()
			}
		}
	}
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	var req Request
	if err := ReadFrame(c, &req); err != nil {
		s.log.Debug("agent: read", "err", err)
		return
	}
	resp := s.dispatch(ctx, &req)
	_ = WriteFrame(c, resp)
}

func (s *Server) dispatch(ctx context.Context, req *Request) *Response {
	s.mu.Lock()
	s.lastReq = time.Now()
	s.mu.Unlock()
	switch req.Op {
	case OpStatus:
		return s.handleStatus()
	case OpUnlock:
		if req.Unlock == nil {
			return errResp("missing unlock body")
		}
		return s.handleUnlock(req.Unlock)
	case OpLock:
		s.lock()
		return &Response{}
	case OpSign:
		if req.Sign == nil {
			return errResp("missing sign body")
		}
		return s.handleSign(req.Sign)
	case OpOpenSeal:
		if req.OpenSeal == nil {
			return errResp("missing open_seal body")
		}
		return s.handleOpenSeal(req.OpenSeal)
	case OpReSeal:
		if req.ReSeal == nil {
			return errResp("missing re_seal body")
		}
		return s.handleReSeal(req.ReSeal)
	case OpGetBody:
		return s.handleGetBody()
	case OpRecoveryExport:
		if req.RecoveryExport == nil {
			return errResp("missing recovery_export body")
		}
		return s.handleRecoveryExport(req.RecoveryExport)
	case OpEncryptSuperPriv:
		if req.EncryptSuperPriv == nil {
			return errResp("missing encrypt_super_priv body")
		}
		return s.handleEncryptSuperPriv(req.EncryptSuperPriv)
	case OpAddWrap:
		if req.AddWrap == nil {
			return errResp("missing add_wrap body")
		}
		return s.handleAddWrap(req.AddWrap)
	case OpRemoveWrap:
		if req.RemoveWrap == nil {
			return errResp("missing remove_wrap body")
		}
		return s.handleRemoveWrap(req.RemoveWrap)
	default:
		return errResp(fmt.Sprintf("bad op %d", req.Op))
	}
}

func (s *Server) handleStatus() *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &StatusResp{Unlocked: s.superPriv != nil}
	if st.Unlocked {
		st.SinceUnix = s.unlockedAt.Unix()
		st.UserSuperPub = append([]byte(nil), s.userSuperPub...)
		st.ActiveMethodID = s.unlockMID
	}
	return &Response{Status: st}
}

func (s *Server) handleUnlock(u *UnlockReq) *Response {
	v, err := vault.Read(u.VaultPath)
	if err != nil {
		return errResp(err.Error())
	}
	var resolver vault.MethodResolver
	switch u.MethodType {
	case proto.AuthPassphrase:
		resolver = vault.PassphraseResolver{Passphrase: u.Passphrase}
	default:
		return errResp("unsupported method_type")
	}
	res, err := vault.Open(v, []vault.MethodResolver{resolver})
	if err != nil {
		return errResp(err.Error())
	}
	body := res.Body

	// SECURITY: rollback-detection (codex audit 🔴). The vault file
	// is mutable storage; the user.cbor chain is append-only and
	// every entry is signed. If an attacker rolls back vault.enc to
	// an older snapshot (e.g. one where a now-revoked credential
	// was still active), the older vault still decrypts cleanly and
	// the agent would otherwise cache super_priv under the revoked
	// credential. Compare body.AuthTip against the live chain tip;
	// mismatch ⇒ refuse.
	if u.UserChainPath != "" {
		st, rerr := chain.ReplayUser(u.UserChainPath)
		if rerr != nil {
			crypto.Wipe(res.UnlockKey)
			crypto.Wipe(res.PayloadKey)
			return errResp(fmt.Sprintf("vault: replay user chain for rollback check: %v", rerr))
		}
		// st == nil means "no user chain yet" (file missing or
		// empty). For a freshly-`init`'d vault this is fine; for a
		// vault that has gone through `auth add` etc, body.AuthTip
		// would be non-zero, and a missing chain is a rollback.
		var liveSeq uint64
		var liveHash []byte
		if st != nil {
			liveSeq = st.TipSeq
			liveHash = st.TipHash
		}
		// SECURITY (codex security audit 🟠 vault.go:253): legacy
		// vaults from before the AuthTip field was added decode
		// with AuthTip = zero (CBOR omits absent fields). If an
		// attacker rolls back to such a vault snapshot AND deletes
		// the user chain, the previous check would see (0, nil) ==
		// (0, nil) and unlock. Properly init'd modern vaults have
		// AuthTip.Hash == HashPrefix(genesis_event), which is
		// always exactly 32 bytes. Reject any vault whose AuthTip
		// hash is missing/short — it can't be a legitimately-
		// initialised v1 vault.
		if len(body.AuthTip.Hash) != 32 {
			crypto.Wipe(res.UnlockKey)
			crypto.Wipe(res.PayloadKey)
			return errResp(fmt.Sprintf(
				"vault: AuthTip.Hash is %d bytes (want 32) — possible legacy/rolled-back vault; refusing to unlock",
				len(body.AuthTip.Hash),
			))
		}
		if liveSeq != body.AuthTip.Seq || !bytes.Equal(liveHash, body.AuthTip.Hash) {
			crypto.Wipe(res.UnlockKey)
			crypto.Wipe(res.PayloadKey)
			return errResp(fmt.Sprintf(
				"vault: ROLLBACK DETECTED — vault auth_tip (seq=%d) does not match user chain tip (seq=%d); refusing to unlock with potentially revoked credentials",
				body.AuthTip.Seq, liveSeq,
			))
		}
	}

	if len(body.SuperPriv) != ed25519.PrivateKeySize {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp("vault body super_priv: bad length")
	}
	derivedPub := ed25519.PrivateKey(body.SuperPriv).Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPub, v.UserSuperPub) {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp("vault: super_priv pub != user_super_pub")
	}
	x, err := crypto.EdPrivToX25519(body.SuperPriv)
	if err != nil {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp(err.Error())
	}
	s.mu.Lock()
	if s.superPriv != nil {
		s.superPriv.Destroy()
	}
	if s.x25519Priv != nil {
		s.x25519Priv.Destroy()
	}
	if s.unlockKey != nil {
		s.unlockKey.Destroy()
	}
	if s.payloadKey != nil {
		s.payloadKey.Destroy()
	}
	s.superPriv = crypto.NewSecretCopy(body.SuperPriv)
	s.x25519Priv = crypto.NewSecret(x)
	s.unlockKey = crypto.NewSecret(res.UnlockKey) // takes ownership; wipes uk
	s.payloadKey = crypto.NewSecret(res.PayloadKey)
	s.unlockMID = res.UsedWrap.MethodID
	s.unlockMType = res.UsedWrap.MethodType
	s.unlockPP = append([]byte(nil), res.UsedWrap.PublicParams...)
	s.userSuperPub = append([]byte(nil), v.UserSuperPub...)
	s.unlockedAt = time.Now()
	// Build redacted body: same shape, super_priv replaced with zeros.
	redacted := *body
	redacted.SuperPriv = bytes.Repeat([]byte{0}, ed25519.PrivateKeySize)
	rb, err := proto.Marshal(redacted)
	if err != nil {
		s.mu.Unlock()
		return errResp(err.Error())
	}
	// SECURITY (codex audit 🟡 server.go:305): wipe any prior
	// redactedBody before overwriting. The "redacted" body still
	// contains OEKs and other sensitive scope data; repeated
	// unlocks would leave old buffers in heap memory until GC.
	if s.redactedBody != nil {
		crypto.Wipe(s.redactedBody)
	}
	s.redactedBody = rb
	s.mu.Unlock()
	// Zero the original body (best-effort; CBOR decode allocated copies).
	crypto.Wipe(body.SuperPriv)
	if s.scheduler != nil && s.scheduler.cfg.OnUnlock {
		go s.scheduler.TriggerSync("unlock")
	}
	return &Response{Unlock: &UnlockResp{
		RedactedBody: rb,
		UserSuperPub: append([]byte(nil), v.UserSuperPub...),
	}}
}

func (s *Server) handleSign(sr *SignReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil {
		return errResp("locked")
	}
	// Go's ed25519 internally caches expanded scalars via weak pointers,
	// which require GC-managed memory. memguard buffers are mlocked outside
	// the heap. Copy briefly, sign, wipe.
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(priv, s.superPriv.Bytes())
	defer crypto.Wipe(priv)
	// Wave C-3': SignBytes is the byte-slice boundary helper —
	// the agent's mlocked source is the trust anchor; the typed
	// Ed25519Priv path is for callers who hold the value across
	// multiple operations. SignBytes runs the length-gate then
	// hands to ed25519.Sign on a guaranteed-correct-length input.
	sig, err := crypto.SignBytes(priv, sr.Payload)
	if err != nil {
		return errResp("sign failed")
	}
	return &Response{Sign: &SignResp{Signature: sig}}
}

func (s *Server) handleOpenSeal(or *OpenSealReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.x25519Priv == nil {
		return errResp("locked")
	}
	// Same heap-vs-mlock concern as Sign: copy briefly.
	xPriv := make([]byte, 32)
	copy(xPriv, s.x25519Priv.Bytes())
	defer crypto.Wipe(xPriv)
	xPub, err := crypto.X25519Pub(xPriv)
	if err != nil {
		return errResp(err.Error())
	}
	plain, ok := crypto.OpenAnonymous(or.Sealed, xPub, xPriv)
	if !ok {
		return errResp("open_anonymous failed")
	}
	return &Response{OpenSeal: &OpenSealResp{Plain: plain}}
}

func (s *Server) handleReSeal(r *ReSealReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.payloadKey == nil {
		return errResp("locked")
	}
	body, err := s.unredact(r.RedactedBody)
	if err != nil {
		return errResp(err.Error())
	}
	defer crypto.Wipe(body.SuperPriv)
	pk := make([]byte, 32)
	copy(pk, s.payloadKey.Bytes())
	defer crypto.Wipe(pk)
	if err := vault.SaveBody(r.VaultPath, s.userSuperPub, body, pk); err != nil {
		return errResp(err.Error())
	}
	if s.redactedBody != nil {
		crypto.Wipe(s.redactedBody)
	}
	s.redactedBody = append([]byte(nil), r.RedactedBody...)
	return &Response{ReSeal: &ReSealResp{}}
}

// unredact rebuilds a VaultBody from the redacted CBOR + cached super_priv.
// Returns a body with super_priv populated; caller wipes after use.
func (s *Server) unredact(redactedBody []byte) (*proto.VaultBody, error) {
	var body proto.VaultBody
	if err := proto.Unmarshal(redactedBody, &body); err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}
	if !bytes.Equal(body.SuperPriv, bytes.Repeat([]byte{0}, ed25519.PrivateKeySize)) {
		return nil, errors.New("redacted_body: super_priv not zero-redacted")
	}
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(priv, s.superPriv.Bytes())
	body.SuperPriv = priv
	return &body, nil
}

// handleGetBody returns the cached redacted body. Caller must already have
// unlocked the vault.
//
// SECURITY NOTE. The redacted body still contains every OEK the user holds
// (one per subscribed scope, per OEK version). Same-UID-Code-Execution
// attackers can read these. This is acceptable in v1 because:
//   1. Same-UID attackers can equally call Sign/OpenSeal to recover OEKs by
//      simulating member.change replay.
//   2. THREATS.md §2 lists same-UID compromise as an acknowledged limit.
//   3. The agent's value-add is keeping super_priv (the master key) sealed;
//      OEK lifecycle is shorter (rotates on every member.change) and recovery
//      after compromise of an OEK era is supported by the protocol.
func (s *Server) handleGetBody() *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.redactedBody == nil {
		return errResp("locked")
	}
	return &Response{GetBody: &GetBodyResp{
		RedactedBody: append([]byte(nil), s.redactedBody...),
		UserSuperPub: append([]byte(nil), s.userSuperPub...),
	}}
}

// handleRecoveryExport AEAD-encrypts super_priv under the caller-supplied
// K_recovery. super_priv never leaves the agent in plaintext, but a
// same-UID caller CAN exfiltrate the current identity by supplying their
// own K_recovery and decrypting the response. This is consistent with the
// agent's documented same-UID trust boundary (THREATS.md §2: same-UID
// code execution); the user_super_pub check below only prevents export
// under a foreign identity, not exfiltration of the current one.
func (s *Server) handleRecoveryExport(r *RecoveryExportReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil {
		return errResp("locked")
	}
	if len(r.UnlockKey) != 32 || len(r.Nonce) != 12 || len(r.UserSuperPub) != 32 {
		return errResp("recovery_export: bad params")
	}
	if !bytes.Equal(r.UserSuperPub, s.userSuperPub) {
		return errResp("recovery_export: user_super_pub mismatch")
	}
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(priv, s.superPriv.Bytes())
	defer crypto.Wipe(priv)
	aad := append([]byte(proto.DomainRecoveryKey), r.UserSuperPub...)
	ct, err := crypto.AEADSeal(r.UnlockKey, r.Nonce, priv, aad)
	if err != nil {
		return errResp(err.Error())
	}
	return &Response{RecoveryExport: &RecoveryExportResp{Encrypted: ct}}
}

// handleEncryptSuperPriv produces an `encrypted_super_priv` blob (nonce ||
// AEAD-ciphertext) under K_unlock with the protocol AAD. Used by `fd0 auth
// add` to assemble the new AuthMethod for the next auth.set.
func (s *Server) handleEncryptSuperPriv(r *EncryptSuperPrivReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil {
		return errResp("locked")
	}
	if len(r.UnlockKey) != 32 {
		return errResp("encrypt_super_priv: bad K_unlock length")
	}
	if r.MethodID == "" {
		return errResp("encrypt_super_priv: empty method_id")
	}
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(priv, s.superPriv.Bytes())
	defer crypto.Wipe(priv)
	enc, err := vault.EncryptSuperPriv(priv, s.userSuperPub, r.MethodID, r.UnlockKey)
	if err != nil {
		return errResp(err.Error())
	}
	return &Response{EncryptSuperPriv: &EncryptSuperPrivResp{EncryptedSuperPriv: enc}}
}

// handleAddWrap encrypts the cached payload_key under the supplied K_unlock
// and appends the wrap to the on-disk vault. Body is re-encrypted (AAD
// covers the wraps array).
func (s *Server) handleAddWrap(r *AddWrapReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.payloadKey == nil {
		return errResp("locked")
	}
	if r.MethodID == "" || r.MethodType == "" || len(r.UnlockKey) != 32 {
		return errResp("add_wrap: missing method_id/method_type/unlock_key")
	}
	body, err := s.unredact(s.redactedBody)
	if err != nil {
		return errResp(err.Error())
	}
	defer crypto.Wipe(body.SuperPriv)
	pk := make([]byte, 32)
	copy(pk, s.payloadKey.Bytes())
	defer crypto.Wipe(pk)
	wrap := vault.WrapInput{
		MethodID:     r.MethodID,
		MethodType:   r.MethodType,
		PublicParams: r.PublicParams,
		UnlockKey:    r.UnlockKey,
	}
	if err := vault.AddWrap(r.VaultPath, s.userSuperPub, body, pk, wrap); err != nil {
		return errResp(err.Error())
	}
	return &Response{AddWrap: &AddWrapResp{}}
}

// handleRemoveWrap drops a wrap from the on-disk vault. Refuses to remove
// the currently-active wrap (would lock the agent out for future re-seals)
// and refuses to leave zero wraps.
func (s *Server) handleRemoveWrap(r *RemoveWrapReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.payloadKey == nil {
		return errResp("locked")
	}
	if r.MethodID == s.unlockMID {
		return errResp("remove_wrap: cannot remove the currently-active method (lock first, unlock with another method, then retry)")
	}
	body, err := s.unredact(s.redactedBody)
	if err != nil {
		return errResp(err.Error())
	}
	defer crypto.Wipe(body.SuperPriv)
	pk := make([]byte, 32)
	copy(pk, s.payloadKey.Bytes())
	defer crypto.Wipe(pk)
	if err := vault.RemoveWrap(r.VaultPath, s.userSuperPub, body, pk, r.MethodID); err != nil {
		return errResp(err.Error())
	}
	return &Response{RemoveWrap: &RemoveWrapResp{}}
}

// lock zeroizes super_priv, x25519_priv, and the cached body.
func (s *Server) lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv != nil {
		s.superPriv.Destroy()
		s.superPriv = nil
	}
	if s.x25519Priv != nil {
		s.x25519Priv.Destroy()
		s.x25519Priv = nil
	}
	if s.unlockKey != nil {
		s.unlockKey.Destroy()
		s.unlockKey = nil
	}
	if s.payloadKey != nil {
		s.payloadKey.Destroy()
		s.payloadKey = nil
	}
	if s.redactedBody != nil {
		crypto.Wipe(s.redactedBody)
		s.redactedBody = nil
	}
	s.unlockMID = ""
	s.unlockMType = ""
	s.unlockPP = nil
	s.userSuperPub = nil
	s.unlockedAt = time.Time{}
}

func errResp(msg string) *Response { return &Response{Err: msg} }

// SafeExit calls memguard.SafePanic on signals; the Stop helper calls Purge.
func SafeExit() { memguard.SafePanic(errors.New("agent SafeExit")) }

// isPriorAgentAlive reads the PID file (if any) and probes whether the
// recorded process is still around. We use signal 0 (no-op) to test
// liveness without disturbing the process. Returns (alive, pid).
//
// On any error (no file, bad content, foreign-owned PID) we conservatively
// return (false, 0) — the caller will then proceed and replace the socket.
// The worst-case behaviour is a brief duplicate-agent window during crash
// recovery, which is no worse than the previous unconditional behaviour.
func isPriorAgentAlive(pidPath string) (bool, int) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return false, 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return false, 0
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}
	// On Unix, FindProcess always succeeds; signal 0 is the liveness probe.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false, 0
	}
	return true, pid
}

// probeAgentSocket returns true iff something is currently listening
// on `path`. Used in Listen() to detect the bug-class where the PID
// file is missing/stale but an old agent is still serving requests
// — unlinking the socket then would orphan the old agent (still
// holding super_priv mlocked) and start a duplicate.
func probeAgentSocket(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
