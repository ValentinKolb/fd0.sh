package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func newLifecycleTestServer(t *testing.T, idle, maxLifetime time.Duration) *Server {
	t.Helper()
	now := time.Now()
	s := &Server{
		cfg:           Config{IdleTimeout: idle, MaxLifetime: maxLifetime},
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		superPriv:     crypto.NewSecretCopy(make([]byte, 64)),
		redactedBody:  []byte{0x01},
		userSuperPub:  make([]byte, 32),
		unlockedAt:    now,
		lastActivity:  now,
		lifecycleWake: make(chan struct{}, 1),
	}
	t.Cleanup(s.lock)
	return s
}

func isLifecycleTestServerLocked(s *Server) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.superPriv == nil
}

func TestPassiveAndRejectedRequestsDoNotRefreshIdle(t *testing.T) {
	s := newLifecycleTestServer(t, time.Hour, time.Hour)
	baseline := time.Now().Add(-10 * time.Minute)
	s.unlockedAt = baseline
	s.lastActivity = baseline

	tests := []struct {
		name    string
		request Request
		wantErr bool
	}{
		{name: "status", request: Request{Op: OpStatus}},
		{name: "unknown operation", request: Request{Op: 255}, wantErr: true},
		{name: "rejected protected operation", request: Request{Op: OpSign}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := s.lastActivity
			resp := s.dispatch(context.Background(), &tt.request)
			if (resp.Err != "") != tt.wantErr {
				t.Fatalf("response error = %q, wantErr %v", resp.Err, tt.wantErr)
			}
			if !s.lastActivity.Equal(before) {
				t.Fatalf("lastActivity changed from %v to %v", before, s.lastActivity)
			}
		})
	}
}

func TestSuccessfulProtectedRequestRefreshesIdle(t *testing.T) {
	s := newLifecycleTestServer(t, time.Hour, time.Hour)
	baseline := time.Now().Add(-10 * time.Minute)
	s.unlockedAt = baseline
	s.lastActivity = baseline

	resp := s.dispatch(context.Background(), &Request{Op: OpGetBody})
	if resp.Err != "" {
		t.Fatalf("get body: %s", resp.Err)
	}
	if !s.lastActivity.After(baseline) {
		t.Fatalf("lastActivity = %v, want after %v", s.lastActivity, baseline)
	}
}

func TestStatusReportsEffectiveLifecyclePolicy(t *testing.T) {
	s := newLifecycleTestServer(t, 5*time.Minute, 8*time.Hour)
	status := s.handleStatus().Status
	if status.IdleTimeoutMillis != (5 * time.Minute).Milliseconds() {
		t.Fatalf("idle timeout = %dms", status.IdleTimeoutMillis)
	}
	if status.MaxLifetimeMillis != (8 * time.Hour).Milliseconds() {
		t.Fatalf("max lifetime = %dms", status.MaxLifetimeMillis)
	}
}

func TestStatusLifecycleMetadataIsWireAdditive(t *testing.T) {
	type legacyStatus struct {
		Unlocked  bool  `cbor:"unlocked"`
		SinceUnix int64 `cbor:"since,omitempty"`
	}
	type legacyResponse struct {
		Status *legacyStatus `cbor:"status,omitempty"`
	}

	newWire, err := proto.Marshal(Response{Status: &StatusResp{
		Unlocked:          true,
		SinceUnix:         123,
		IdleTimeoutMillis: 300_000,
		MaxLifetimeMillis: 28_800_000,
	}})
	if err != nil {
		t.Fatal(err)
	}
	var legacy legacyResponse
	if err := proto.Unmarshal(newWire, &legacy); err != nil {
		t.Fatalf("legacy decode of new status: %v", err)
	}
	if legacy.Status == nil || !legacy.Status.Unlocked || legacy.Status.SinceUnix != 123 {
		t.Fatalf("legacy status = %+v", legacy.Status)
	}

	oldWire, err := proto.Marshal(legacyResponse{Status: &legacyStatus{Unlocked: true, SinceUnix: 456}})
	if err != nil {
		t.Fatal(err)
	}
	var current Response
	if err := proto.Unmarshal(oldWire, &current); err != nil {
		t.Fatalf("current decode of legacy status: %v", err)
	}
	if current.Status == nil || current.Status.IdleTimeoutMillis != 0 || current.Status.MaxLifetimeMillis != 0 {
		t.Fatalf("current status = %+v", current.Status)
	}
}

func TestListenRejectsNegativeLifecycleDurations(t *testing.T) {
	tests := []Config{
		{IdleTimeout: -time.Second},
		{MaxLifetime: -time.Second},
	}
	for _, cfg := range tests {
		if _, err := Listen(fdhome.Paths{}, cfg); err == nil {
			t.Fatalf("Listen accepted config %+v", cfg)
		}
	}
}

func TestLifecycleExpiration(t *testing.T) {
	now := time.Now()

	t.Run("before deadline", func(t *testing.T) {
		s := newLifecycleTestServer(t, 5*time.Minute, time.Hour)
		s.unlockedAt = now.Add(-30 * time.Minute)
		s.lastActivity = now.Add(-5*time.Minute + time.Millisecond)
		if reason := s.expireUnlocked(now); reason != "" {
			t.Fatalf("expired early: %s", reason)
		}
		if isLifecycleTestServerLocked(s) {
			t.Fatal("server locked before deadline")
		}
	})

	t.Run("idle deadline", func(t *testing.T) {
		s := newLifecycleTestServer(t, 5*time.Minute, time.Hour)
		s.unlockedAt = now.Add(-30 * time.Minute)
		s.lastActivity = now.Add(-5 * time.Minute)
		if reason := s.expireUnlocked(now); reason != "idle timeout" {
			t.Fatalf("reason = %q", reason)
		}
		if !isLifecycleTestServerLocked(s) {
			t.Fatal("server remained unlocked at idle deadline")
		}
	})

	t.Run("absolute max lifetime", func(t *testing.T) {
		s := newLifecycleTestServer(t, 5*time.Minute, time.Hour)
		s.unlockedAt = now.Add(-time.Hour)
		s.lastActivity = now
		if reason := s.expireUnlocked(now); reason != "max lifetime" {
			t.Fatalf("reason = %q", reason)
		}
		if !isLifecycleTestServerLocked(s) {
			t.Fatal("server remained unlocked at max lifetime")
		}
	})
}

func TestExpiredSessionCannotBeRevivedByRequest(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*Server)
	}{
		{
			name: "idle deadline",
			setup: func(s *Server) {
				s.lastActivity = time.Now().Add(-time.Second)
			},
		},
		{
			name: "max lifetime",
			setup: func(s *Server) {
				s.unlockedAt = time.Now().Add(-2 * time.Hour)
				s.lastActivity = time.Now()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newLifecycleTestServer(t, 10*time.Millisecond, time.Hour)
			tt.setup(s)
			resp := s.dispatch(context.Background(), &Request{Op: OpGetBody})
			if resp.Err != "locked" {
				t.Fatalf("response error = %q, want locked", resp.Err)
			}
			if !isLifecycleTestServerLocked(s) {
				t.Fatal("expired session was revived")
			}
			if !s.lastActivity.IsZero() {
				t.Fatalf("lastActivity = %v, want zero after lock", s.lastActivity)
			}
		})
	}
}

func TestActivityMovesIdleButNotMaxDeadline(t *testing.T) {
	s := newLifecycleTestServer(t, 5*time.Minute, time.Hour)
	base := time.Now()
	s.unlockedAt = base
	s.lastActivity = base

	s.markActivity(base.Add(4 * time.Minute))
	deadline, ok := s.nextLifecycleDeadline()
	if !ok || !deadline.Equal(base.Add(9*time.Minute)) {
		t.Fatalf("idle deadline = %v, ok=%v", deadline, ok)
	}

	s.markActivity(base.Add(59 * time.Minute))
	deadline, ok = s.nextLifecycleDeadline()
	if !ok || !deadline.Equal(base.Add(time.Hour)) {
		t.Fatalf("max deadline = %v, ok=%v", deadline, ok)
	}
}

func TestLifecycleTimerLocksAtDeadline(t *testing.T) {
	s := newLifecycleTestServer(t, 10*time.Millisecond, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.lifecycleTimer(ctx)

	deadline := time.Now().Add(time.Second)
	for !isLifecycleTestServerLocked(s) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !isLifecycleTestServerLocked(s) {
		t.Fatal("server did not lock at the idle deadline")
	}
}
