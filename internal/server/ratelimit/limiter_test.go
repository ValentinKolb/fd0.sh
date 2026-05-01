package ratelimit

import (
	"testing"
	"time"
)

// fakeClock lets tests advance time without sleeping.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time { return c.now }

func newTestLimiter(t *testing.T, cfg Config) (*Limiter, *fakeClock) {
	t.Helper()
	c := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	cfg.Now = c.Now
	// Pass nil ctx so the GC goroutine is not started; tests call gcOnce.
	return New(nil, cfg), c
}

func TestAcquireWriteAllowsBurstUpToCapacity(t *testing.T) {
	l, _ := newTestLimiter(t, Config{IdentityWritesPerMin: 5})
	for i := 0; i < 5; i++ {
		if d := l.AcquireWrite("alice"); !d.Allow {
			t.Fatalf("acquire %d: should allow within capacity, got Retry=%v", i, d.Retry)
		}
	}
	d := l.AcquireWrite("alice")
	if d.Allow {
		t.Fatal("6th acquire should be denied")
	}
	if d.Retry < time.Second {
		t.Fatalf("Retry should be at least 1s, got %v", d.Retry)
	}
}

func TestAcquireWriteRefillsOverTime(t *testing.T) {
	l, clk := newTestLimiter(t, Config{IdentityWritesPerMin: 60}) // 1/sec
	// Drain the bucket.
	for i := 0; i < 60; i++ {
		l.AcquireWrite("bob")
	}
	if d := l.AcquireWrite("bob"); d.Allow {
		t.Fatal("expected denial after draining")
	}
	// Advance 30s → 30 tokens back.
	clk.now = clk.now.Add(30 * time.Second)
	allowed := 0
	for i := 0; i < 100; i++ {
		if l.AcquireWrite("bob").Allow {
			allowed++
		}
	}
	// Allow some float drift but it should be very close to 30.
	if allowed < 28 || allowed > 31 {
		t.Fatalf("expected ~30 tokens after 30s refill, got %d", allowed)
	}
}

func TestSeparateIdentitiesAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(t, Config{IdentityWritesPerMin: 1})
	if d := l.AcquireWrite("alice"); !d.Allow {
		t.Fatal("alice first should pass")
	}
	if d := l.AcquireWrite("alice"); d.Allow {
		t.Fatal("alice second should fail")
	}
	// Bob is unaffected.
	if d := l.AcquireWrite("bob"); !d.Allow {
		t.Fatal("bob should be unaffected by alice's bucket")
	}
}

func TestAcquireBytesEnforcesByteBudget(t *testing.T) {
	l, _ := newTestLimiter(t, Config{IdentityBytesPerMin: 1024})
	if d := l.AcquireBytes("alice", 600); !d.Allow {
		t.Fatal("600 bytes within 1024 budget should pass")
	}
	if d := l.AcquireBytes("alice", 500); d.Allow {
		t.Fatal("500 more bytes (total 1100) should exceed 1024 budget")
	}
}

func TestAcquireBytesZeroIsNoop(t *testing.T) {
	l, _ := newTestLimiter(t, Config{IdentityBytesPerMin: 100})
	for i := 0; i < 100; i++ {
		if d := l.AcquireBytes("x", 0); !d.Allow {
			t.Fatalf("zero-byte acquire must always allow, iter %d", i)
		}
	}
}

func TestAcquireRegisterEnforcesPerHour(t *testing.T) {
	l, clk := newTestLimiter(t, Config{RegisterPerHour: 2})
	for i := 0; i < 2; i++ {
		if d := l.AcquireRegister("1.2.3.4"); !d.Allow {
			t.Fatalf("register %d: should pass within 2/h budget", i)
		}
	}
	if d := l.AcquireRegister("1.2.3.4"); d.Allow {
		t.Fatal("3rd register should fail")
	}
	// After half an hour we have 1 token back.
	clk.now = clk.now.Add(30 * time.Minute)
	if d := l.AcquireRegister("1.2.3.4"); !d.Allow {
		t.Fatal("should allow after 30min refill")
	}
	if d := l.AcquireRegister("1.2.3.4"); d.Allow {
		t.Fatal("only 1 token regenerated, second should fail")
	}
}

func TestNegativeLimitDisablesClass(t *testing.T) {
	l, _ := newTestLimiter(t, Config{IdentityWritesPerMin: -1, IdentityBytesPerMin: -1, RegisterPerHour: -1})
	for i := 0; i < 1000; i++ {
		if d := l.AcquireWrite("x"); !d.Allow {
			t.Fatal("negative writes-per-min should always allow")
		}
		if d := l.AcquireBytes("x", 1<<20); !d.Allow {
			t.Fatal("negative bytes should always allow")
		}
		if d := l.AcquireRegister("x"); !d.Allow {
			t.Fatal("negative register should always allow")
		}
	}
}

func TestGCDropsIdleBuckets(t *testing.T) {
	l, clk := newTestLimiter(t, Config{IdentityWritesPerMin: 5, IdleEvict: time.Minute})
	l.AcquireWrite("alice")
	l.AcquireWrite("bob")
	if l.Size() != 2 {
		t.Fatalf("expected 2 buckets, got %d", l.Size())
	}
	// Touch alice again 30s in.
	clk.now = clk.now.Add(30 * time.Second)
	l.AcquireWrite("alice")
	// 90s after start: bob is idle for 90s > 60s, alice for 60s <= 60s.
	clk.now = clk.now.Add(60 * time.Second)
	l.gcOnce()
	if l.Size() != 1 {
		t.Fatalf("expected only alice to survive GC, got %d buckets", l.Size())
	}
}

func TestRefillCapsAtCapacity(t *testing.T) {
	l, clk := newTestLimiter(t, Config{IdentityWritesPerMin: 10})
	// Touch then jump far ahead — bucket must not exceed capacity.
	l.AcquireWrite("x")
	clk.now = clk.now.Add(24 * time.Hour)
	allowed := 0
	for i := 0; i < 100; i++ {
		if l.AcquireWrite("x").Allow {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("after long gap, capacity must clamp at 10; got %d", allowed)
	}
}
