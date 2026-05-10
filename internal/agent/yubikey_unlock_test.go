package agent

import (
	"errors"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// Adversarial coverage of the agent's YubiKey-unlock plumbing without
// any hardware. Each test injects a fake NewYubikeyResolver factory
// whose OpenSealed callback simulates a specific failure mode and
// asserts the agent's handleUnlock surfaces the right error.
//
// These tests don't go through the full RPC layer — they construct
// the resolver factory the way the agent would call it and exercise
// the code path that consumes UnlockReq.YubikeyPIN.

// fakeFactory builds a resolver whose OpenSealed always returns the
// caller-supplied (kunlock, err) tuple. expectedPub captures the pub
// the resolver sees so callers can assert it.
func fakeFactory(t *testing.T, kunlock []byte, err error) (func(pin []byte) vault.MethodResolver, *[]byte) {
	t.Helper()
	captured := new([]byte)
	return func(_ []byte) vault.MethodResolver {
		return vault.YubikeyResolver{
			OpenSealed: func(expectedPub, _ []byte) ([]byte, error) {
				*captured = append([]byte(nil), expectedPub...)
				if err != nil {
					return nil, err
				}
				return append([]byte(nil), kunlock...), nil
			},
		}
	}, captured
}

// The agent rejects yubikey unlocks when no factory is wired, with
// vault.ErrYubikeyNotConfigured. This is the build-without-yubikey
// path; the agent still loads, but yubikey methods can't unlock.
func TestAgentUnlock_YubikeyMethodWithoutFactory(t *testing.T) {
	t.Parallel()
	cfg := Config{} // no NewYubikeyResolver
	srv := &Server{cfg: cfg}
	resp := srv.handleUnlock(&UnlockReq{
		MethodType: proto.AuthYubikey,
		VaultPath:  "/dev/null",
		YubikeyPIN: []byte("123456"),
	})
	if resp == nil || resp.Err == "" {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if !strings.Contains(resp.Err, vault.ErrYubikeyNotConfigured.Error()) {
		t.Fatalf("error should match ErrYubikeyNotConfigured, got: %s", resp.Err)
	}
}

// Unsupported method types must be rejected with a clear message
// pointing at the offending method, not a generic "internal error".
func TestAgentUnlock_RejectsUnknownMethod(t *testing.T) {
	t.Parallel()
	srv := &Server{cfg: Config{}}
	resp := srv.handleUnlock(&UnlockReq{
		MethodType: "alien-method",
		VaultPath:  "/dev/null",
	})
	if resp == nil || resp.Err == "" {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if !strings.Contains(resp.Err, "alien-method") {
		t.Fatalf("error should name the bad method type, got: %s", resp.Err)
	}
}

// The agent must wipe the user-supplied PIN bytes after the resolver
// call returns. We can't observe wiped bytes through the API, but we
// can construct a resolver factory that aliases the PIN slice and
// then check post-call.
//
// Note: handleUnlock fails on the bogus VaultPath, but the deferred
// PIN wipe must still fire on the failure path.
func TestAgentUnlock_PINIsWipedAfterResolverCall(t *testing.T) {
	t.Parallel()
	pin := []byte("123456")
	cfg := Config{
		NewYubikeyResolver: func(p []byte) vault.MethodResolver {
			// Capture the slice header; the agent should wipe the
			// caller's slice (UnlockReq.YubikeyPIN) on the way out.
			return vault.YubikeyResolver{
				OpenSealed: func(_, _ []byte) ([]byte, error) {
					return nil, errors.New("forced failure")
				},
			}
		},
	}
	srv := &Server{cfg: cfg}
	_ = srv.handleUnlock(&UnlockReq{
		MethodType: proto.AuthYubikey,
		VaultPath:  "/nonexistent",
		YubikeyPIN: pin,
	})
	// After handleUnlock returns, the slice must be wiped (all-zero).
	for i, b := range pin {
		if b != 0 {
			t.Fatalf("PIN byte at index %d not wiped: 0x%02x", i, b)
		}
	}
}

// The fake-factory plumbing must thread expectedPub through unchanged.
// This is the precondition for the wrong-card check downstream.
func TestAgentUnlock_FakeFactory_ResolverArgsForwarded(t *testing.T) {
	t.Parallel()
	factory, captured := fakeFactory(t, []byte("01234567890123456789012345678901"), nil)
	r := factory([]byte("123456"))
	pp := proto.YubikeyPublicParams{
		X25519Pub:     []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		SealedKUnlock: []byte("sealed-bytes"),
		Slot:          0x9d,
	}
	ppBytes, err := proto.Marshal(pp)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = r.UnlockKey(ppBytes)
	if string(*captured) != string(pp.X25519Pub) {
		t.Fatalf("expectedPub not forwarded: got %x want %x", *captured, pp.X25519Pub)
	}
}
