package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Adversarial coverage of YubikeyResolver.UnlockKey. None of these
// require hardware: the OpenSealed callback is a fake that lets us
// simulate every branch (no card, wrong card, PIN failure, garbage
// shared secret, length mismatch, ECDH refusal). Hardware is too
// expensive a test fixture for tail-of-distribution bugs.

const fakeKUnlockBytes = "01234567890123456789012345678901" // 32 bytes

func mkYubikeyParams(t *testing.T, pub32, sealed []byte) []byte {
	t.Helper()
	pp := proto.YubikeyPublicParams{X25519Pub: pub32, SealedKUnlock: sealed, Slot: 0x9d}
	out, err := proto.Marshal(pp)
	if err != nil {
		t.Fatalf("marshal YubikeyPublicParams: %v", err)
	}
	return out
}

func TestYubikeyResolver_NilOpenSealed_ReturnsSentinel(t *testing.T) {
	t.Parallel()
	r := YubikeyResolver{}
	pp := mkYubikeyParams(t, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 80))
	_, err := r.UnlockKey(pp)
	if !errors.Is(err, ErrYubikeyNotConfigured) {
		t.Fatalf("want ErrYubikeyNotConfigured, got %v", err)
	}
}

func TestYubikeyResolver_BadCBORPublicParams(t *testing.T) {
	t.Parallel()
	r := YubikeyResolver{
		OpenSealed: func(_, _ []byte) ([]byte, error) {
			t.Fatal("OpenSealed should not be called with malformed params")
			return nil, nil
		},
	}
	for _, name := range []string{"empty", "garbage", "truncated", "wrong-shape"} {
		var blob []byte
		switch name {
		case "empty":
			blob = nil
		case "garbage":
			blob = []byte{0xFF, 0xFF, 0xFF, 0xFF}
		case "truncated":
			full := mkYubikeyParams(t, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 80))
			blob = full[:len(full)/2]
		case "wrong-shape":
			// Valid CBOR but a different struct entirely.
			blob, _ = proto.Marshal(map[string]int{"version": 1})
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := r.UnlockKey(blob)
			if err == nil {
				t.Fatalf("expected error on %s public_params, got nil", name)
			}
		})
	}
}

func TestYubikeyResolver_RejectsBadX25519PubLen(t *testing.T) {
	t.Parallel()
	r := YubikeyResolver{
		OpenSealed: func(_, _ []byte) ([]byte, error) {
			t.Fatal("OpenSealed should not be called when X25519Pub length is wrong")
			return nil, nil
		},
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		t.Run("len="+itoa(n), func(t *testing.T) {
			t.Parallel()
			pp := mkYubikeyParams(t, bytes.Repeat([]byte{1}, n), bytes.Repeat([]byte{2}, 80))
			_, err := r.UnlockKey(pp)
			if err == nil {
				t.Fatalf("expected error on X25519Pub len=%d, got nil", n)
			}
			if !strings.Contains(err.Error(), "x25519_pub") {
				t.Fatalf("error should mention x25519_pub, got %v", err)
			}
		})
	}
}

func TestYubikeyResolver_RejectsEmptySealedKUnlock(t *testing.T) {
	t.Parallel()
	r := YubikeyResolver{
		OpenSealed: func(_, _ []byte) ([]byte, error) {
			t.Fatal("OpenSealed should not be called with empty SealedKUnlock")
			return nil, nil
		},
	}
	pp := mkYubikeyParams(t, bytes.Repeat([]byte{1}, 32), nil)
	_, err := r.UnlockKey(pp)
	if err == nil {
		t.Fatalf("expected error on empty SealedKUnlock, got nil")
	}
	if !strings.Contains(err.Error(), "missing sealed K_unlock") {
		t.Fatalf("error should describe missing sealed_k_unlock, got %v", err)
	}
}

// The resolver MUST forward expectedPub to the callback so a wrong-card
// situation can be caught BEFORE the callback runs ECDH. We don't run
// ECDH here; we just observe the argument.
func TestYubikeyResolver_PassesExpectedPubToOpenSealed(t *testing.T) {
	t.Parallel()
	wantPub := bytes.Repeat([]byte{0xAB}, 32)
	wantSealed := bytes.Repeat([]byte{0xCD}, 80)
	got := struct {
		expectedPub, sealed []byte
	}{}
	r := YubikeyResolver{
		OpenSealed: func(eph, sealed []byte) ([]byte, error) {
			got.expectedPub = append([]byte(nil), eph...)
			got.sealed = append([]byte(nil), sealed...)
			return []byte(fakeKUnlockBytes), nil
		},
	}
	pp := mkYubikeyParams(t, wantPub, wantSealed)
	_, err := r.UnlockKey(pp)
	if err != nil {
		t.Fatalf("UnlockKey: %v", err)
	}
	if !bytes.Equal(got.expectedPub, wantPub) {
		t.Fatalf("expectedPub forwarded incorrectly: got %x want %x", got.expectedPub, wantPub)
	}
	if !bytes.Equal(got.sealed, wantSealed) {
		t.Fatalf("sealed forwarded incorrectly: got %x want %x", got.sealed, wantSealed)
	}
}

func TestYubikeyResolver_PropagatesCallbackError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("card-broken-sentinel")
	r := YubikeyResolver{
		OpenSealed: func(_, _ []byte) ([]byte, error) { return nil, sentinel },
	}
	pp := mkYubikeyParams(t, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 80))
	_, err := r.UnlockKey(pp)
	if !errors.Is(err, sentinel) {
		t.Fatalf("error chain missing sentinel, got %v", err)
	}
}

func TestYubikeyResolver_RejectsBadKUnlockLen(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 31, 33, 64, 128} {
		t.Run("len="+itoa(n), func(t *testing.T) {
			t.Parallel()
			r := YubikeyResolver{
				OpenSealed: func(_, _ []byte) ([]byte, error) {
					return bytes.Repeat([]byte{0xEE}, n), nil
				},
			}
			pp := mkYubikeyParams(t, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 80))
			_, err := r.UnlockKey(pp)
			if err == nil {
				t.Fatalf("expected length-error for K_unlock len=%d, got nil", n)
			}
			if !strings.Contains(err.Error(), "32") {
				t.Fatalf("error should mention 32-byte requirement, got %v", err)
			}
		})
	}
}

// Successful path: callback returns 32 bytes; resolver returns them
// verbatim. Pins the happy-path contract so a future refactor that
// e.g. copies into a new buffer doesn't silently change behaviour.
func TestYubikeyResolver_HappyPath(t *testing.T) {
	t.Parallel()
	want := []byte(fakeKUnlockBytes)
	r := YubikeyResolver{
		OpenSealed: func(_, _ []byte) ([]byte, error) {
			return append([]byte(nil), want...), nil
		},
	}
	pp := mkYubikeyParams(t, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 80))
	got, err := r.UnlockKey(pp)
	if err != nil {
		t.Fatalf("UnlockKey: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("K_unlock mismatch: got %x want %x", got, want)
	}
}

// Trim helpers from strconv to avoid pulling in another dep here.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
