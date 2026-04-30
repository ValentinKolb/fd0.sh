package crypto

import (
	"crypto/subtle"

	"github.com/awnumar/memguard"
)

// Secret holds sensitive bytes (super_priv, OEKs, derived keys) in a memguard
// LockedBuffer. It is mlocked, excluded from core dumps, and zeroized on
// Destroy or finalisation.
//
// Best-effort: Go's runtime can still copy slices around. We minimise plain
// []byte exposure by accepting/returning Secret where possible.
type Secret struct {
	buf *memguard.LockedBuffer
}

// NewSecret takes ownership of plain (which is wiped) and returns a Secret.
func NewSecret(plain []byte) *Secret {
	if len(plain) == 0 {
		return &Secret{}
	}
	b := memguard.NewBufferFromBytes(plain) // wipes plain
	return &Secret{buf: b}
}

// NewSecretCopy copies plain into a Secret without modifying plain.
// Use when the caller still needs the value (e.g. it came from a CBOR struct).
func NewSecretCopy(plain []byte) *Secret {
	if len(plain) == 0 {
		return &Secret{}
	}
	b := memguard.NewBufferFromBytes(append([]byte(nil), plain...))
	return &Secret{buf: b}
}

// Bytes returns the underlying bytes. The slice aliases the locked buffer;
// do not retain it after Destroy.
func (s *Secret) Bytes() []byte {
	if s == nil || s.buf == nil {
		return nil
	}
	return s.buf.Bytes()
}

// Len returns the secret length.
func (s *Secret) Len() int {
	if s == nil || s.buf == nil {
		return 0
	}
	return s.buf.Size()
}

// Destroy zeroes and unlocks the buffer.
func (s *Secret) Destroy() {
	if s == nil || s.buf == nil {
		return
	}
	s.buf.Destroy()
	s.buf = nil
}

// Equal returns true iff a and b have identical contents (constant-time).
func (s *Secret) Equal(other []byte) bool {
	if s == nil || s.buf == nil {
		return len(other) == 0
	}
	return subtle.ConstantTimeCompare(s.buf.Bytes(), other) == 1
}

// Wipe zeroizes a []byte. Best-effort; the compiler may still keep copies.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
