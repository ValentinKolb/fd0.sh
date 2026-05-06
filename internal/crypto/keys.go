package crypto

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Wave C-3: opaque newtypes for Ed25519 identity keys.
//
// Motivation: ed25519.Sign panics on a wrong-size private key, and
// ed25519.Verify silently returns false (rather than the
// constant-time path) on wrong-size inputs. The stdlib types are
// `type PublicKey []byte` and `type PrivateKey []byte` — slice
// aliases that allow any length at construction. Past audit
// rounds caught two separate "decode raw bytes from CBOR, hand
// directly to Sign without a length check" patterns; the fix
// each time was a runtime length-guard at the call site.
//
// Wave C-3 makes the guarantee structural: an `Ed25519Pub` /
// `Ed25519Priv` value can only be obtained from ParseEd25519Pub /
// ParseEd25519Priv (both validate length) or from
// GenerateIdentity (correct by construction). Sign / Verify and
// the Signer interface accept the typed values; a raw []byte of
// the wrong length cannot reach the underlying stdlib call.
//
// WIRE FORMAT NOTE: pub/priv keys still ride []byte fields on the
// CBOR wire (PROTOCOL.md §1 — fixed-length byte strings). The
// proto package keeps `UserSuperPub []byte` etc. unchanged. The
// type-state lives at the API boundary: anywhere a key is
// CONSUMED for a cryptographic operation, the function takes a
// typed value, and the caller must have run ParseEd25519Pub on
// the wire bytes to get it.

// Ed25519Pub is a validated Ed25519 public key (32 bytes).
//
// Opaque struct rather than a named slice type so that
// `crypto.Ed25519Pub(rawBytes)` does not compile — construction
// must go through ParseEd25519Pub or MustParseEd25519Pub. The
// underlying slice is owned by this struct and not aliased to
// the input (deep-copied on construction) so post-construction
// mutation of the source bytes cannot retroactively change the
// key.
type Ed25519Pub struct {
	b []byte // owned, len == 32 by construction
}

// Ed25519Priv is a validated Ed25519 expanded private key (64
// bytes — seed[32] || public[32] per RFC 8032).
//
// Same opacity rationale as Ed25519Pub. Lifecycle: zero out
// before discard via Wipe() — the underlying slice is mlock'd by
// the agent in normal operation.
type Ed25519Priv struct {
	b []byte // owned, len == 64 by construction
}

// ParseEd25519Pub validates a 32-byte slice as an Ed25519 public
// key and wraps it in an Ed25519Pub. Returns an error on the
// wrong length so callers can surface the problem rather than
// crash in ed25519.Verify.
//
// THREAT: T10 (ed25519.Verify accepts wrong-size pub silently).
func ParseEd25519Pub(raw []byte) (Ed25519Pub, error) {
	if len(raw) != ed25519.PublicKeySize {
		return Ed25519Pub{}, fmt.Errorf("crypto: ed25519 pub: want %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, raw)
	return Ed25519Pub{b: out}, nil
}

// MustParseEd25519Pub panics on validation failure. Use only for
// values guaranteed valid by construction (test fixtures, freshly
// generated keys); never on operator-supplied input.
func MustParseEd25519Pub(raw []byte) Ed25519Pub {
	p, err := ParseEd25519Pub(raw)
	if err != nil {
		panic(err)
	}
	return p
}

// ParseEd25519Priv validates a 64-byte slice as an Ed25519
// expanded private key and wraps it in an Ed25519Priv.
//
// Codex Wave-C-3 review fix: also verify that the public-half
// (raw[32:]) matches the public key derived from the seed-half
// (raw[:32]). A 64-byte slice with inconsistent halves —
// corrupted recovery file, mis-spliced Yubikey blob, attacker-
// crafted "valid-length" priv — would otherwise wrap cleanly
// but produce signatures that fail every Verify call against
// `priv.Public()`. Reject up-front so the failure mode is a
// loud parse error, not silent signing-failure.
//
// THREAT: T09 (ed25519.Sign panics on wrong-size priv),
//         T11 (forged seed/public-half mismatch).
func ParseEd25519Priv(raw []byte) (Ed25519Priv, error) {
	if len(raw) != ed25519.PrivateKeySize {
		return Ed25519Priv{}, fmt.Errorf("crypto: ed25519 priv: want %d bytes, got %d", ed25519.PrivateKeySize, len(raw))
	}
	// Re-derive the public half from the seed and compare in
	// constant time. ed25519.NewKeyFromSeed re-hashes the seed,
	// which is the canonical derivation path.
	//
	// Codex Wave-C-3.1 review fix: NewKeyFromSeed returns a full
	// 64-byte expanded private key whose seed-half is identical
	// to raw[:32]. That temporary copy lives on the heap and
	// would persist past this function until GC; wipe it before
	// return so recovery imports / mlocked-key reparse paths
	// don't leak an extra heap-resident super_priv copy.
	derived := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	defer Wipe(derived)
	if !constantTimeEqual(derived[ed25519.SeedSize:], raw[ed25519.SeedSize:]) {
		return Ed25519Priv{}, errors.New("crypto: ed25519 priv: seed and public halves do not match (corrupted or forged key)")
	}
	out := make([]byte, ed25519.PrivateKeySize)
	copy(out, raw)
	return Ed25519Priv{b: out}, nil
}

// MustParseEd25519Priv panics on validation failure.
func MustParseEd25519Priv(raw []byte) Ed25519Priv {
	p, err := ParseEd25519Priv(raw)
	if err != nil {
		panic(err)
	}
	return p
}

// Bytes returns a copy of the underlying 32 bytes. Defensive
// against callers mutating the slice — the wrapper retains its
// invariant. CBOR / wire-format encoders consume these bytes.
func (p Ed25519Pub) Bytes() []byte {
	out := make([]byte, len(p.b))
	copy(out, p.b)
	return out
}

// Bytes returns a copy of the underlying 64 bytes. SECURITY: the
// caller now holds a copy of secret material; use only at the
// boundary where the bytes will be immediately handed to
// ed25519.Sign (through crypto.Sign) or wiped after use.
func (p Ed25519Priv) Bytes() []byte {
	out := make([]byte, len(p.b))
	copy(out, p.b)
	return out
}

// IsZero reports whether the value is the zero sentinel
// (Ed25519Pub{} / Ed25519Priv{}). Useful for absent-key checks.
func (p Ed25519Pub) IsZero() bool  { return len(p.b) == 0 }
func (p Ed25519Priv) IsZero() bool { return len(p.b) == 0 }

// Equal reports whether two pubs are byte-equal. Constant-time
// comparison via ed25519's standard library helper avoids leaking
// timing data on partial matches (relevant for the pin-mismatch
// branch in EnsurePinnedServer).
func (p Ed25519Pub) Equal(other Ed25519Pub) bool {
	if len(p.b) != len(other.b) {
		return false
	}
	// crypto.ConstantTimeCompare is the standard primitive.
	return constantTimeEqual(p.b, other.b)
}

// AsStdlib returns an ed25519.PublicKey view that aliases the
// internal slice. Unexported — only Sign / Verify in this
// package call it. Callers must NOT mutate.
func (p Ed25519Pub) asStdlib() ed25519.PublicKey { return ed25519.PublicKey(p.b) }

// asStdlib returns an ed25519.PrivateKey view that aliases the
// internal slice. Unexported — only Sign in this package calls
// it.
func (p Ed25519Priv) asStdlib() ed25519.PrivateKey { return ed25519.PrivateKey(p.b) }

// Public derives the public key from the expanded private key
// (the second half of the 64-byte form). Returns the typed value;
// callers don't need to know the layout.
func (p Ed25519Priv) Public() Ed25519Pub {
	if len(p.b) != ed25519.PrivateKeySize {
		// Should be unreachable for a value constructed via
		// ParseEd25519Priv, but degrade safely if someone
		// somehow obtained a zero-value Ed25519Priv.
		return Ed25519Pub{}
	}
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, p.b[ed25519.PublicKeySize:])
	return Ed25519Pub{b: out}
}

// Wipe zeroes the underlying secret bytes. Caller MUST ensure no
// further use of the value follows; subsequent Sign calls would
// fail with "zero-key" since the seal sentinel still says ok=true
// but the key material is all zeros (and ed25519.Sign would
// happily produce a signature for the seed `0^64`, which is a
// known-bad scalar — but no useful signature). For agent-mlock'd
// buffers, the agent should call Wipe in its shutdown path.
//
// Codex Wave-C-3 review fix: delegate to crypto.Wipe so the
// runtime.KeepAlive safeguard there protects against compiler
// dead-store elimination of the zeroing loop. A hand-rolled
// loop would be subject to the same optimisation hazard
// documented at Wipe's call site.
//
// THREAT: T07 (same-UID malware reads agent memory),
//         T12 (heap leak of priv after Wipe).
func (p Ed25519Priv) Wipe() {
	Wipe(p.b)
}

// constantTimeEqual: subtle-style byte-equal. Pulled to a free
// helper so we don't pull crypto/subtle into the broader package.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// errSignBadKey is returned by Sign when called with a zero-value
// Ed25519Priv (one that bypassed the ParseEd25519Priv constructor
// — e.g. a foreign-package composite literal). Defence in depth
// alongside the type-gate.
var errSignBadKey = errors.New("crypto: Sign called with zero-value Ed25519Priv")
