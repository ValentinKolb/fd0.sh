package proto

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// PROTOCOL.md §1.3:
//   Event ID  = "e_" + base32(truncate_128(SHA-256(prefix)))
//   Scope ID  = "s_" + base32(truncate_128(SHA-256(genesis_event_id)))
//   shortId   = 8 chars Crockford-base32 (server-assigned)
//
// Event/Scope IDs use lowercase RFC 4648 base32 (no padding) over 16 bytes
// (= 26 chars output, truncated; we keep 26 to avoid ambiguity).

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EventID returns "e_" + base32(SHA-256(prefix)[:16]).
// prefix is cbor(SignedPrefix) for scope events, cbor(UserEvent without sig)
// for user events.
func EventID(prefix []byte) string {
	sum := sha256.Sum256(prefix)
	return "e_" + strings.ToLower(b32.EncodeToString(sum[:16]))
}

// DeriveScopeID returns the scope id derived from a genesis event id
// per PROTOCOL.md §1.3. The returned value is a typed ScopeID — by
// construction it satisfies ValidScopeIDShape, so callers receiving
// it never need to re-validate.
func DeriveScopeID(genesisEventID string) ScopeID {
	sum := sha256.Sum256([]byte(genesisEventID))
	return ScopeID{s: "s_" + strings.ToLower(b32.EncodeToString(sum[:16]))}
}

// HashPrefix returns SHA-256(prefix). Used for prev_hash linking.
func HashPrefix(prefix []byte) [32]byte { return sha256.Sum256(prefix) }
