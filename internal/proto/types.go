package proto

// CBOR struct shapes for events, identity cards, vault, and recovery files.
//
// Field tags use `cbor:"<name>,keyasint?"`. We use string keys throughout to
// match the CDDL in PROTOCOL.md exactly. Determinism is enforced by the
// encoder mode (CoreDetEncOptions sorts map keys bytewise-lexically).

// ---- User identity chain (PROTOCOL.md §3) ----

// UserEvent is one entry in the user identity chain. Kind is always "auth.set".
type UserEvent struct {
	Kind         string         `cbor:"kind"`
	Seq          uint64         `cbor:"seq"`
	PrevHash     []byte         `cbor:"prev_hash"` // nil iff seq=0
	UserSuperPub []byte         `cbor:"user_super_pub"`
	Payload      AuthSetPayload `cbor:"payload"`
	Signature    []byte         `cbor:"signature"`
}

// userEventSigned is UserEvent without the signature field; signed_input is
// "fd0-user-event-v1" || cbor(userEventSigned).
type userEventSigned struct {
	Kind         string         `cbor:"kind"`
	Seq          uint64         `cbor:"seq"`
	PrevHash     []byte         `cbor:"prev_hash"`
	UserSuperPub []byte         `cbor:"user_super_pub"`
	Payload      AuthSetPayload `cbor:"payload"`
}

// AuthSetPayload is the payload of an auth.set event.
type AuthSetPayload struct {
	Active []AuthMethod `cbor:"active"`
}

// AuthMethod is one credential by which super_priv can be unwrapped.
type AuthMethod struct {
	MethodID           string `cbor:"method_id"`
	MethodType         string `cbor:"method_type"`
	PublicParams       []byte `cbor:"public_params"`
	EncryptedSuperPriv []byte `cbor:"encrypted_super_priv"`
}

// SignedInput returns "fd0-user-event-v1" || cbor(UserEvent without signature).
func (e *UserEvent) SignedInput() ([]byte, error) {
	body, err := Marshal(userEventSigned{
		Kind: e.Kind, Seq: e.Seq, PrevHash: e.PrevHash,
		UserSuperPub: e.UserSuperPub, Payload: e.Payload,
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(DomainUserEvent), body...), nil
}

// PrevHashInput returns cbor(UserEvent without signature) — the input hashed
// to produce the next event's prev_hash.
func (e *UserEvent) PrevHashInput() ([]byte, error) {
	return Marshal(userEventSigned{
		Kind: e.Kind, Seq: e.Seq, PrevHash: e.PrevHash,
		UserSuperPub: e.UserSuperPub, Payload: e.Payload,
	})
}

// ---- Scope event chain (PROTOCOL.md §4) ----

// ScopeEvent is the wire form of every scope event.
type ScopeEvent struct {
	SignedPrefix SignedPrefix `cbor:"signed_prefix"`
	Signature    Signature    `cbor:"signature"`
}

// SignedPrefix is the part of a ScopeEvent covered by the signature and by
// the prev_hash chain. Per-kind payload lives under Payload.
//
// Scope is *string so genesis encodes as CBOR null (0xf6) per PROTOCOL.md
// §4.1 (`scope: tstr / nil, nil iff genesis`); a non-genesis event uses a
// non-nil pointer so CBOR emits a definite text-string. PrevHash uses the
// same nil-vs-bytes distinction implicitly: nil []byte is CBOR null.
type SignedPrefix struct {
	Kind          string        `cbor:"kind"`
	Scope         *string       `cbor:"scope"`
	PrevHash      []byte        `cbor:"prev_hash"`
	Author        []byte        `cbor:"author"`
	Seq           uint64        `cbor:"seq"`
	OEKVersion    uint64        `cbor:"oek_version"`
	KeyDeliveries []KeyDelivery `cbor:"key_deliveries"`
	Payload       Payload       `cbor:"payload"`
}

// ScopePtr returns a *string pointer wrapping s. Used by event builders.
func ScopePtr(s string) *string { return &s }

// Payload is a sum of member.change and secret.set payloads. Both fields are
// "omitempty" so the wire form has exactly one populated key per kind.
type Payload struct {
	// member.change
	Op            string `cbor:"op,omitempty"`
	Member        []byte `cbor:"member,omitempty"`
	EncProjection []byte `cbor:"enc_projection,omitempty"`
	// secret.set
	EncBody []byte `cbor:"enc_body,omitempty"`
}

// KeyDelivery is one sealed-box copy of the OEK to one recipient.
type KeyDelivery struct {
	RecipientPubkey []byte `cbor:"recipient_pubkey"`
	Sealed          []byte `cbor:"sealed"`
}

// Signature carries the signing key alongside the signature so verifiers can
// match the embedded key against author and against the scope's auth_list.
type Signature struct {
	SignerPubkey []byte `cbor:"signer_pubkey"`
	Signature    []byte `cbor:"signature"`
}

// SignedInput returns "fd0-event-v1" || cbor(SignedPrefix).
func (e *ScopeEvent) SignedInput() ([]byte, error) {
	body, err := Marshal(e.SignedPrefix)
	if err != nil {
		return nil, err
	}
	return append([]byte(DomainEvent), body...), nil
}

// PrevHashInput returns cbor(SignedPrefix) — input hashed for next prev_hash.
func (e *ScopeEvent) PrevHashInput() ([]byte, error) { return Marshal(e.SignedPrefix) }

// ---- Plaintext bodies ----

// MemberProjection is the plaintext of a member.change enc_projection.
// It is the full set of current SecretRecords at this seq.
type MemberProjection struct {
	Secrets []SecretInProjection `cbor:"secrets"`
}

// SecretInProjection carries the secret id alongside its record so a new
// member receives a complete map on join.
type SecretInProjection struct {
	ID     string        `cbor:"id"`
	Record *SecretRecord `cbor:"record"`
}

// SecretBody is the plaintext of a secret.set enc_body.
type SecretBody struct {
	ID     string        `cbor:"id"`
	Record *SecretRecord `cbor:"record"` // nil = tombstone
}

// SecretRecord is the user-facing record stored under a secret id.
type SecretRecord struct {
	Name          string            `cbor:"name"`
	Type          string            `cbor:"type"`
	SchemaVersion uint64            `cbor:"schema_version"`
	Payload       any               `cbor:"payload"`
	Tags          map[string]string `cbor:"tags"`
}

// ---- Identity card (PROTOCOL.md §2.3) ----

// IdentityCard is the small CBOR-then-base64url document users exchange to
// pin each other's super_pub.
type IdentityCard struct {
	Version   uint8  `cbor:"version"`
	ShortID   string `cbor:"shortId"`
	SuperPub  []byte `cbor:"super_pub"`
	IssuedAt  uint64 `cbor:"issued_at"`
	ExpiresAt uint64 `cbor:"expires_at"`
	Signature []byte `cbor:"signature"`
}

type identityCardSigned struct {
	Version   uint8  `cbor:"version"`
	ShortID   string `cbor:"shortId"`
	SuperPub  []byte `cbor:"super_pub"`
	IssuedAt  uint64 `cbor:"issued_at"`
	ExpiresAt uint64 `cbor:"expires_at"`
}

// SignedInput returns "fd0-card-v1" || cbor(card without signature).
func (c *IdentityCard) SignedInput() ([]byte, error) {
	body, err := Marshal(identityCardSigned{
		Version: c.Version, ShortID: c.ShortID, SuperPub: c.SuperPub,
		IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(DomainCard), body...), nil
}

// ---- Vault (PROTOCOL.md §6.1) ----

// VaultFile is the encrypted vault on disk. Body is decrypted into VaultBody.
type VaultFile struct {
	Magic              string       `cbor:"magic"`
	Version            uint8        `cbor:"version"`
	UserSuperPub       []byte       `cbor:"user_super_pub"`
	WrappedPayloadKeys []WrappedKey `cbor:"wrapped_payload_keys"`
	BodyNonce          []byte       `cbor:"body_nonce"`
	Body               []byte       `cbor:"body"`
}

// VaultFileHeader is VaultFile minus body; used as part of the body AAD.
type VaultFileHeader struct {
	Magic              string       `cbor:"magic"`
	Version            uint8        `cbor:"version"`
	UserSuperPub       []byte       `cbor:"user_super_pub"`
	WrappedPayloadKeys []WrappedKey `cbor:"wrapped_payload_keys"`
	BodyNonce          []byte       `cbor:"body_nonce"`
}

// WrappedKey is one unlock entry: payload_key wrapped under one auth method.
type WrappedKey struct {
	MethodID     string `cbor:"method_id"`
	MethodType   string `cbor:"method_type"`
	PublicParams []byte `cbor:"public_params"`
	WrapNonce    []byte `cbor:"wrap_nonce"`
	Wrapped      []byte `cbor:"wrapped"`
}

// WrappedKeyHeader is WrappedKey minus wrapped; used as part of the wrap AAD.
type WrappedKeyHeader struct {
	MethodID     string `cbor:"method_id"`
	MethodType   string `cbor:"method_type"`
	PublicParams []byte `cbor:"public_params"`
	WrapNonce    []byte `cbor:"wrap_nonce"`
}

// VaultBody is the plaintext that lives inside VaultFile.Body.
type VaultBody struct {
	SuperPriv        []byte                    `cbor:"super_priv"`
	AuthTip          ChainTip                  `cbor:"auth_tip"`
	Scopes           map[string]ScopeVaultData `cbor:"scopes"`
	PinnedIdentities map[string]PinnedIdentity `cbor:"pinned_identities"`
}

// ScopeVaultData holds the OEK lineage and the latest accepted chain tip for
// one scope this client is a member of. Label is a local-only convenience
// (never sent to the server / never part of any signed input).
type ScopeVaultData struct {
	Label    string     `cbor:"label,omitempty"`
	OEKs     []OEKEntry `cbor:"oeks"`
	ChainTip ChainTip   `cbor:"chain_tip"`
}

// OEKEntry is one (version, key) pair.
type OEKEntry struct {
	Version uint64 `cbor:"version"`
	Key     []byte `cbor:"key"`
}

// ChainTip is the latest seq+hash this client has accepted on a chain.
type ChainTip struct {
	Seq  uint64 `cbor:"seq"`
	Hash []byte `cbor:"hash"`
}

// PinnedIdentity is a peer the user has imported via identity card.
type PinnedIdentity struct {
	SuperPub []byte `cbor:"super_pub"`
	Label    string `cbor:"label"`
}

// ---- Recovery export (PROTOCOL.md §6.3) ----

// RecoveryFile is the offline-stored super_priv backup.
type RecoveryFile struct {
	Magic              string        `cbor:"magic"`
	Version            uint8         `cbor:"version"`
	UserSuperPub       []byte        `cbor:"user_super_pub"`
	Salt               []byte        `cbor:"salt"`
	Argon2Params       Argon2Params  `cbor:"argon2_params"`
	Nonce              []byte        `cbor:"nonce"`
	EncryptedSuperPriv []byte        `cbor:"encrypted_super_priv"`
}

// Argon2Params are the cost parameters used for passphrase-derived keys.
type Argon2Params struct {
	M uint32 `cbor:"m"` // memory in KiB
	T uint32 `cbor:"t"` // iterations
	P uint8  `cbor:"p"` // parallelism
}
