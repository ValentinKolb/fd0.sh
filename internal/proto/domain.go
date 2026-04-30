// Package proto defines fd0's wire format: CBOR schemas, domain separators,
// and hashing helpers shared by client, agent, and server.
//
// Every value used as input to Ed25519 signing or AEAD AAD is prefixed with
// one of the domain separators below. A signature or ciphertext valid under
// one domain MUST be invalid under any other (PROTOCOL.md §1.1).
package proto

// Domain separators. See PROTOCOL.md §1.1.
const (
	DomainEvent              = "fd0-event-v1"                // scope event signatures
	DomainUserEvent          = "fd0-user-event-v1"           // user identity event signatures
	DomainCard               = "fd0-card-v1"                 // identity card signatures
	DomainHTTP               = "fd0-http-request-v1"         // per-request HTTP auth
	DomainEncryptedSuperPriv = "fd0-encrypted-super-priv-v1" // AAD: auth-method ciphertext
	DomainVaultBody          = "fd0-vault-body-v1"           // AAD: vault body
	DomainVaultWrap          = "fd0-vault-wrap-v1"           // AAD: vault wrapped key
	DomainRecoveryKey        = "fd0-recovery-key-v1"         // AAD: recovery export
	DomainSafety             = "fd0-safety-v1"               // safety-number derivation prefix
)

// Magic strings for on-disk file headers.
const (
	VaultMagic    = "FD0V"
	RecoveryMagic = "FD0K"
)

// Event kinds.
const (
	KindAuthSet      = "auth.set"
	KindMemberChange = "member.change"
	KindSecretSet    = "secret.set"
)

// member.change ops.
const (
	OpAdd    = "add"
	OpRemove = "remove"
)

// AuthMethod types.
const (
	AuthPassphrase = "passphrase"
	AuthYubikey    = "yubikey"
)
