// Package sshkey handles SSH key material for fd0: in-house ed25519
// generation, OpenSSH key import (legacy formats accepted, only modern
// generation), and OpenSSH wire-format encoding of public keys.
//
// Why in-house keygen instead of shelling out to `ssh-keygen`:
//   - cross-platform (Windows doesn't always have ssh-keygen on PATH)
//   - no subprocess fork + temp-file leakage
//   - private key bytes stay in this process's memory, never touch disk
//   - deterministic audit trail: the bytes signed by fd0's translog are
//     exactly what this package emits.
//
// The wire format we emit for public keys is the OpenSSH
// `authorized_keys` line: `<algo> <base64(wire-key)> [<comment>]`. The
// private key is stored in the vault as a JSON struct (see Marshal /
// Unmarshal); we deliberately do NOT use OpenSSH's PEM private-key
// format on disk because the vault already handles encryption.
package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Type identifies a key algorithm in the JSON marshal form. New keys are
// always TypeEd25519; importers may accept the historical RSA / ECDSA
// shapes but they are tagged distinctly so the agent layer can refuse
// to sign with weak algorithms by policy.
type Type string

const (
	TypeEd25519 Type = "ssh-ed25519"
	TypeRSA     Type = "ssh-rsa"   // legacy import only
	TypeECDSA   Type = "ecdsa-sha2-nistp256" // legacy import only
)

// MinRSABits is the minimum modulus accepted on RSA import. Below this
// is refused — ssh-rsa with SHA-1 is deprecated as of OpenSSH 8.8 and
// 2048-bit moduli are no longer considered safe for long-lived keys.
const MinRSABits = 3072

// Key is the in-memory representation of an SSH key. Private is the
// raw algorithm-specific private material; Public is the OpenSSH
// public-key wire format ready to print into authorized_keys.
type Key struct {
	Type    Type
	Private []byte // algorithm-specific raw bytes (ed25519: 64-byte seed||pub)
	Public  []byte // ssh-encoded public key (`ssh.MarshalAuthorizedKey` minus comment)
	Comment string // free-form, defaults to `<name>@fd0`
}

// JSON is the wire shape stored as a fd0 secret value. The discriminator
// (`type`) lives in the JSON so a single `fd0 get <name>` can recover
// the full key without out-of-band metadata.
type JSON struct {
	Type    string `json:"type"`              // matches Type constants
	Priv    string `json:"priv"`              // base64(raw private material)
	Pub     string `json:"pub"`               // OpenSSH authorized_keys line (no comment, no newline)
	Comment string `json:"comment,omitempty"` // free-form
}

// NewEd25519 generates a fresh ed25519 keypair. The comment defaults to
// `<name>@fd0`; pass an empty string to fall back. The returned Key
// holds the 64-byte seed||pub private buffer that ed25519.Sign expects.
func NewEd25519(name, comment string) (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshkey: generate ed25519: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("sshkey: marshal ed25519 pub: %w", err)
	}
	pubLine := authorizedKeyLine(sshPub)
	if comment == "" {
		comment = name + "@fd0"
	}
	return &Key{
		Type:    TypeEd25519,
		Private: append([]byte(nil), priv...),
		Public:  pubLine,
		Comment: comment,
	}, nil
}

// ImportOpenSSH parses an OpenSSH-format private key (PEM-wrapped) and
// returns it as a Key. Encrypted keys are decrypted using passphrase;
// pass nil for unencrypted. RSA keys below MinRSABits are refused.
//
// We accept ed25519, RSA, and ECDSA on import for the migration story.
// We DO NOT accept DSA (cryptographically broken) or RSA shorter than
// MinRSABits — operators should rotate before storing those in fd0.
func ImportOpenSSH(pemBytes, passphrase []byte, name string) (*Key, error) {
	var (
		signer ssh.Signer
		err    error
	)
	if len(passphrase) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, passphrase)
	} else {
		signer, err = ssh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("sshkey: parse openssh: %w", err)
	}
	pub := signer.PublicKey()
	algo := pub.Type() // "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", ...
	switch algo {
	case "ssh-ed25519":
		// Reparse to extract the raw ed25519 priv (signer wraps it).
		// Pass the passphrase through — the earlier ssh.ParsePrivate
		// KeyWithPassphrase decrypted into a signer, but ParseRaw
		// keeps the raw bytes encrypted and needs the same key to
		// unwrap. Without this, encrypted ed25519 imports always hit
		// the "unable to extract raw key" fallback.
		var raw any
		var err error
		if len(passphrase) > 0 {
			raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
		} else {
			raw, err = ssh.ParseRawPrivateKey(pemBytes)
		}
		if err == nil {
			// ssh.ParseRawPrivateKey returns *ed25519.PrivateKey for
			// OpenSSH-format keys and ed25519.PrivateKey (value type)
			// for PKCS#8-format keys (the path crypto/x509 takes).
			// Handle both — the previous code missed the value case
			// and returned "unable to extract raw key" for any
			// `openssl genpkey -algorithm ed25519` output.
			var priv ed25519.PrivateKey
			switch r := raw.(type) {
			case *ed25519.PrivateKey:
				priv = *r
			case ed25519.PrivateKey:
				priv = r
			}
			if priv != nil {
				return &Key{
					Type:    TypeEd25519,
					Private: append([]byte(nil), priv...),
					Public:  authorizedKeyLine(pub),
					Comment: name + "@fd0",
				}, nil
			}
		}
		return nil, fmt.Errorf("sshkey: import ed25519: unable to extract raw key (err=%v)", err)
	case "ssh-rsa":
		// Refuse weak moduli. ssh.PublicKey's BitLen isn't directly
		// exposed; we read it off ssh.PublicKey via type assertion.
		if bits := rsaBitLen(pub); bits > 0 && bits < MinRSABits {
			return nil, fmt.Errorf("sshkey: rsa key has %d bits, minimum is %d", bits, MinRSABits)
		}
		// Refuse encrypted RSA imports. We previously stored the
		// encrypted PEM as-is, then Signer() re-parsed it without
		// passphrase — every later sign op would fail. Decrypting
		// here and writing an unencrypted PEM would change the
		// at-rest contract (vault then holds plaintext key material
		// instead of the operator's encrypted blob), so we surface
		// the limitation explicitly.
		if len(passphrase) > 0 || isEncryptedPEM(pemBytes) {
			return nil, errors.New("sshkey: encrypted RSA imports are not supported; decrypt first (ssh-keygen -p -N \"\" -f <file>) or rotate to ed25519")
		}
		return &Key{
			Type:    TypeRSA,
			Private: append([]byte(nil), pemBytes...),
			Public:  authorizedKeyLine(pub),
			Comment: name + "@fd0",
		}, nil
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		if len(passphrase) > 0 || isEncryptedPEM(pemBytes) {
			return nil, errors.New("sshkey: encrypted ECDSA imports are not supported; decrypt first or rotate to ed25519")
		}
		return &Key{
			Type:    TypeECDSA,
			Private: append([]byte(nil), pemBytes...),
			Public:  authorizedKeyLine(pub),
			Comment: name + "@fd0",
		}, nil
	case "ssh-dss":
		return nil, errors.New("sshkey: DSA keys are cryptographically broken; refusing")
	default:
		return nil, fmt.Errorf("sshkey: unsupported algorithm %q", algo)
	}
}

// Marshal serialises a Key for vault storage. Pub is the
// authorized_keys-format line without trailing newline; Priv is base64
// of the raw private bytes (ed25519: 64-byte seed||pub; RSA/ECDSA: the
// original PEM).
func (k *Key) Marshal() JSON {
	return JSON{
		Type:    string(k.Type),
		Priv:    base64.StdEncoding.EncodeToString(k.Private),
		Pub:     string(k.Public),
		Comment: k.Comment,
	}
}

// Unmarshal recovers a Key from its JSON form. Errors only on malformed
// base64 in Priv; everything else is best-effort tolerant so a vault
// holding an unknown future Type still round-trips harmlessly.
func Unmarshal(j JSON) (*Key, error) {
	priv, err := base64.StdEncoding.DecodeString(j.Priv)
	if err != nil {
		return nil, fmt.Errorf("sshkey: base64 priv: %w", err)
	}
	return &Key{
		Type:    Type(j.Type),
		Private: priv,
		Public:  []byte(j.Pub),
		Comment: j.Comment,
	}, nil
}

// Signer materialises a ssh.Signer from a Key. Ed25519 reconstructs
// directly from the 64-byte buffer; RSA / ECDSA re-parse the stored PEM
// (slower per call, but signing isn't a hot path — at most one sign per
// ssh handshake).
func (k *Key) Signer() (ssh.Signer, error) {
	switch k.Type {
	case TypeEd25519:
		if len(k.Private) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("sshkey: ed25519 priv has %d bytes, want %d",
				len(k.Private), ed25519.PrivateKeySize)
		}
		return ssh.NewSignerFromKey(ed25519.PrivateKey(k.Private))
	case TypeRSA, TypeECDSA:
		signer, err := ssh.ParsePrivateKey(k.Private)
		if err != nil {
			return nil, fmt.Errorf("sshkey: reparse %s pem: %w", k.Type, err)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("sshkey: cannot sign with type %q", k.Type)
	}
}

// PublicKey returns the ssh.PublicKey corresponding to k. Convenience
// wrapper around ssh.ParseAuthorizedKey on k.Public.
func (k *Key) PublicKey() (ssh.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(k.Public)
	return pub, err
}

// AuthorizedKeyLine returns the full authorized_keys-format line
// (with comment), suitable for direct append to a remote's
// ~/.ssh/authorized_keys.
func (k *Key) AuthorizedKeyLine() string {
	if k.Comment == "" {
		return string(k.Public)
	}
	return string(k.Public) + " " + k.Comment
}

// Fingerprint returns the OpenSSH SHA256 fingerprint of the public key,
// matching `ssh-keygen -lf` output (e.g. "SHA256:abcd..."). Used in
// CLI listings so users can verify out-of-band against `ssh-keyscan`.
func (k *Key) Fingerprint() string {
	pub, err := k.PublicKey()
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

// authorizedKeyLine returns just `<algo> <base64-wire>` — no comment, no
// trailing newline. We add the comment in AuthorizedKeyLine so the
// stored Public stays compact in the vault.
func authorizedKeyLine(pub ssh.PublicKey) []byte {
	line := ssh.MarshalAuthorizedKey(pub)
	// MarshalAuthorizedKey adds a trailing \n; strip it.
	line = []byte(strings.TrimRight(string(line), "\n"))
	return line
}

// isEncryptedPEM detects whether the supplied PEM block carries
// encryption. Used as a belt-and-braces check on RSA / ECDSA imports
// — if the caller forgot to pass --passphrase we'd otherwise store
// an encrypted blob that Signer() can't decrypt later.
//
// Detection is via the canonical PEM header (Proc-Type: 4,ENCRYPTED
// for legacy PKCS#1) — substring matching the raw bytes would false-
// positive on user comments and false-negative on OpenSSH-format
// encrypted keys. For OpenSSH-format we rely on the fact that the
// ssh.ParsePrivateKey call earlier in the import path returns a
// `*ssh.PassphraseMissingError` when encryption is present — that's
// the with-passphrase signal the caller already passed through.
func isEncryptedPEM(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	if pt := block.Headers["Proc-Type"]; pt != "" && strings.Contains(pt, "ENCRYPTED") {
		return true
	}
	// "BEGIN ENCRYPTED PRIVATE KEY" (PKCS#8 encrypted) — pem.Decode
	// surfaces this as the block Type.
	return strings.Contains(block.Type, "ENCRYPTED")
}

// rsaBitLen extracts the modulus bit length from a ssh.PublicKey known
// to be ssh-rsa. Returns 0 if the assertion fails (caller skips the
// check on unknown shapes — preferring "weird key parses but we don't
// know its size" over "we crash on import").
func rsaBitLen(pub ssh.PublicKey) int {
	if cp, ok := pub.(ssh.CryptoPublicKey); ok {
		if r, ok := cp.CryptoPublicKey().(interface{ Size() int }); ok {
			return r.Size() * 8
		}
	}
	return 0
}
