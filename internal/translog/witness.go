package translog

import (
	"crypto/ed25519"
	"errors"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// WitnessedSTH is a server STH that a witness has independently
// observed and cosigned. Wire format follows TRANSLOG.md §10.
//
// The witness signature attests "I, the holder of WitnessPub, observed
// this exact STH being served from ServerURL". A cosign for one
// (server, chain, size) cannot be replayed against another server
// because ServerURL is part of the signed input.
//
// Clients that have pinned a witness pubkey use this to cross-check
// the server: if the witnessed STH at a given tree_size has a
// different root_hash than the server-provided STH, the server has
// equivocated.
type WitnessedSTH struct {
	STH        STH    `cbor:"sth"`         // the server STH the witness saw
	ServerURL  string `cbor:"server_url"`  // which server it came from
	WitnessPub []byte `cbor:"witness_pub"` // ed25519 pubkey of the witness
	WitnessSig []byte `cbor:"witness_sig"` // ed25519 sig over SignedInput
}

// witnessSignedPrefix is the in-memory shape that gets CBOR-encoded
// into the witness signature input. We keep it separate from the
// public WitnessedSTH struct so signature inputs never accidentally
// pick up the witness sig itself or any future fields added to
// WitnessedSTH.
type witnessSignedPrefix struct {
	STH       STH    `cbor:"sth"`
	ServerURL string `cbor:"server_url"`
}

// SignedInput returns the bytes a witness signs (and a verifier
// reconstructs) when cosigning an STH:
//
//	"fd0-witness-cosign-v1" || cbor({sth, server_url})
//
// CBOR is deterministic per RFC 8949 §4.2.1 so witness and verifier
// agree byte-for-byte without negotiating an encoding.
func (w *WitnessedSTH) SignedInput() ([]byte, error) {
	body, err := proto.Marshal(witnessSignedPrefix{STH: w.STH, ServerURL: w.ServerURL})
	if err != nil {
		return nil, err
	}
	return append([]byte(proto.DomainWitnessCosign), body...), nil
}

// SignWitnessedSTH constructs and signs a WitnessedSTH using `priv`.
// The returned value is wire-ready. The witness's pubkey is embedded
// so a verifier can correlate the cosign to a configured pin without
// extra lookups.
//
// The function does NOT verify the embedded server STH — the caller
// (the witness poll loop) is expected to have run VerifySTH already.
// SignWitnessedSTH is purely the cosigning step.
func SignWitnessedSTH(priv ed25519.PrivateKey, sth STH, serverURL string) (WitnessedSTH, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return WitnessedSTH{}, errors.New("translog.SignWitnessedSTH: priv must be 64 bytes")
	}
	if serverURL == "" {
		return WitnessedSTH{}, errors.New("translog.SignWitnessedSTH: serverURL must not be empty")
	}
	w := WitnessedSTH{
		STH:        sth,
		ServerURL:  serverURL,
		WitnessPub: priv.Public().(ed25519.PublicKey),
	}
	si, err := w.SignedInput()
	if err != nil {
		return WitnessedSTH{}, err
	}
	w.WitnessSig = ed25519.Sign(priv, si)
	return w, nil
}

// ErrWitnessBadCosign is returned when a WitnessedSTH fails verification
// (signature, embedded pubkey mismatch, or pin mismatch).
var ErrWitnessBadCosign = errors.New("translog: bad witness cosign")

// VerifyWitnessedSTH checks a WitnessedSTH against a pinned witness
// pubkey AND validates the embedded server STH against the pinned
// server pubkey. Both checks are bundled — a caller that verified one
// without the other could be tricked into trusting a witness's
// signature on a server STH the witness never actually saw.
//
// The caller MUST pass the expected ServerURL AND the expected
// ChainID. Mismatches on either field are rejected (a witness
// cosign for chain X@server Y is not transferable to chain X'@Y or
// X@Y'). The chain check is mandatory here because the cosign signs
// the STH (which embeds chain_id) but does NOT separately sign the
// expected chain — without an outer check, a cosign for a sibling
// chain on the same server with the same (size, root) could be
// replayed (codex fix #4).
//
// On any failure the function returns ErrWitnessBadCosign or the
// underlying STH-validation error from VerifySTH.
func VerifyWitnessedSTH(serverPub ed25519.PublicKey, witnessPubPin ed25519.PublicKey, expectedServerURL, expectedChainID string, w WitnessedSTH) error {
	if len(witnessPubPin) != ed25519.PublicKeySize {
		return errors.New("translog.VerifyWitnessedSTH: witness pin must be 32 bytes")
	}
	if expectedServerURL == "" {
		return errors.New("translog.VerifyWitnessedSTH: expectedServerURL must not be empty")
	}
	if expectedChainID == "" {
		return errors.New("translog.VerifyWitnessedSTH: expectedChainID must not be empty")
	}
	if w.ServerURL != expectedServerURL {
		return ErrWitnessBadCosign
	}
	if w.STH.Head.ChainID != expectedChainID {
		return ErrWitnessBadCosign
	}
	if len(w.WitnessPub) != ed25519.PublicKeySize {
		return ErrWitnessBadCosign
	}
	if !equalBytes(w.WitnessPub, witnessPubPin) {
		return ErrWitnessBadCosign
	}
	if len(w.WitnessSig) != ed25519.SignatureSize {
		return ErrWitnessBadCosign
	}
	if err := VerifySTH(serverPub, w.STH); err != nil {
		return err
	}
	si, err := w.SignedInput()
	if err != nil {
		return err
	}
	if !ed25519.Verify(witnessPubPin, si, w.WitnessSig) {
		return ErrWitnessBadCosign
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
