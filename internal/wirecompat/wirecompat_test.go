// Package wirecompat holds golden-file tests that pin the on-disk
// wire format. The point: any future change to vault.enc / chain
// CBOR layout, vault wrap construction, AAD inputs, or replay
// semantics will fail these tests if the change isn't backwards
// compatible with the committed snapshot.
//
// Two modes:
//
//   1. VERIFY (default `go test ./internal/wirecompat`): reads the
//      committed snapshot from testdata/v1/, decodes it through the
//      production APIs (vault.Read+Open, chain.ReplayUser,
//      chain.ReplayScope), and asserts a fixed set of properties.
//      A wire-format break shows up here as a decode/replay error
//      or a property mismatch.
//
//   2. REGENERATE (`WIRE_COMPAT_REGEN=1 go test
//      ./internal/wirecompat -run TestWireCompatV1Regenerate`):
//      writes a fresh snapshot using the current code. Run when an
//      INTENTIONAL wire-format bump lands; commit the new
//      testdata/ contents and bump the version directory
//      (testdata/v2/...).
//
// The snapshot uses fixed seeds for keys + a fixed passphrase
// "fd0-wire-compat-v1" so the generation is repeatable across
// hosts (modulo the random nonces / OEK in AEAD wraps, which the
// verify test doesn't depend on byte-for-byte — only on
// "decrypts cleanly").
package wirecompat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// snapshotV1 is the parameter set for the v1 golden snapshot. Any
// change to these constants requires a new testdata/vN/ directory.
const (
	snapshotPassphrase = "fd0-wire-compat-v1"
	snapshotMethodID   = "am_compatv1aaaaaaaaaaaaaaaaaaa"
	snapshotLabel      = "compat-test-scope"
	snapshotSecretName = "API_KEY"
	snapshotSecretValN = "compat-v1-payload-stable-bytes"
)

// ----- VERIFY -----

func TestWireCompatV1Verify(t *testing.T) {
	dir := filepath.Join("testdata", "v1")
	if _, err := os.Stat(filepath.Join(dir, "vault.enc")); err != nil {
		t.Skipf("snapshot not present at %s — run TestWireCompatV1Regenerate first: %v", dir, err)
	}

	// Open vault.enc with the fixed passphrase. A wire-format
	// break (CBOR layout, magic, version, KDF params) surfaces
	// here.
	v, err := vault.Read(filepath.Join(dir, "vault.enc"))
	if err != nil {
		t.Fatalf("vault.Read: %v", err)
	}
	if v.Magic != proto.VaultMagic {
		t.Fatalf("vault magic drift: got %q want %q", v.Magic, proto.VaultMagic)
	}
	if v.Version != 1 {
		t.Fatalf("vault version drift: got %d want 1", v.Version)
	}
	if len(v.WrappedPayloadKeys) != 1 {
		t.Fatalf("expected 1 wrap, got %d", len(v.WrappedPayloadKeys))
	}
	wrap := v.WrappedPayloadKeys[0]
	if wrap.MethodID != snapshotMethodID {
		t.Errorf("wrap method_id drift: got %q want %q", wrap.MethodID, snapshotMethodID)
	}
	if wrap.MethodType != proto.AuthPassphrase {
		t.Errorf("wrap method_type drift: got %q want %q", wrap.MethodType, proto.AuthPassphrase)
	}

	res, err := vault.Open(v, []vault.MethodResolver{vault.PassphraseResolver{Passphrase: []byte(snapshotPassphrase)}})
	if err != nil {
		t.Fatalf("vault.Open with snapshot passphrase: %v", err)
	}
	defer crypto.Wipe(res.PayloadKey)
	defer crypto.Wipe(res.UnlockKey)

	body := res.Body
	if len(body.SuperPriv) != ed25519.PrivateKeySize {
		t.Errorf("SuperPriv length drift: got %d want %d", len(body.SuperPriv), ed25519.PrivateKeySize)
	}
	// UserSuperPub lives on the VaultFile header (vault encryption
	// AAD binds it). VaultBody only carries the priv.
	if len(v.UserSuperPub) != ed25519.PublicKeySize {
		t.Errorf("VaultFile.UserSuperPub length drift: got %d want %d", len(v.UserSuperPub), ed25519.PublicKeySize)
	}
	if !bytes.Equal(v.UserSuperPub, expectedUserSuperPub()) {
		t.Errorf("UserSuperPub drift from deterministic seed: got %x want %x", v.UserSuperPub, expectedUserSuperPub())
	}
	// SuperPriv inside vault must derive to the same pub.
	derivedPub := ed25519.PrivateKey(body.SuperPriv).Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPub, v.UserSuperPub) {
		t.Errorf("SuperPriv→pub mismatch with VaultFile.UserSuperPub")
	}
	if body.AuthTip.Seq != 0 {
		t.Errorf("AuthTip.Seq drift: got %d want 0", body.AuthTip.Seq)
	}
	if len(body.Scopes) != 1 {
		t.Fatalf("expected 1 scope in vault, got %d", len(body.Scopes))
	}
	var scopeID proto.ScopeID
	for sid, sd := range body.Scopes {
		if sd.Label != snapshotLabel {
			t.Errorf("scope label drift: got %q want %q", sd.Label, snapshotLabel)
		}
		if len(sd.OEKs) == 0 {
			t.Error("scope has no OEK entries")
		}
		if sd.ChainTip.Seq != 1 {
			t.Errorf("scope ChainTip.Seq drift: got %d want 1", sd.ChainTip.Seq)
		}
		if sd.PushFloor != 0 {
			// Snapshot is "never pushed", so PushFloor stays at 0.
			t.Errorf("scope PushFloor drift: got %d want 0 (never pushed in snapshot)", sd.PushFloor)
		}
		scopeID = proto.MustParseScopeID(sid)
	}

	// Replay user chain.
	userEvents, err := chain.ReadUserEvents(filepath.Join(dir, "user.cbor"))
	if err != nil {
		t.Fatalf("ReadUserEvents: %v", err)
	}
	if len(userEvents) != 1 {
		t.Fatalf("user chain: expected 1 event, got %d", len(userEvents))
	}
	uState, err := chain.ReplayUser(filepath.Join(dir, "user.cbor"))
	if err != nil {
		t.Fatalf("chain.ReplayUser: %v", err)
	}
	if uState == nil || uState.LatestAuthSet == nil {
		t.Fatal("user chain replay produced no LatestAuthSet")
	}
	if len(uState.LatestAuthSet.Payload.Active) != 1 {
		t.Errorf("user chain: expected 1 active auth method, got %d", len(uState.LatestAuthSet.Payload.Active))
	}
	if uState.LatestAuthSet.Payload.Active[0].MethodID != snapshotMethodID {
		t.Errorf("user chain method_id drift: got %q want %q", uState.LatestAuthSet.Payload.Active[0].MethodID, snapshotMethodID)
	}

	// Replay scope chain. Need our X25519 keypair from the
	// SuperPriv (vault gave us the bytes) to open key_deliveries.
	xPub, err := crypto.EdPubToX25519(v.UserSuperPub)
	if err != nil {
		t.Fatalf("EdPubToX25519: %v", err)
	}
	xPriv, err := crypto.EdPrivToX25519(body.SuperPriv)
	if err != nil {
		t.Fatalf("EdPrivToX25519: %v", err)
	}
	defer crypto.Wipe(xPriv)
	opener := chain.LocalOpener{Pub: xPub, Priv: xPriv}

	scopePath := filepath.Join(dir, scopeID.String()+".cbor")
	st, err := chain.ReplayScope(scopePath, v.UserSuperPub, xPub, opener)
	if err != nil {
		t.Fatalf("chain.ReplayScope: %v", err)
	}
	if st == nil {
		t.Fatal("replay produced nil state")
	}
	if st.ScopeID != scopeID {
		t.Errorf("scope id drift: got %s want %s", st.ScopeID, scopeID)
	}
	if st.TipSeq != 1 {
		t.Errorf("scope TipSeq drift: got %d want 1", st.TipSeq)
	}
	if len(st.MemberSet) != 1 {
		t.Errorf("scope member count drift: got %d want 1", len(st.MemberSet))
	}
	if !bytes.Equal(st.MemberSet[0], v.UserSuperPub) {
		t.Errorf("scope member is not vault owner")
	}
	// Find the snapshot secret.
	var foundSecret *proto.SecretRecord
	for _, cur := range st.SecretIndex {
		if cur.Record != nil && cur.Record.Name == snapshotSecretName {
			foundSecret = cur.Record
			break
		}
	}
	if foundSecret == nil {
		t.Fatalf("secret %q not found in SecretIndex", snapshotSecretName)
	}
	if foundSecret.Payload != snapshotSecretValN {
		t.Errorf("secret payload drift: got %q want %q", foundSecret.Payload, snapshotSecretValN)
	}
}

// ----- REGENERATE -----

// TestWireCompatV1Regenerate writes the snapshot at testdata/v1/.
// Gated on WIRE_COMPAT_REGEN=1 so a normal `go test` doesn't
// silently overwrite the committed golden. Run when an
// intentional wire-format change lands.
func TestWireCompatV1Regenerate(t *testing.T) {
	if os.Getenv("WIRE_COMPAT_REGEN") != "1" {
		t.Skip("set WIRE_COMPAT_REGEN=1 to regenerate snapshot")
	}
	dir := filepath.Join("testdata", "v1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Deterministic identity from a fixed seed. ed25519 derives
	// the public half from the seed, so the user_super_pub is
	// stable across regenerations.
	seed := deterministicSeed("fd0-wire-compat-v1-identity")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	// Wrap into typed values via Parse — confirms the snapshot
	// regenerator goes through the same validation gates as
	// production code.
	pubT, err := crypto.ParseEd25519Pub(pub)
	if err != nil {
		t.Fatalf("ParseEd25519Pub: %v", err)
	}
	privT, err := crypto.ParseEd25519Priv(priv)
	if err != nil {
		t.Fatalf("ParseEd25519Priv: %v", err)
	}

	// User-chain genesis with a single passphrase method.
	salt := bytes.Repeat([]byte{0x42}, 16)
	pp, err := vault.NewPassphraseParams(salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	unlockKey, err := crypto.DeriveKey([]byte(snapshotPassphrase), salt, crypto.DefaultArgon2)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.Wipe(unlockKey)
	encSP, err := vault.EncryptSuperPriv(privT.Bytes(), pubT.Bytes(), snapshotMethodID, unlockKey)
	if err != nil {
		t.Fatal(err)
	}

	g, err := chain.BuildUserAuthSet(chain.LocalSigner{Priv: privT}, pubT.Bytes(), 0, nil, []proto.AuthMethod{{
		MethodID:           snapshotMethodID,
		MethodType:         proto.AuthPassphrase,
		PublicParams:       pp,
		EncryptedSuperPriv: encSP,
	}})
	if err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(dir, "user.cbor")
	if err := os.Remove(userPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := chain.AppendUser(userPath, g); err != nil {
		t.Fatal(err)
	}
	prefix, _ := g.PrevHashInput()
	authTipHash := proto.HashPrefix(prefix)

	// Scope chain: genesis member.change + one secret.set.
	gen, oek, scopeID, err := chain.BuildScopeGenesis(chain.LocalSigner{Priv: privT}, pubT.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	scopePath := filepath.Join(dir, scopeID.String()+".cbor")
	if err := os.Remove(scopePath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := chain.AppendScope(scopePath, gen); err != nil {
		t.Fatal(err)
	}
	genPrefix, _ := gen.PrevHashInput()
	genTipHash := proto.HashPrefix(genPrefix)

	body := &proto.SecretBody{
		ID: "s_compatv1secretaaaaaaaaa",
		Record: &proto.SecretRecord{
			Name:          snapshotSecretName,
			Type:          "kv.string",
			SchemaVersion: 1,
			Payload:       snapshotSecretValN,
			Tags:          map[string]string{"env": "prod", "owner": "compat"},
		},
	}
	secretEv, err := chain.BuildSecretSet(chain.LocalSigner{Priv: privT}, pubT.Bytes(), scopeID,
		0 /* prevSeq */, genTipHash[:], oek, 1 /* oekVersion */, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := chain.AppendScope(scopePath, secretEv); err != nil {
		t.Fatal(err)
	}
	secPrefix, _ := secretEv.PrevHashInput()
	secTipHash := proto.HashPrefix(secPrefix)

	// Vault: 1 wrap, 1 scope entry. UserSuperPub lives on the
	// VaultFile header (set by vault.Save), not in the body.
	vaultBody := &proto.VaultBody{
		SuperPriv: privT.Bytes(),
		AuthTip:   proto.ChainTip{Seq: 0, Hash: authTipHash[:]},
		Scopes: map[string]proto.ScopeVaultData{
			scopeID.String(): {
				Label:    snapshotLabel,
				OEKs:     []proto.OEKEntry{{Version: 1, Key: append([]byte(nil), oek...)}},
				ChainTip: proto.ChainTip{Seq: 1, Hash: secTipHash[:]},
			},
		},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	vaultPath := filepath.Join(dir, "vault.enc")
	if err := os.Remove(vaultPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := vault.Save(vaultPath, pubT.Bytes(), vaultBody, []vault.WrapInput{{
		MethodID:     snapshotMethodID,
		MethodType:   proto.AuthPassphrase,
		PublicParams: pp,
		UnlockKey:    unlockKey,
	}}); err != nil {
		t.Fatal(err)
	}

	t.Logf("wrote snapshot: %s, %s, %s", vaultPath, userPath, scopePath)
	t.Logf("user_super_pub (deterministic): %x", pubT.Bytes())
	t.Logf("scope_id: %s", scopeID.String())
}

// expectedUserSuperPub is the public key derived from the fixed
// regeneration seed. Pinned here so a seed drift in the
// regenerator surfaces as a clean test failure rather than the
// snapshot quietly capturing a different identity.
func expectedUserSuperPub() []byte {
	seed := deterministicSeed("fd0-wire-compat-v1-identity")
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey)
}

// deterministicSeed hashes a label into 32 bytes.
func deterministicSeed(label string) []byte {
	h := sha512.Sum512([]byte(label))
	return h[:32]
}

// Sanity: assert the local file paths match what the test
// directory layout implies. Catches misconfigured testdata.
func TestWireCompatTestdataLayout(t *testing.T) {
	wantSubpaths := []string{"vault.enc", "user.cbor"}
	for _, sp := range wantSubpaths {
		full := filepath.Join("testdata", "v1", sp)
		if _, err := os.Stat(full); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				t.Skipf("snapshot file %s missing — run TestWireCompatV1Regenerate", full)
			}
			t.Errorf("stat %s: %v", full, err)
		}
	}
	// At least one *.cbor that isn't user.cbor (the scope chain).
	entries, err := os.ReadDir(filepath.Join("testdata", "v1"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("testdata/v1 missing — regenerate first")
		}
		t.Fatal(err)
	}
	scopeCount := 0
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "user.cbor" && e.Name() != "vault.enc" && e.Name() != "README.md" {
			scopeCount++
		}
	}
	if scopeCount == 0 {
		t.Errorf("no scope chain file in testdata/v1 — at least one expected (filename = scope_id + .cbor)")
	}
	if scopeCount > 1 {
		t.Errorf("multiple scope chains in testdata/v1, snapshot expects exactly 1 (got %d)", scopeCount)
	}
	_ = fmt.Sprintf // anchor for the import check below
}
