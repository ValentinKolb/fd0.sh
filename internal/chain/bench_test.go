package chain

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// bench_test.go — chain replay performance baselines.
// Run: `go test -bench=. -benchmem ./internal/chain`.
//
// Replay is the load-bearing client-side step: every CLI command
// that touches a scope re-reads the chain file and re-verifies it.
// We need to know how cost scales with chain length so we can
// reason about "compaction kicks in at N" thresholds and tune the
// CompactScope policy in STORAGE.md §5.

// buildScopeForBench writes a scope chain with `nSecrets` secret.set
// events past genesis. Returns path + the inputs ReplayScope needs.
func buildScopeForBench(b *testing.B, dir string, nSecrets int) (path string, ownPub, ownXPub []byte, opener Opener) {
	b.Helper()
	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		b.Fatal(err)
	}
	xPub, err := crypto.EdPubToX25519(pub.Bytes())
	if err != nil {
		b.Fatal(err)
	}
	xPriv, err := crypto.EdPrivToX25519(priv.Bytes())
	if err != nil {
		b.Fatal(err)
	}
	signer := LocalSigner{Priv: priv}
	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub.Bytes())
	if err != nil {
		b.Fatal(err)
	}
	path = filepath.Join(dir, scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		b.Fatal(err)
	}
	st, err := ReplayScope(path, pub.Bytes(), xPub, LocalOpener{Pub: xPub, Priv: xPriv})
	if err != nil {
		b.Fatal(err)
	}
	tipSeq := st.TipSeq
	tipHash := st.TipHash
	for i := 0; i < nSecrets; i++ {
		body := &proto.SecretBody{
			ID: fmt.Sprintf("s_bench_%016x", i),
			Record: &proto.SecretRecord{
				Name: fmt.Sprintf("k%d", i), Type: "kv.string", SchemaVersion: 1,
				Payload: fmt.Sprintf("payload-%d", i), Tags: map[string]string{},
			},
		}
		ev, err := BuildSecretSet(signer, pub.Bytes(), scopeID, tipSeq, tipHash, oek, 1, body)
		if err != nil {
			b.Fatal(err)
		}
		if err := AppendScope(path, ev); err != nil {
			b.Fatal(err)
		}
		preb, _ := ev.PrevHashInput()
		h := proto.HashPrefix(preb)
		tipSeq++
		tipHash = h[:]
	}
	return path, pub.Bytes(), xPub, LocalOpener{Pub: xPub, Priv: xPriv}
}

// BenchmarkReplayScope measures cost of full chain replay at three
// chain depths. The expected scaling is O(N) — every event must
// be signature-verified + applied to the running state.
func BenchmarkReplayScope100(b *testing.B)   { benchReplay(b, 100) }
func BenchmarkReplayScope1k(b *testing.B)    { benchReplay(b, 1_000) }
func BenchmarkReplayScope10k(b *testing.B)   { benchReplay(b, 10_000) }

func benchReplay(b *testing.B, n int) {
	dir := b.TempDir()
	path, pub, xPub, opener := buildScopeForBench(b, dir, n)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ReplayScope(path, pub, xPub, opener); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAppendScopeOnly measures cost of one fsync-flushed
// AppendScope call (CBOR-encode + per-event fsync). This is the
// inner loop on every secret.set or member.change.
func BenchmarkAppendScopeOnly(b *testing.B) {
	dir := b.TempDir()
	pub, priv, _ := crypto.GenerateIdentity()
	signer := LocalSigner{Priv: priv}
	gen, oek, scopeID, err := BuildScopeGenesis(signer, pub.Bytes())
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(dir, scopeID.String()+".cbor")
	if err := AppendScope(path, gen); err != nil {
		b.Fatal(err)
	}
	xPub, _ := crypto.EdPubToX25519(pub.Bytes())
	xPriv, _ := crypto.EdPrivToX25519(priv.Bytes())
	st, _ := ReplayScope(path, pub.Bytes(), xPub, LocalOpener{Pub: xPub, Priv: xPriv})
	tipSeq, tipHash := st.TipSeq, st.TipHash
	body := &proto.SecretBody{
		ID: "s_bench_appendonly__",
		Record: &proto.SecretRecord{
			Name: "k", Type: "kv.string", SchemaVersion: 1,
			Payload: "payload", Tags: map[string]string{},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev, err := BuildSecretSet(signer, pub.Bytes(), scopeID, tipSeq, tipHash, oek, 1, body)
		if err != nil {
			b.Fatal(err)
		}
		if err := AppendScope(path, ev); err != nil {
			b.Fatal(err)
		}
		preb, _ := ev.PrevHashInput()
		h := proto.HashPrefix(preb)
		tipSeq++
		tipHash = h[:]
	}
}
