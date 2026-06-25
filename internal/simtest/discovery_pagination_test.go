package simtest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestLateJoinDiscoveryPaginatesPastServerCap(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")

	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice initial sync failed:\n%s", out)
	}
	if out, ok := bob.Sync(); !ok {
		t.Fatalf("bob initial sync failed:\n%s", out)
	}
	if out, err := alice.run("scope", "create", "--label", "team"); err != nil {
		t.Fatalf("alice scope create: %v\n%s", err, out)
	}
	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice scope publish sync failed:\n%s", out)
	}

	scopeIDs := alice.ScopeIDs()
	if len(scopeIDs) != 1 {
		t.Fatalf("alice scope ids = %v; want exactly one", scopeIDs)
	}
	scopeID := scopeIDs[0]

	appendBulkSecrets(t, alice, scopeID, 1001)
	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice bulk-history sync failed:\n%s", out)
	}

	aliceCard := exportCard(t, alice)
	bobCard := exportCard(t, bob)
	if out, err := alice.run("card", "import", bobCard, "--label", bob.Name, "--yes"); err != nil {
		t.Fatalf("alice import bob card: %v\n%s", err, out)
	}
	if out, err := bob.run("card", "import", aliceCard, "--label", alice.Name, "--yes"); err != nil {
		t.Fatalf("bob import alice card: %v\n%s", err, out)
	}
	if out, err := alice.run("scope", "add-member", bob.Name, "--scope", "team"); err != nil {
		t.Fatalf("alice add bob: %v\n%s", err, out)
	}
	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice membership sync failed:\n%s", out)
	}

	out, ok := bob.Sync()
	if !ok {
		t.Fatalf("bob discovery sync failed:\n%s", out)
	}
	if strings.Contains(out, "no current OEK after replay") {
		t.Fatalf("bob discovery used an incomplete first page:\n%s", out)
	}
	got, ok := bob.Get("team", "bulk-1000")
	if !ok || got != "value-1000" {
		t.Fatalf("bob Get bulk-1000 = %q,%v; want value-1000,true", got, ok)
	}
}

func appendBulkSecrets(t *testing.T, c *Client, scopeID string, n int) {
	t.Helper()
	withClientEnv(t, c, func() {
		s, err := cli.Open(context.Background())
		if err != nil {
			t.Fatalf("%s open session: %v", c.Name, err)
		}
		defer s.Close()

		pid := proto.MustParseScopeID(scopeID)
		path := s.Paths.ScopeChain(pid)
		st, err := chain.ReplayScope(path, s.UserSuperPub, s.UserX25519Pub, cli.AgentOpener{Agent: s.Agent})
		if err != nil {
			t.Fatalf("%s replay scope: %v", c.Name, err)
		}
		sd, ok := s.Body.Scopes[scopeID]
		if !ok {
			t.Fatalf("%s vault has no scope %s", c.Name, scopeID)
		}
		var curOEK proto.OEKEntry
		for _, entry := range sd.OEKs {
			if entry.Version == st.CurrentOEKVer {
				curOEK = entry
				break
			}
		}
		if curOEK.Version == 0 {
			t.Fatalf("%s scope %s: missing OEK v%d", c.Name, scopeID, st.CurrentOEKVer)
		}

		tipSeq := st.TipSeq
		tipHash := append([]byte(nil), st.TipHash...)
		for i := 0; i < n; i++ {
			body := &proto.SecretBody{
				ID: fmt.Sprintf("s_bulk_%04d", i),
				Record: &proto.SecretRecord{
					Name:          fmt.Sprintf("bulk-%04d", i),
					Type:          "kv.string",
					SchemaVersion: 1,
					Payload:       fmt.Sprintf("value-%04d", i),
					Tags:          map[string]string{},
				},
			}
			ev, err := chain.BuildSecretSet(cli.AgentSigner{Agent: s.Agent}, s.UserSuperPub, pid, tipSeq, tipHash, curOEK.Key, curOEK.Version, body)
			if err != nil {
				t.Fatalf("build bulk secret %d: %v", i, err)
			}
			if err := chain.AppendScope(path, ev); err != nil {
				t.Fatalf("append bulk secret %d: %v", i, err)
			}
			prefix, err := ev.PrevHashInput()
			if err != nil {
				t.Fatalf("bulk secret %d hash input: %v", i, err)
			}
			hash := proto.HashPrefix(prefix)
			tipSeq = ev.SignedPrefix.Seq
			tipHash = append(tipHash[:0], hash[:]...)
		}

		sd.ChainTip = proto.ChainTip{Seq: tipSeq, Hash: append([]byte(nil), tipHash...)}
		s.Body.Scopes[scopeID] = sd
		if err := s.ReSeal(); err != nil {
			t.Fatalf("%s reseal after bulk append: %v", c.Name, err)
		}
	})
}

func withClientEnv(t *testing.T, c *Client, fn func()) {
	t.Helper()
	type prior struct {
		value string
		ok    bool
	}
	old := map[string]prior{}
	for _, kv := range c.env() {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		prev, existed := os.LookupEnv(key)
		old[key] = prior{value: prev, ok: existed}
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
	defer func() {
		for key, prev := range old {
			if prev.ok {
				_ = os.Setenv(key, prev.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}()
	fn()
}
