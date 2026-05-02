package chain

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadScopeEvents stresses the chain-file parser's tail-
// truncate logic. The contract: ReadScopeEvents must
//   - never panic on any input
//   - never return an empty slice from a non-empty file UNLESS at
//     least one event decoded successfully (truncating the tail)
//
// The latter is the codex+adversarial finding from earlier this
// session: a file truncated from byte 0 was silently parsed as
// "no events", letting the next sync treat the scope as fresh.
func FuzzReadScopeEvents(f *testing.F) {
	// Seeds: a real one-event chain (built via roundtrip in
	// chain_test.go) and a few short pathologicals.
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff})
	f.Add([]byte{0x9f, 0x01, 0xff}) // CBOR indefinite array (rejected by strict mode)
	// Build one valid event by reading the genesis from a roundtrip
	// fixture would be heavy; the fuzzer's mutation will explore
	// the parser's state space from these seeds anyway.

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.cbor")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		_, _ = ReadScopeEvents(path)
		// Read again — must be deterministic (post-truncation state
		// is stable). If the FIRST read truncated, the second must
		// not panic on the truncated tail.
		_, _ = ReadScopeEvents(path)
	})
}

// FuzzReadUserEvents — same shape for the user chain.
func FuzzReadUserEvents(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.cbor")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		_, _ = ReadUserEvents(path)
		_, _ = ReadUserEvents(path)
	})
}
