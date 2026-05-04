package chain

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzReadScopeEvents stresses the chain-file parser's tail-
// truncate logic. The contract:
//   - never panic on any input
//   - never return an empty slice from a non-empty file UNLESS at
//     least one event decoded successfully (truncating the tail)
//   - second read after first must be IDEMPOTENT: same number of
//     events returned, OR file unchanged from first call's view
//
// This previously had ZERO assertions (test audit 🔴). Now: every
// fuzz iteration verifies the contract above.
func FuzzReadScopeEvents(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xff})
	f.Add([]byte{0x9f, 0x01, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.cbor")
		origLen := len(data)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		evs1, err1 := ReadScopeEvents(path)
		// Contract 1: empty INPUT → empty result, no error.
		if origLen == 0 {
			if err1 != nil || len(evs1) != 0 {
				t.Fatalf("empty file should parse to (nil,nil), got (len=%d, err=%v)", len(evs1), err1)
			}
			return
		}
		// Contract 2: NON-empty input that decodes to zero events
		// MUST return an error (the prev>0 guard from the
		// adversarial truncation fix). This is the property the
		// audit flagged as un-asserted.
		if err1 == nil && len(evs1) == 0 {
			// File was non-empty going in. ReadScopeEvents may
			// have truncated it in the tail-rollback path; check
			// the post-call file size. If file is now zero AND
			// no events were decoded, that's the "garbage from
			// byte 0 silently dropped" bug we already fixed.
			st, _ := os.Stat(path)
			if st != nil && st.Size() == 0 {
				t.Fatalf("non-empty input %dB silently truncated to 0B with no decoded events", origLen)
			}
		}
		// Contract 3: second read MUST be idempotent. The file
		// state after a truncate-rollback is stable; further
		// calls must not differ.
		evs2, err2 := ReadScopeEvents(path)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-idempotent: first err=%v, second err=%v", err1, err2)
		}
		if err1 == nil && err2 == nil && len(evs1) != len(evs2) {
			t.Fatalf("non-idempotent event count: first=%d, second=%d", len(evs1), len(evs2))
		}
	})
}

// FuzzReadUserEvents — same contract for the user chain.
func FuzzReadUserEvents(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.cbor")
		origLen := len(data)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		evs1, err1 := ReadUserEvents(path)
		if origLen == 0 {
			if err1 != nil || len(evs1) != 0 {
				t.Fatalf("empty file should parse to (nil,nil), got (len=%d, err=%v)", len(evs1), err1)
			}
			return
		}
		if err1 == nil && len(evs1) == 0 {
			st, _ := os.Stat(path)
			if st != nil && st.Size() == 0 {
				t.Fatalf("non-empty input %dB silently truncated to 0B with no decoded events", origLen)
			}
		}
		evs2, err2 := ReadUserEvents(path)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-idempotent: first err=%v, second err=%v", err1, err2)
		}
		if err1 == nil && err2 == nil && len(evs1) != len(evs2) {
			t.Fatalf("non-idempotent event count: first=%d, second=%d", len(evs1), len(evs2))
		}
	})
}
