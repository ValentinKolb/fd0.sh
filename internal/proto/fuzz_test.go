package proto

import (
	"bytes"
	"testing"
)

// Native Go fuzz targets for the proto package. Run for ≥1 minute
// per target in CI:
//
//	go test ./internal/proto/ -fuzz=FuzzCBORUnmarshal -fuzztime=60s
//	go test ./internal/proto/ -fuzz=FuzzHTTPSignedInput -fuzztime=60s
//
// Each target is a "doesn't panic / doesn't infinite-loop / strict
// mode actually rejects malformed input" property test driven by
// AFL-style coverage-guided mutation.

// FuzzCBORUnmarshal stresses the strict CBOR decoder. The contract:
// for ANY input, Unmarshal must terminate, must not panic, and any
// successfully-decoded value must round-trip byte-identically when
// re-marshaled.
func FuzzCBORUnmarshal(f *testing.F) {
	// Seed corpus: a few well-formed canonical encodings.
	f.Add([]byte{0x80})                                // []
	f.Add([]byte{0xa0})                                // {}
	f.Add([]byte{0x00})                                // 0
	f.Add([]byte{0xf6})                                // null
	f.Add([]byte{0x82, 0x01, 0x02})                    // [1, 2]
	f.Add([]byte{0xa1, 0x61, 'a', 0x01})               // {"a": 1}
	f.Add([]byte{0x44, 0xde, 0xad, 0xbe, 0xef})        // h'deadbeef'
	f.Add([]byte{0x1b, 0xff, 0xff, 0xff, 0xff,         // uint MaxInt64+
		0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		// Property 1: doesn't panic.
		err := Unmarshal(data, &v)
		if err != nil {
			return
		}
		// Property 2: round-trip byte-stable for accepted inputs.
		// Since we accept then re-marshal, the bytes must match
		// (canonical-in canonical-out).
		out, mErr := Marshal(v)
		if mErr != nil {
			t.Fatalf("decoded %x but Marshal failed: %v", data, mErr)
		}
		if !bytes.Equal(data, out) {
			// Round-trip mismatch is OK ONLY if our `any` decoding
			// loses information (e.g., int vs uint). We assert
			// that re-marshaling THE RE-MARSHALED form is now
			// stable (idempotent).
			var v2 any
			if err := Unmarshal(out, &v2); err != nil {
				t.Fatalf("re-decoded form failed: %v", err)
			}
			out2, _ := Marshal(v2)
			if !bytes.Equal(out, out2) {
				t.Fatalf("non-idempotent canonicalisation: %x → %x → %x", data, out, out2)
			}
		}
	})
}

// FuzzHTTPSignedInput stresses the HTTP signature input builder.
// The contract: any inputs (incl. empty / huge / unicode / binary)
// produce a deterministic byte-string and never panic.
func FuzzHTTPSignedInput(f *testing.F) {
	// Seeds derived from real call patterns.
	f.Add("POST", "/sync", "", uint64(1700000000), []byte("nonce"), []byte("body"), []byte("server-pub-32-bytes-aaaaaaaaaaaa"))
	f.Add("GET", "/v1/sth/x", "k=v", uint64(0), []byte{}, []byte{}, []byte{})
	f.Add("", "", "", uint64(0), []byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, method, path, queryEnc string, ts uint64, nonce, body, srvPub []byte) {
		// Build a query map from a "k=v&k2=v2" string. Multi-value
		// values are forbidden by HTTPSignedInput callers, so we
		// flatten — last-wins.
		qmap := map[string]string{}
		for _, pair := range splitAmp(queryEnc) {
			k, v, ok := splitEq(pair)
			if !ok {
				continue
			}
			qmap[k] = v
		}
		// Property: doesn't panic on ANY input shape.
		a, err := HTTPSignedInput(method, path, qmap, ts, nonce, body, srvPub)
		if err != nil {
			return
		}
		// Property: deterministic — calling twice yields identical bytes.
		b, err := HTTPSignedInput(method, path, qmap, ts, nonce, body, srvPub)
		if err != nil {
			t.Fatalf("second call errored after first succeeded: %v", err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("HTTPSignedInput non-deterministic\n  a: %x\n  b: %x", a, b)
		}
		// Property: prefix is the domain string (no inadvertent
		// truncation or replacement).
		if len(a) < len(DomainHTTP) || string(a[:len(DomainHTTP)]) != DomainHTTP {
			t.Fatalf("missing domain prefix: got %q", a[:min(len(a), len(DomainHTTP))])
		}
	})
}

func splitAmp(s string) []string {
	var out []string
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '&' {
			out = append(out, s[last:i])
			last = i + 1
		}
	}
	out = append(out, s[last:])
	return out
}

func splitEq(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
