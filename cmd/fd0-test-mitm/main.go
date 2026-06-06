// fd0-test-mitm is a TEST-ONLY HTTP proxy that sits between fd0 CLI
// clients and fd0-server, mutating responses according to a flag-
// configured "attack mode". Used by tests/integration_malicious_server.sh
// to verify the client's translog verifier rejects every malformed
// or actively malicious server response.
//
// NOT intended for production use. Lives in cmd/ only because Go's
// build system treats internal/ test helpers awkwardly when they
// need to be runnable binaries.
//
// Modes (FD0_MITM_MODE env var or --mode flag):
//
//   passthrough      — forward verbatim. Baseline.
//   tamper-sth       — flip a byte in the STH bytes returned by
//                      /v1/sth/{cid} OR in any /sync/users response
//                      that carries an embedded STH. Verifier sees
//                      bad signature.
//   tamper-inclusion — flip a byte in inclusion_proofs[].audit_path[0]
//                      on /sync responses.
//   tamper-consistency — flip a byte in consistency_proof.nodes[0].
//   drop-sth         — strip the STH field from /sync responses.
//                      Verifier sees missing-STH and refuses.
//   drop-inclusion   — strip inclusion_proofs from /sync responses.
//   swap-chain-id    — change sth.head.chain_id to a different
//                      string. Verifier's chain_id binding rejects.
//   replay-stale     — cache the FIRST STH and replay it forever
//                      (server keeps growing). Mimics a server
//                      pinned to its initial state.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

func main() {
	var (
		listen   = flag.String("listen", ":15011", "bind address for the proxy")
		upstream = flag.String("upstream", "http://127.0.0.1:14999", "upstream fd0-server URL")
		mode     = flag.String("mode", "", "attack mode (overrides FD0_MITM_MODE)")
	)
	flag.Parse()
	if *mode == "" {
		*mode = os.Getenv("FD0_MITM_MODE")
	}
	if *mode == "" {
		*mode = "passthrough"
	}
	target, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("bad upstream URL: %v", err)
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = makeMutator(*mode)
	log.Printf("fd0-test-mitm listening on %s (mode=%s upstream=%s)", *listen, *mode, *upstream)
	if err := http.ListenAndServe(*listen, rp); err != nil {
		log.Fatal(err)
	}
}

// stateBox holds the per-mode mutable state (e.g., the cached STH
// for replay-stale). httputil.ReverseProxy may invoke ModifyResponse
// concurrently, so we lock around accesses.
type stateBox struct {
	mu        sync.Mutex
	cachedSTH []byte
}

var state = &stateBox{}

// makeMutator returns the response-rewriter for the chosen mode.
// Each mutator decodes the CBOR body, mutates the in-memory struct,
// re-encodes, and replaces resp.Body + Content-Length.
//
// Fail-closed: a mode that fails to apply (CBOR decode error,
// unknown field shape, etc.) returns a 500 to the client instead
// of silently passing the response through. Otherwise an attack
// scenario could "succeed" (= client accepts) merely because the
// proxy didn't actually mutate anything (codex C5 review #1).
func makeMutator(mode string) func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.StatusCode != 200 {
			return nil
		}
		ct := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/cbor") {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()

		path := resp.Request.URL.Path
		mutated, applied, mErr := mutate(mode, path, body)
		if mErr != nil {
			log.Printf("mutate(%s, %s): FAIL-CLOSED: %v", mode, path, mErr)
			resp.StatusCode = 502
			resp.Status = "502 mutation failed"
			resp.Body = io.NopCloser(strings.NewReader("mutation failed: " + mErr.Error()))
			resp.ContentLength = int64(len(mErr.Error()) + len("mutation failed: "))
			resp.Header.Set("Content-Type", "text/plain")
			return nil
		}
		if applied {
			log.Printf("APPLIED mode=%s path=%s", mode, path)
		}
		resp.Body = io.NopCloser(bytes.NewReader(mutated))
		resp.ContentLength = int64(len(mutated))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(mutated)))
		return nil
	}
}

// mutate applies the mode-specific transformation to body. Returns
// (mutatedBody, applied, err) — `applied` is true iff the mode's
// mutation actually changed at least one targeted field on this
// (path, body) combination. The caller logs `applied` so the test
// harness can verify that the expected attack actually hit a request.
//
// Crucially: `applied = (err == nil)` is WRONG (successful marshal
// of an unchanged body still returns nil). Every mutator now reports
// the count of fields it changed; we treat changed == 0 as a no-op.
func mutate(mode, path string, body []byte) ([]byte, bool, error) {
	switch mode {
	case "passthrough":
		return body, false, nil

	case "tamper-sth":
		switch {
		case strings.HasPrefix(path, "/v1/sth/"):
			out, n, err := tamperSTHBytes(body)
			return out, err == nil && n > 0, err
		case path == "/v1/sync":
			out, n, err := tamperFieldInSync(body, "sth")
			return out, err == nil && n > 0, err
		}

	case "tamper-inclusion":
		if path == "/v1/sync" {
			out, n, err := tamperFieldInSync(body, "inclusion_proofs")
			return out, err == nil && n > 0, err
		}

	case "tamper-consistency":
		if path == "/v1/sync" {
			out, n, err := tamperFieldInSync(body, "consistency_proof")
			return out, err == nil && n > 0, err
		}

	case "drop-sth":
		if path == "/v1/sync" {
			out, n, err := stripFieldFromSync(body, "sth")
			return out, err == nil && n > 0, err
		}

	case "drop-inclusion":
		if path == "/v1/sync" {
			out, n, err := stripFieldFromSync(body, "inclusion_proofs")
			return out, err == nil && n > 0, err
		}

	case "swap-chain-id":
		if strings.HasPrefix(path, "/v1/sth/") {
			out, n, err := swapChainIDInSTH(body)
			return out, err == nil && n > 0, err
		}
		if path == "/v1/sync" {
			out, n, err := swapChainIDInSync(body)
			return out, err == nil && n > 0, err
		}

	case "bad-leaf-index":
		// Mutate inclusion proof leaf_index in /sync responses.
		// Targets the chain_id binding via inclusion verification —
		// proof says leaf_index=999 but client expects leaf_index=N.
		if path == "/v1/sync" {
			out, n, err := mutateInclusionProofIndex(body)
			return out, err == nil && n > 0, err
		}

	case "replay-stale":
		if strings.HasPrefix(path, "/v1/sth/") {
			state.mu.Lock()
			defer state.mu.Unlock()
			if state.cachedSTH == nil {
				state.cachedSTH = append([]byte(nil), body...)
				return body, false, nil
			}
			return append([]byte(nil), state.cachedSTH...), true, nil
		}

	default:
		// Unknown mode — fail-closed so misconfigured tests are loud.
		return nil, false, fmt.Errorf("unknown mode %q", mode)
	}
	return body, false, nil
}

// mutateInclusionProofIndex bumps the first inclusion proof's
// leaf_index by 1. The pure-layer verifier requires
// proof.LeafIndex == expectedLeafIndices[i] (= event.Seq), so any
// bump should fail.
func mutateInclusionProofIndex(body []byte) ([]byte, int, error) {
	var resp map[string]any
	if err := proto.Unmarshal(body, &resp); err != nil {
		return body, 0, err
	}
	pull, _ := resp["pull"].(map[any]any)
	changed := 0
	for _, v := range pull {
		entry, ok := v.(map[any]any)
		if !ok {
			continue
		}
		arr, ok := entry["inclusion_proofs"].([]any)
		if !ok || len(arr) == 0 {
			continue
		}
		p, ok := arr[0].(map[any]any)
		if !ok {
			continue
		}
		switch v := p["leaf_index"].(type) {
		case uint64:
			p["leaf_index"] = v + 1000
			changed++
		case int64:
			p["leaf_index"] = v + 1000
			changed++
		case int:
			p["leaf_index"] = uint64(v) + 1000
			changed++
		default:
			return body, 0, fmt.Errorf("unexpected leaf_index type %T", p["leaf_index"])
		}
	}
	out, err := proto.Marshal(resp)
	return out, changed, err
}

// tamperSTHBytes flips a byte inside a CBOR-encoded translog.STH.
// Returns (out, 1, nil) when a byte was flipped (always for body
// >= 4 bytes), else (body, 0, nil).
func tamperSTHBytes(body []byte) ([]byte, int, error) {
	if len(body) < 4 {
		return body, 0, nil
	}
	out := append([]byte(nil), body...)
	out[len(out)-1] ^= 0x01
	return out, 1, nil
}

// tamperFieldInSync re-encodes a /sync response with the named field
// mutated by one byte. Returns the count of fields changed so the
// caller can detect "no-op" mutations (target field absent).
//
// Targeted fields:
//
//	sth                — pull[*].sth and push[*].sth
//	inclusion_proofs   — pull[*].inclusion_proofs[0].audit_path[0]
//	consistency_proof  — pull[*].consistency_proof.nodes[0]
func tamperFieldInSync(body []byte, field string) ([]byte, int, error) {
	var resp map[string]any
	if err := proto.Unmarshal(body, &resp); err != nil {
		return body, 0, err
	}
	pull, _ := resp["pull"].(map[any]any)
	changed := 0
	for _, v := range pull {
		entry, ok := v.(map[any]any)
		if !ok {
			continue
		}
		switch field {
		case "sth":
			if sth, ok := entry["sth"].(map[any]any); ok {
				if flipFirstByteInSig(sth) {
					changed++
				}
			}
		case "inclusion_proofs":
			if arr, ok := entry["inclusion_proofs"].([]any); ok && len(arr) > 0 {
				if p, ok := arr[0].(map[any]any); ok {
					if path, ok := p["audit_path"].([]any); ok && len(path) > 0 {
						if b, ok := path[0].([]byte); ok && len(b) > 0 {
							b2 := append([]byte(nil), b...)
							b2[0] ^= 0x01
							path[0] = b2
							changed++
						}
					}
				}
			}
		case "consistency_proof":
			if cp, ok := entry["consistency_proof"].(map[any]any); ok {
				if nodes, ok := cp["nodes"].([]any); ok && len(nodes) > 0 {
					if b, ok := nodes[0].([]byte); ok && len(b) > 0 {
						b2 := append([]byte(nil), b...)
						b2[0] ^= 0x01
						nodes[0] = b2
						changed++
					}
				}
			}
		}
	}
	if push, ok := resp["push"].([]any); ok {
		for _, item := range push {
			entry, ok := item.(map[any]any)
			if !ok {
				continue
			}
			if field == "sth" {
				if sth, ok := entry["sth"].(map[any]any); ok {
					if flipFirstByteInSig(sth) {
						changed++
					}
				}
			}
		}
	}
	out, err := proto.Marshal(resp)
	return out, changed, err
}

// flipFirstByteInSig mutates the embedded sth.signature byte string
// in-place. Returns true iff a signature byte was actually flipped.
func flipFirstByteInSig(sth map[any]any) bool {
	sig, ok := sth["signature"].([]byte)
	if !ok || len(sig) == 0 {
		return false
	}
	s2 := append([]byte(nil), sig...)
	s2[0] ^= 0x01
	sth["signature"] = s2
	return true
}

// stripFieldFromSync removes a named field from every pull/push
// entry. Returns the count of entries from which the field was
// actually removed.
func stripFieldFromSync(body []byte, field string) ([]byte, int, error) {
	var resp map[string]any
	if err := proto.Unmarshal(body, &resp); err != nil {
		return body, 0, err
	}
	pull, _ := resp["pull"].(map[any]any)
	changed := 0
	for _, v := range pull {
		if entry, ok := v.(map[any]any); ok {
			if _, present := entry[field]; present {
				delete(entry, field)
				changed++
			}
		}
	}
	if push, ok := resp["push"].([]any); ok {
		for _, item := range push {
			if entry, ok := item.(map[any]any); ok {
				if _, present := entry[field]; present {
					delete(entry, field)
					changed++
				}
			}
		}
	}
	out, err := proto.Marshal(resp)
	return out, changed, err
}

// swapChainIDInSTH rewrites the embedded TreeHead.chain_id. The
// signature is over the head, so changing chain_id INVALIDATES it.
// The test asserts client refuses, regardless of error class.
func swapChainIDInSTH(body []byte) ([]byte, int, error) {
	var sth translog.STH
	if err := proto.Unmarshal(body, &sth); err != nil {
		return body, 0, err
	}
	sth.Head.ChainID = "scope:s_attackerattackerattackerattac"
	out, err := proto.Marshal(sth)
	return out, 1, err
}

// swapChainIDInSync mutates each per-scope pull entry's STH chain_id.
func swapChainIDInSync(body []byte) ([]byte, int, error) {
	var resp map[string]any
	if err := proto.Unmarshal(body, &resp); err != nil {
		return body, 0, err
	}
	pull, _ := resp["pull"].(map[any]any)
	changed := 0
	for _, v := range pull {
		entry, ok := v.(map[any]any)
		if !ok {
			continue
		}
		if sth, ok := entry["sth"].(map[any]any); ok {
			if head, ok := sth["head"].(map[any]any); ok {
				head["chain_id"] = "scope:s_swappedswappedswappedswapped"
				changed++
			}
		}
	}
	out, err := proto.Marshal(resp)
	return out, changed, err
}
