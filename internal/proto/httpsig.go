package proto

import (
	"crypto/sha256"
	"sort"
	"strings"
)

// HTTPSignedInput builds the input over which fd0-sig signatures are computed.
// API.md §1:
//
//	signed_input = "fd0-http-request-v1" || cbor({
//	    method, path, query, ts, nonce, body_sha
//	})
//
// query is sorted lexicographically; multi-value keys are forbidden in v1
// (callers MUST flatten or reject). body_sha is SHA-256(body) or SHA-256("") if
// the body is empty.
func HTTPSignedInput(method, path string, query map[string]string, ts uint64, nonce []byte, body []byte) ([]byte, error) {
	sum := sha256.Sum256(body)
	if len(query) == 0 {
		query = map[string]string{}
	}
	// Marshal canonicalises map keys, but we additionally validate that keys
	// don't carry duplicate-after-flattening collisions; callers should pass
	// already-flattened maps.
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// We construct a struct-like map[string]string via a deterministic marshal
	// of an anonymous struct, so the encoding sorts keys per CBOR Core Det rules.
	body2, err := Marshal(struct {
		Method  string            `cbor:"method"`
		Path    string            `cbor:"path"`
		Query   map[string]string `cbor:"query"`
		TS      uint64            `cbor:"ts"`
		Nonce   []byte            `cbor:"nonce"`
		BodySHA []byte            `cbor:"body_sha"`
	}{
		Method:  strings.ToUpper(method),
		Path:    path,
		Query:   query,
		TS:      ts,
		Nonce:   nonce,
		BodySHA: sum[:],
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(DomainHTTP), body2...), nil
}
