package proto

import (
	"bytes"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// CBOR encode/decode modes used everywhere on the wire and at rest.
//
// Encoding uses RFC 8949 §4.2.1 Core Deterministic Encoding so that signed
// inputs and content-addressed event IDs are byte-stable across implementations.
// Decoding is strict: any non-canonical input is rejected.
var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	encMode = em

	dm, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		IntDec:           cbor.IntDecConvertSignedOrFail,
		MaxArrayElements: MaxCBORCollectionElements,
		MaxMapPairs:      MaxCBORCollectionElements,
		MaxNestedLevels:  16,
		// Codex audit (🟡 cbor.go:27): case-sensitive struct field
		// matching. Without it, two distinct CBOR encodings ("Field"
		// and "field") could decode into the same struct field —
		// breaking determinism for signed inputs that get unmarshaled
		// then re-marshaled (the second pass would canonicalise to
		// one casing, changing signed bytes).
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	decMode = dm
}

// Marshal returns deterministic CBOR per RFC 8949 §4.2.1.
func Marshal(v any) ([]byte, error) { return encMode.Marshal(v) }

// Unmarshal strictly decodes deterministic CBOR.
func Unmarshal(data []byte, v any) error { return decMode.Unmarshal(data, v) }

// NewStreamDecoder returns a strict streaming decoder over r. Used by chain
// replay where events are concatenated raw CBOR (STORAGE.md §3.1).
// Decoder.NumBytesRead() reports total bytes consumed and is used to recover
// per-event offsets for tail-truncation on partial decode.
func NewStreamDecoder(r io.Reader) *cbor.Decoder { return decMode.NewDecoder(r) }

// NewStreamDecoderBytes is a convenience wrapper for in-memory replay.
func NewStreamDecoderBytes(b []byte) *cbor.Decoder { return decMode.NewDecoder(bytes.NewReader(b)) }
