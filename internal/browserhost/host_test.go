package browserhost

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/browserconfig"
)

func frameJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func decodeResponse(t *testing.T, frame []byte) Response {
	t.Helper()
	if len(frame) < 4 {
		t.Fatalf("short response frame: %d", len(frame))
	}
	size := binary.LittleEndian.Uint32(frame[:4])
	if int(size) != len(frame)-4 {
		t.Fatalf("response length = %d, payload = %d", size, len(frame)-4)
	}
	var response Response
	if err := json.Unmarshal(frame[4:], &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestRunRejectsUnknownCallerBeforeVaultAccess(t *testing.T) {
	t.Parallel()
	input := frameJSON(t, Request{ID: "1", Operation: "status"})
	var output bytes.Buffer
	if err := Run(context.Background(), "chrome-extension://unknown/", bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	response := decodeResponse(t, output.Bytes())
	if response.OK || response.Error == nil || response.Error.Code != "forbidden" {
		t.Fatalf("response = %+v", response)
	}
}

func TestRunRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	input := frameJSON(t, map[string]any{
		"id":        "1",
		"operation": "matches",
		"origin":    "https://example.com",
		"secret":    "not allowed",
	})
	var output bytes.Buffer
	if err := Run(context.Background(), browserconfig.DevelopmentExtensionOrigin, bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	response := decodeResponse(t, output.Bytes())
	if response.OK || response.Error == nil || response.Error.Code != "invalid_request" {
		t.Fatalf("response = %+v", response)
	}
}

func TestReadFrameRejectsOversizeAndTruncation(t *testing.T) {
	t.Parallel()
	var oversize [4]byte
	binary.LittleEndian.PutUint32(oversize[:], maxMessageBytes+1)
	if _, err := readFrame(bytes.NewReader(oversize[:])); err == nil {
		t.Fatal("oversize frame succeeded")
	}

	truncated := append([]byte(nil), frameJSON(t, Request{ID: "1", Operation: "status"})...)
	truncated = truncated[:len(truncated)-1]
	if _, err := readFrame(bytes.NewReader(truncated)); err == nil {
		t.Fatal("truncated frame succeeded")
	}
}

func TestHandleValidatesOperationShapeBeforeVaultAccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  Request
		code string
	}{
		{name: "missing id", req: Request{Operation: "matches"}, code: "invalid_request"},
		{name: "unknown operation", req: Request{ID: "1", Operation: "write"}, code: "unsupported_operation"},
		{name: "status origin", req: Request{ID: "1", Operation: "status", Origin: "https://example.com"}, code: "invalid_request"},
		{name: "matches missing origin", req: Request{ID: "1", Operation: "matches"}, code: "invalid_request"},
		{name: "matches credential id", req: Request{ID: "1", Operation: "matches", CredentialID: "x"}, code: "invalid_request"},
		{name: "reveal missing origin", req: Request{ID: "1", Operation: "reveal", CredentialID: "x"}, code: "invalid_request"},
		{name: "reveal missing credential id", req: Request{ID: "1", Operation: "reveal"}, code: "invalid_request"},
		{name: "totp missing credential id", req: Request{ID: "1", Operation: "totp", Origin: "https://example.com"}, code: "invalid_request"},
		{name: "save missing password", req: Request{ID: "1", Operation: "save", Origin: "https://example.com", Title: "Login"}, code: "invalid_request"},
		{name: "update missing revision", req: Request{ID: "1", Operation: "update", Origin: "https://example.com", CredentialID: "x", Password: "secret"}, code: "invalid_request"},
		{name: "add totp missing uri", req: Request{ID: "1", Operation: "add_totp", Origin: "https://example.com", CredentialID: "x", Revision: "1"}, code: "invalid_request"},
		{name: "long origin", req: Request{ID: "1", Operation: "matches", Origin: "https://" + strings.Repeat("a", maxOriginBytes)}, code: "invalid_request"},
		{name: "long credential id", req: Request{ID: "1", Operation: "reveal", Origin: "https://example.com", CredentialID: strings.Repeat("a", maxCredentialID+1)}, code: "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := handle(context.Background(), tt.req)
			if response.OK || response.Error == nil || response.Error.Code != tt.code {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}

func TestWriteResponseFallsBackWhenResultIsTooLarge(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	err := writeResponse(&output, Response{
		ID:     "request-1",
		OK:     true,
		Result: strings.Repeat("x", maxMessageBytes),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := decodeResponse(t, output.Bytes())
	if response.OK || response.ID != "request-1" || response.Error == nil ||
		response.Error.Code != "response_too_large" {
		t.Fatalf("response = %+v", response)
	}
}

func TestReadRequestRejectsTrailingJSON(t *testing.T) {
	t.Parallel()
	payload := `{"id":"1","operation":"status"} {}`
	frame := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	_, err := readRequest(bytes.NewReader(frame))
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("err = %v", err)
	}
}
