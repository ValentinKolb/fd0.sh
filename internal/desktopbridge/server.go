package desktopbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
)

type Handler interface {
	Handle(context.Context, string, json.RawMessage) (any, error)
}

type Server struct {
	Handler Handler
}

func (s Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Handler == nil {
		return errors.New("desktop bridge: nil handler")
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), MaxFrameBytes+1)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame := append([]byte(nil), scanner.Bytes()...)
		if len(frame) == 0 {
			continue
		}
		if len(frame) > MaxFrameBytes {
			crypto.Wipe(frame)
			return fmt.Errorf("desktop bridge: frame exceeds %d bytes", MaxFrameBytes)
		}
		response := s.handleFrame(ctx, frame)
		crypto.Wipe(frame)
		if err := writeResponse(out, response); err != nil {
			wipeResponse(response)
			return err
		}
		wipeResponse(response)
	}
	if err := scanner.Err(); err != nil {
		if strings.Contains(err.Error(), "token too long") {
			return fmt.Errorf("desktop bridge: frame exceeds %d bytes", MaxFrameBytes)
		}
		return fmt.Errorf("desktop bridge: read: %w", err)
	}
	return nil
}

type wipeableResult interface {
	Wipe()
}

func wipeResponse(response Response) {
	if result, ok := response.Result.(wipeableResult); ok {
		result.Wipe()
	}
}

func (s Server) handleFrame(ctx context.Context, frame []byte) Response {
	response := Response{Version: ProtocolVersion}
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	var request Request
	defer func() { crypto.Wipe(request.Params) }()
	if err := decodeOne(decoder, &request); err != nil {
		response.Error = &BridgeError{Code: "bad_request", Message: "The desktop bridge received an invalid request."}
		return response
	}
	response.ID = request.ID
	if request.Version != ProtocolVersion {
		response.Error = &BridgeError{
			Code:    "incompatible_version",
			Message: "The desktop app and fd0 bridge are not compatible.",
			Action:  "Update or reinstall fd0 Desktop.",
		}
		return response
	}
	if request.ID == "" || len(request.ID) > 128 || strings.ContainsAny(request.ID, "\r\n") {
		response.Error = &BridgeError{Code: "bad_request", Message: "The desktop bridge received an invalid request ID."}
		return response
	}
	if request.Method == "" || len(request.Method) > 128 {
		response.Error = &BridgeError{Code: "bad_request", Message: "The desktop bridge received an invalid method."}
		return response
	}
	result, err := s.Handler.Handle(ctx, request.Method, request.Params)
	if err != nil {
		var typed *methodError
		if errors.As(err, &typed) {
			copy := typed.bridge
			response.Error = &copy
		} else {
			response.Error = &BridgeError{
				Code:      "internal",
				Message:   "fd0 could not complete that action.",
				Action:    "Try again. Open Support if the problem continues.",
				Retryable: true,
			}
		}
		return response
	}
	response.Result = result
	return response
}

func decodeOne(decoder *json.Decoder, target any) error {
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func writeResponse(out io.Writer, response Response) error {
	frame, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("desktop bridge: encode response: %w", err)
	}
	if len(frame) > MaxFrameBytes {
		crypto.Wipe(frame)
		response.Result = nil
		response.Error = &BridgeError{
			Code:    "response_too_large",
			Message: "fd0 could not display that much data at once.",
			Action:  "Narrow the current view and try again.",
		}
		frame, err = json.Marshal(response)
		if err != nil {
			return fmt.Errorf("desktop bridge: encode bounded response: %w", err)
		}
	}
	defer crypto.Wipe(frame)
	frame = append(frame, '\n')
	_, err = out.Write(frame)
	return err
}
