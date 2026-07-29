// Package browserhost implements fd0's narrow Chrome Native Messaging
// protocol. It exposes only the origin-bound login lifecycle used by the
// extension; generic vault operations are deliberately unavailable.
package browserhost

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/browserconfig"
	"github.com/valentinkolb/fd0.sh/internal/cli"
)

const (
	maxMessageBytes = 64 * 1024
	maxRequestID    = 128
	maxOriginBytes  = 2048
	maxCredentialID = 1024
	maxFieldBytes   = 32 * 1024
)

type Request struct {
	ID           string `json:"id"`
	Operation    string `json:"operation"`
	Origin       string `json:"origin,omitempty"`
	CredentialID string `json:"credentialId,omitempty"`
	Revision     string `json:"revision,omitempty"`
	ScopeID      string `json:"scopeId,omitempty"`
	Title        string `json:"title,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	TOTPURI      string `json:"totpUri,omitempty"`
}

type Response struct {
	ID     string         `json:"id,omitempty"`
	OK     bool           `json:"ok"`
	Result any            `json:"result,omitempty"`
	Error  *ResponseError `json:"error,omitempty"`
}

type ResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type StatusResult struct {
	Unlocked bool `json:"unlocked"`
}

type MatchesResult struct {
	Credentials []cli.BrowserCredential `json:"credentials"`
}

type ScopesResult struct {
	Scopes []cli.BrowserScope `json:"scopes"`
}

// Run handles exactly one Native Messaging request. Chrome's
// sendNativeMessage API starts a fresh host process for each request.
func Run(ctx context.Context, callerOrigin string, in io.Reader, out io.Writer) error {
	req, err := readRequest(in)
	if err != nil {
		return writeResponse(out, errorResponse("", "invalid_request", err.Error()))
	}
	if !browserconfig.AllowsExtensionOrigin(callerOrigin) {
		return writeResponse(out, errorResponse(req.ID, "forbidden", "browser extension is not allowed"))
	}
	return writeResponse(out, handle(ctx, req))
}

func handle(ctx context.Context, req Request) Response {
	if message := validateRequest(req); message != "" {
		id := req.ID
		if len(id) > maxRequestID {
			id = ""
		}
		return errorResponse(id, "invalid_request", message)
	}
	switch req.Operation {
	case "status":
		s, err := cli.Open(ctx)
		if err != nil {
			return mappedError(req.ID, err)
		}
		s.Close()
		return Response{ID: req.ID, OK: true, Result: StatusResult{Unlocked: true}}
	case "matches":
		if req.CredentialID != "" {
			return errorResponse(req.ID, "invalid_request", "credentialId is not allowed for matches")
		}
		credentials, err := cli.BrowserCredentialsForOrigin(ctx, req.Origin)
		if err != nil {
			return mappedError(req.ID, err)
		}
		if credentials == nil {
			credentials = []cli.BrowserCredential{}
		}
		return Response{ID: req.ID, OK: true, Result: MatchesResult{Credentials: credentials}}
	case "scopes":
		scopes, err := cli.BrowserScopes(ctx)
		if err != nil {
			return mappedError(req.ID, err)
		}
		if scopes == nil {
			scopes = []cli.BrowserScope{}
		}
		return Response{ID: req.ID, OK: true, Result: ScopesResult{Scopes: scopes}}
	case "reveal":
		if req.CredentialID == "" {
			return errorResponse(req.ID, "invalid_request", "credentialId is required")
		}
		credential, err := cli.RevealBrowserCredential(ctx, req.Origin, req.CredentialID)
		if err != nil {
			return mappedError(req.ID, err)
		}
		return Response{ID: req.ID, OK: true, Result: credential}
	case "totp":
		result, err := cli.BrowserTOTPForCredential(ctx, req.Origin, req.CredentialID)
		if err != nil {
			return mappedError(req.ID, err)
		}
		return Response{ID: req.ID, OK: true, Result: result}
	case "save":
		result, err := cli.SaveBrowserLogin(ctx, cli.BrowserSaveLoginInput{
			Origin: req.Origin, ScopeID: req.ScopeID, Title: req.Title,
			Username: req.Username, Password: req.Password,
		})
		if err != nil {
			return mappedError(req.ID, err)
		}
		return Response{ID: req.ID, OK: true, Result: result}
	case "update":
		result, err := cli.UpdateBrowserLogin(ctx, cli.BrowserUpdateLoginInput{
			Origin: req.Origin, CredentialID: req.CredentialID,
			Revision: req.Revision, Title: req.Title,
			Username: req.Username, Password: req.Password,
		})
		if err != nil {
			return mappedError(req.ID, err)
		}
		return Response{ID: req.ID, OK: true, Result: result}
	case "add_totp":
		result, err := cli.AddBrowserTOTP(
			ctx, req.Origin, req.CredentialID, req.Revision, req.TOTPURI,
		)
		if err != nil {
			return mappedError(req.ID, err)
		}
		return Response{ID: req.ID, OK: true, Result: result}
	default:
		return errorResponse(req.ID, "unsupported_operation", "operation is not supported")
	}
}

func validateRequest(req Request) string {
	if req.ID == "" || len(req.ID) > maxRequestID {
		return "request id is required"
	}
	if len(req.Operation) > 32 {
		return "operation is invalid"
	}
	if len(req.Origin) > maxOriginBytes {
		return "origin is too long"
	}
	if len(req.CredentialID) > maxCredentialID {
		return "credentialId is too long"
	}
	if len(req.Title) > 128 || len(req.Username) > maxFieldBytes ||
		len(req.Password) > maxFieldBytes || len(req.TOTPURI) > 4096 ||
		len(req.ScopeID) > 128 || len(req.Revision) > 64 {
		return "request field is too long"
	}
	switch req.Operation {
	case "status":
		if hasBrowserPayload(req) {
			return "status does not accept request fields"
		}
	case "matches":
		if req.Origin == "" {
			return "origin is required"
		}
		if req.CredentialID != "" || hasMutationPayload(req) {
			return "matches accepts only origin"
		}
	case "scopes":
		if hasBrowserPayload(req) {
			return "scopes does not accept request fields"
		}
	case "reveal", "totp":
		if req.Origin == "" {
			return "origin is required"
		}
		if req.CredentialID == "" {
			return "credentialId is required"
		}
		if hasMutationPayload(req) {
			return req.Operation + " accepts only origin and credentialId"
		}
	case "save":
		if req.Origin == "" || req.Title == "" || req.Password == "" {
			return "origin, title, and password are required"
		}
		if req.CredentialID != "" || req.Revision != "" || req.TOTPURI != "" {
			return "save request contains unsupported fields"
		}
	case "update":
		if req.Origin == "" || req.CredentialID == "" || req.Revision == "" ||
			req.Title == "" || req.Password == "" {
			return "origin, credentialId, revision, title, and password are required"
		}
		if req.ScopeID != "" || req.TOTPURI != "" {
			return "update request contains unsupported fields"
		}
	case "add_totp":
		if req.Origin == "" || req.CredentialID == "" || req.Revision == "" || req.TOTPURI == "" {
			return "origin, credentialId, revision, and totpUri are required"
		}
		if req.ScopeID != "" || req.Title != "" || req.Username != "" || req.Password != "" {
			return "add_totp request contains unsupported fields"
		}
	}
	return ""
}

func hasMutationPayload(req Request) bool {
	return req.Revision != "" || req.ScopeID != "" || req.Title != "" ||
		req.Username != "" || req.Password != "" || req.TOTPURI != ""
}

func hasBrowserPayload(req Request) bool {
	return req.Origin != "" || req.CredentialID != "" || hasMutationPayload(req)
}

func mappedError(id string, err error) Response {
	switch {
	case errors.Is(err, cli.ErrAgentLocked):
		return errorResponse(id, "locked", "Unlock fd0 in the desktop app, then try again.")
	case errors.Is(err, cli.ErrAgentNotRunning):
		return errorResponse(id, "unavailable", "Open fd0, unlock it, and try again.")
	case strings.Contains(err.Error(), "changed; review"):
		return errorResponse(id, "conflict", "This login changed in fd0. Review it and try again.")
	case strings.Contains(err.Error(), "already exists"):
		return errorResponse(id, "already_exists", "A login with this name already exists in that vault.")
	case strings.Contains(err.Error(), "invalid browser") ||
		strings.Contains(err.Error(), "must use https") ||
		strings.Contains(err.Error(), "does not match this origin"):
		return errorResponse(id, "invalid_request", "fd0 refused this browser request.")
	default:
		return errorResponse(id, "request_failed", "fd0 could not complete this request.")
	}
}

func errorResponse(id, code, message string) Response {
	return Response{
		ID: id,
		OK: false,
		Error: &ResponseError{
			Code:    code,
			Message: message,
		},
	}
}

func readRequest(r io.Reader) (Request, error) {
	payload, err := readFrame(r)
	if err != nil {
		return Request{}, err
	}
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		return Request{}, fmt.Errorf("decode request: %w", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return Request{}, errors.New("decode request: trailing JSON")
	}
	return req, nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read message length: %w", err)
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size == 0 || size > maxMessageBytes {
		return nil, fmt.Errorf("message length %d is outside 1..%d", size, maxMessageBytes)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	return payload, nil
}

func writeResponse(w io.Writer, response Response) error {
	payload, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("encode response: %w", err)
	}
	if len(payload) > maxMessageBytes {
		payload, err = json.Marshal(errorResponse(response.ID, "response_too_large", "fd0 found too many matching logins."))
		if err != nil {
			return fmt.Errorf("encode oversized response fallback: %w", err)
		}
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write response length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}
