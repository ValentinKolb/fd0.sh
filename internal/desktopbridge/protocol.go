package desktopbridge

import "encoding/json"

const (
	ProtocolVersion = 1
	MaxFrameBytes   = 1 << 20
)

type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Version int          `json:"version"`
	ID      string       `json:"id,omitempty"`
	Result  any          `json:"result,omitempty"`
	Error   *BridgeError `json:"error,omitempty"`
}

type BridgeError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Action    string `json:"action,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
}

type methodError struct {
	bridge BridgeError
}

func (e *methodError) Error() string { return e.bridge.Message }

func fail(code, message, action string, retryable bool) error {
	return &methodError{bridge: BridgeError{
		Code:      code,
		Message:   message,
		Action:    action,
		Retryable: retryable,
	}}
}
