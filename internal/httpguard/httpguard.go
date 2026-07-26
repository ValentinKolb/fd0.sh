package httpguard

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

var ErrResponseTooLarge = errors.New("HTTP response body exceeds limit")

func ReadBody(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, fmt.Errorf("invalid response body limit %d", maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%w (%d bytes)", ErrResponseTooLarge, maxBytes)
	}
	return body, nil
}

func RejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}
