package sftpbridge

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/sftpclient"
)

const (
	ProtocolVersion = 1
	MaxFrameBytes   = 1 << 20
	maxEntries      = 10_000
	maxConcurrent   = 16
	maxPreviewBytes = 128 * 1024
)

type Request struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Action    string `json:"action,omitempty"`
	Retryable bool   `json:"retryable,omitempty"`
}

type Frame struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Event   string `json:"event,omitempty"`
	Data    any    `json:"data,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Client interface {
	WorkingDirectory() (string, error)
	ReadDir(context.Context, string) ([]sftpclient.Entry, error)
	Stat(string, bool) (sftpclient.Entry, error)
	ReadPreview(string, int64) (sftpclient.Preview, error)
	Mkdir(string, bool) error
	Rename(string, string, bool) error
	Remove(context.Context, string, bool) error
	DownloadPath(context.Context, string, string, sftpclient.TransferOptions, sftpclient.Progress) (sftpclient.TransferResult, error)
	UploadPath(context.Context, string, string, sftpclient.TransferOptions, sftpclient.Progress) (sftpclient.TransferResult, error)
}

type Server struct {
	Client Client

	writerMu sync.Mutex
	activeMu sync.Mutex
	active   map[string]context.CancelFunc
}

func (s *Server) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	if s.Client == nil {
		return errors.New("sftp bridge: nil client")
	}
	s.active = make(map[string]context.CancelFunc)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), MaxFrameBytes+1)
	var workers sync.WaitGroup
	slots := make(chan struct{}, maxConcurrent)
	defer func() {
		s.cancelAll()
		workers.Wait()
	}()
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame := append([]byte(nil), scanner.Bytes()...)
		if len(frame) == 0 {
			continue
		}
		if len(frame) > MaxFrameBytes {
			return fmt.Errorf("sftp bridge: frame exceeds %d bytes", MaxFrameBytes)
		}
		request, requestErr := decodeRequest(frame)
		if requestErr != nil {
			if err := s.write(output, Frame{
				Version: ProtocolVersion,
				Error:   &Error{Code: "bad_request", Message: "fd0 received an invalid file request."},
			}); err != nil {
				return err
			}
			continue
		}
		if request.Method == "transfer.cancel" {
			var params struct {
				TransferID string `json:"transferId"`
			}
			if err := decodeParams(request.Params, &params); err != nil || params.TransferID == "" {
				if writeErr := s.write(output, Frame{
					Version: ProtocolVersion,
					ID:      request.ID,
					Error:   &Error{Code: "bad_request", Message: "fd0 received an invalid cancellation request."},
				}); writeErr != nil {
					return writeErr
				}
				continue
			}
			s.cancel(params.TransferID)
			if err := s.write(output, Frame{Version: ProtocolVersion, ID: request.ID, Result: map[string]bool{"cancelled": true}}); err != nil {
				return err
			}
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			if err := s.write(output, Frame{
				Version: ProtocolVersion,
				ID:      request.ID,
				Error: &Error{
					Code:      "busy",
					Message:   "Too many remote file operations are active.",
					Action:    "Wait for an operation to finish and try again.",
					Retryable: true,
				},
			}); err != nil {
				return err
			}
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			s.handle(ctx, output, request)
		}()
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (s *Server) handle(parent context.Context, output io.Writer, request Request) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if strings.HasPrefix(request.Method, "transfer.") {
		s.activeMu.Lock()
		if previous := s.active[request.ID]; previous != nil {
			previous()
		}
		s.active[request.ID] = cancel
		s.activeMu.Unlock()
		defer func() {
			s.activeMu.Lock()
			delete(s.active, request.ID)
			s.activeMu.Unlock()
		}()
	}
	result, err := s.dispatch(ctx, output, request)
	frame := Frame{Version: ProtocolVersion, ID: request.ID, Result: result}
	if err != nil {
		frame.Result = nil
		frame.Error = publicError(err)
	}
	if err := s.write(output, frame); err != nil {
		_ = s.write(output, Frame{
			Version: ProtocolVersion,
			ID:      request.ID,
			Error: &Error{
				Code:    "response_too_large",
				Message: "That directory contains too much metadata to display safely.",
				Action:  "Open a smaller directory or use a narrower path.",
			},
		})
	}
}

func (s *Server) dispatch(ctx context.Context, output io.Writer, request Request) (any, error) {
	switch request.Method {
	case "session.info":
		var params struct{}
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		workingDirectory, err := s.Client.WorkingDirectory()
		if err != nil {
			return nil, err
		}
		return map[string]string{"workingDirectory": workingDirectory}, nil
	case "dir.list":
		var params struct {
			Path string `json:"path"`
		}
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.Path); err != nil {
			return nil, err
		}
		entries, err := s.Client.ReadDir(ctx, params.Path)
		if err != nil {
			return nil, err
		}
		if len(entries) > maxEntries {
			return nil, errors.New("too many remote directory entries")
		}
		return entries, nil
	case "file.stat":
		var params struct {
			Path string `json:"path"`
		}
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.Path); err != nil {
			return nil, err
		}
		return s.Client.Stat(params.Path, false)
	case "file.preview":
		var params struct {
			Path string `json:"path"`
		}
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.Path); err != nil {
			return nil, err
		}
		return s.Client.ReadPreview(params.Path, maxPreviewBytes)
	case "dir.mkdir":
		var params struct {
			Path    string `json:"path"`
			Parents bool   `json:"parents"`
		}
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.Path); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.Client.Mkdir(params.Path, params.Parents)
	case "path.rename":
		var params struct {
			Old   string `json:"old"`
			New   string `json:"new"`
			Force bool   `json:"force"`
		}
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.Old); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.New); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.Client.Rename(params.Old, params.New, params.Force)
	case "path.remove":
		var params struct {
			Path      string `json:"path"`
			Recursive bool   `json:"recursive"`
		}
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.Path); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, s.Client.Remove(ctx, params.Path, params.Recursive)
	case "transfer.download":
		var params transferParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.RemotePath); err != nil {
			return nil, err
		}
		if err := validateLocalPath(params.LocalPath); err != nil {
			return nil, err
		}
		return s.Client.DownloadPath(ctx, params.RemotePath, params.LocalPath, sftpclient.TransferOptions{
			Recursive: params.Recursive,
			Force:     params.Force,
		}, s.progress(output, request.ID))
	case "transfer.upload":
		var params transferParams
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		if err := validateRemotePath(params.RemotePath); err != nil {
			return nil, err
		}
		if err := validateLocalPath(params.LocalPath); err != nil {
			return nil, err
		}
		return s.Client.UploadPath(ctx, params.LocalPath, params.RemotePath, sftpclient.TransferOptions{
			Recursive: params.Recursive,
			Force:     params.Force,
		}, s.progress(output, request.ID))
	default:
		return nil, errors.New("unsupported SFTP bridge method")
	}
}

type transferParams struct {
	LocalPath  string `json:"localPath"`
	RemotePath string `json:"remotePath"`
	Recursive  bool   `json:"recursive"`
	Force      bool   `json:"force"`
}

func (s *Server) progress(output io.Writer, id string) sftpclient.Progress {
	var (
		mu   sync.Mutex
		last time.Time
	)
	return func(transferred, total int64) {
		mu.Lock()
		defer mu.Unlock()
		now := time.Now()
		if transferred != total && now.Sub(last) < 100*time.Millisecond {
			return
		}
		last = now
		_ = s.write(output, Frame{
			Version: ProtocolVersion,
			ID:      id,
			Event:   "progress",
			Data: map[string]int64{
				"transferred": transferred,
				"total":       total,
			},
		})
	}
}

func (s *Server) write(output io.Writer, frame Frame) error {
	value, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if len(value) > MaxFrameBytes {
		return errors.New("sftp bridge: response too large")
	}
	s.writerMu.Lock()
	defer s.writerMu.Unlock()
	value = append(value, '\n')
	_, err = output.Write(value)
	return err
}

func (s *Server) cancel(id string) {
	s.activeMu.Lock()
	cancel := s.active[id]
	s.activeMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) cancelAll() {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	for _, cancel := range s.active {
		cancel()
	}
}

func decodeRequest(frame []byte) (Request, error) {
	decoder := json.NewDecoder(bytes.NewReader(frame))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("multiple JSON values")
	}
	if request.Version != ProtocolVersion || request.ID == "" || len(request.ID) > 128 ||
		request.Method == "" || len(request.Method) > 128 || strings.ContainsAny(request.ID, "\r\n") {
		return Request{}, errors.New("invalid request envelope")
	}
	return request, nil
}

func decodeParams(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid request parameters")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid request parameters")
	}
	return nil
}

func validateRemotePath(value string) error {
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, '\x00') {
		return errors.New("invalid remote path")
	}
	return nil
}

func validateLocalPath(value string) error {
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, '\x00') || !filepath.IsAbs(value) {
		return errors.New("invalid local path")
	}
	return nil
}

func publicError(err error) *Error {
	switch {
	case errors.Is(err, context.Canceled):
		return &Error{Code: "cancelled", Message: "The file transfer was cancelled."}
	case strings.HasPrefix(err.Error(), "invalid "):
		return &Error{Code: "bad_request", Message: "fd0 received an invalid file request."}
	case strings.Contains(err.Error(), "host key verification failed"):
		return &Error{
			Code:    "host_unverified",
			Message: "This server has not been verified on this device.",
			Action:  "Open the server in Terminal once and verify its host key.",
		}
	case strings.Contains(err.Error(), "authentication was denied"):
		return &Error{
			Code:    "authentication_failed",
			Message: "The server did not accept the configured fd0 SSH key.",
			Action:  "Unlock fd0 and check the key assigned to this server.",
		}
	case strings.Contains(err.Error(), "does not provide the SFTP subsystem"):
		return &Error{
			Code:    "sftp_unavailable",
			Message: "This server does not provide SFTP file access.",
			Action:  "Enable the SFTP subsystem on the server or use Terminal.",
		}
	case strings.Contains(err.Error(), "not unlocked"),
		strings.Contains(err.Error(), "agent socket unavailable"):
		return &Error{
			Code:      "vault_locked",
			Message:   "Unlock fd0 before browsing remote files.",
			Action:    "Return to the main fd0 window and unlock the vault.",
			Retryable: true,
		}
	case errors.Is(err, io.EOF),
		strings.Contains(strings.ToLower(err.Error()), "connection lost"),
		strings.Contains(strings.ToLower(err.Error()), "connection reset"),
		strings.Contains(strings.ToLower(err.Error()), "connection closed"):
		return &Error{
			Code:      "disconnected",
			Message:   "The server closed the file session.",
			Action:    "Check the network connection and try again.",
			Retryable: true,
		}
	case os.IsNotExist(err), strings.Contains(err.Error(), "no such file"):
		return &Error{Code: "not_found", Message: "That remote file no longer exists.", Retryable: true}
	case os.IsPermission(err), strings.Contains(strings.ToLower(err.Error()), "permission denied"):
		return &Error{Code: "permission_denied", Message: "The server refused that file operation."}
	case strings.Contains(strings.ToLower(err.Error()), "no space left"),
		strings.Contains(strings.ToLower(err.Error()), "disk quota exceeded"):
		return &Error{
			Code:    "disk_full",
			Message: "The destination does not have enough free space.",
			Action:  "Free space on the destination and try again.",
		}
	case strings.Contains(err.Error(), "already exists"):
		return &Error{Code: "exists", Message: "A file or folder already exists at that destination."}
	default:
		return &Error{
			Code:      "file_operation_failed",
			Message:   "fd0 could not complete that remote file operation.",
			Action:    "Try again. Open Support if the problem continues.",
			Retryable: true,
		}
	}
}
