package sftpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/sftpclient"
)

type fakeClient struct {
	entries []sftpclient.Entry
}

func (f *fakeClient) WorkingDirectory() (string, error) { return "/srv/data", nil }
func (f *fakeClient) ReadDir(context.Context, string) ([]sftpclient.Entry, error) {
	return f.entries, nil
}
func (f *fakeClient) Stat(path string, _ bool) (sftpclient.Entry, error) {
	return sftpclient.Entry{Name: "file.txt", Path: path, Type: "file"}, nil
}
func (f *fakeClient) ReadPreview(string, int64) (sftpclient.Preview, error) {
	return sftpclient.Preview{Data: []byte("preview\n"), Size: 8}, nil
}
func (f *fakeClient) Mkdir(string, bool) error                   { return nil }
func (f *fakeClient) Rename(string, string, bool) error          { return nil }
func (f *fakeClient) Remove(context.Context, string, bool) error { return nil }
func (f *fakeClient) DownloadPath(
	ctx context.Context,
	remotePath string,
	_ string,
	_ sftpclient.TransferOptions,
	progress sftpclient.Progress,
) (sftpclient.TransferResult, error) {
	progress(4, 10)
	select {
	case <-ctx.Done():
		return sftpclient.TransferResult{}, ctx.Err()
	default:
	}
	progress(10, 10)
	return sftpclient.TransferResult{Path: remotePath, Bytes: 10}, nil
}
func (f *fakeClient) UploadPath(
	context.Context,
	string,
	string,
	sftpclient.TransferOptions,
	sftpclient.Progress,
) (sftpclient.TransferResult, error) {
	return sftpclient.TransferResult{}, errors.New("permission denied")
}

func serveFrames(t *testing.T, input string) []Frame {
	t.Helper()
	return serveFramesWithClient(t, input, &fakeClient{
		entries: []sftpclient.Entry{{
			Name:       "file.txt",
			Path:       "/srv/data/file.txt",
			Type:       "file",
			Size:       10,
			Mode:       "-rw-------",
			ModifiedAt: time.Unix(1, 0).UTC(),
		}},
	})
}

func serveFramesWithClient(t *testing.T, input string, client Client) []Frame {
	t.Helper()
	var output bytes.Buffer
	server := &Server{Client: client}
	if err := server.Serve(context.Background(), bytes.NewBufferString(input), &output); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var frames []Frame
	decoder := json.NewDecoder(&output)
	for decoder.More() {
		var frame Frame
		if err := decoder.Decode(&frame); err != nil {
			t.Fatalf("decode frame: %v", err)
		}
		frames = append(frames, frame)
	}
	return frames
}

func TestSessionAndDirectoryProtocol(t *testing.T) {
	frames := serveFrames(t,
		`{"version":1,"id":"session","method":"session.info","params":{}}`+"\n"+
			`{"version":1,"id":"list","method":"dir.list","params":{"path":"/srv/data"}}`+"\n",
	)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	seen := map[string]Frame{}
	for _, frame := range frames {
		seen[frame.ID] = frame
	}
	if seen["session"].Error != nil || seen["list"].Error != nil {
		t.Fatalf("unexpected errors: %#v", frames)
	}
}

func TestFilePreviewProtocolReturnsBoundedBytes(t *testing.T) {
	frames := serveFrames(t,
		`{"version":1,"id":"preview","method":"file.preview","params":{"path":"/srv/data/file.txt"}}`+"\n",
	)
	if len(frames) != 1 || frames[0].Error != nil {
		t.Fatalf("unexpected frames: %#v", frames)
	}
	result, ok := frames[0].Result.(map[string]any)
	if !ok || result["data"] != "cHJldmlldwo=" || result["size"] != float64(8) || result["truncated"] != false {
		t.Fatalf("unexpected preview: %#v", frames[0].Result)
	}
}

func TestTransferProgressAndPublicErrors(t *testing.T) {
	frames := serveFrames(t,
		`{"version":1,"id":"download","method":"transfer.download","params":{"remotePath":"/srv/data/file.txt","localPath":"/tmp/file.txt"}}`+"\n"+
			`{"version":1,"id":"upload","method":"transfer.upload","params":{"remotePath":"/srv/data/file.txt","localPath":"/tmp/file.txt"}}`+"\n",
	)
	var progress bool
	var uploadError *Error
	for _, frame := range frames {
		if frame.ID == "download" && frame.Event == "progress" {
			progress = true
		}
		if frame.ID == "upload" {
			uploadError = frame.Error
		}
	}
	if !progress {
		t.Fatal("missing transfer progress frame")
	}
	if uploadError == nil || uploadError.Code != "permission_denied" {
		t.Fatalf("unexpected upload error: %#v", uploadError)
	}
}

func TestRejectsInvalidRemotePath(t *testing.T) {
	frames := serveFrames(t,
		`{"version":1,"id":"bad","method":"dir.list","params":{"path":"bad\u0000path"}}`+"\n",
	)
	if len(frames) != 1 || frames[0].Error == nil || frames[0].Error.Code != "bad_request" {
		t.Fatalf("unexpected frames: %#v", frames)
	}
}

func TestPublicErrorsStayActionableAndDoNotEchoDiagnostics(t *testing.T) {
	for _, test := range []struct {
		err  error
		code string
	}{
		{err: errors.New("write /Users/alice/private: no space left on device"), code: "disk_full"},
		{err: errors.New("ssh: connection reset by peer alice@example"), code: "disconnected"},
		{err: errors.New("sftp: authentication was denied; secret diagnostic"), code: "authentication_failed"},
	} {
		got := publicError(test.err)
		if got.Code != test.code {
			t.Fatalf("error=%v code=%q want=%q", test.err, got.Code, test.code)
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("alice")) || bytes.Contains(encoded, []byte("/Users/")) {
			t.Fatalf("public error leaked diagnostics: %s", encoded)
		}
	}
}

func TestOversizedMetadataReturnsBoundedError(t *testing.T) {
	frames := serveFramesWithClient(t,
		`{"version":1,"id":"huge","method":"dir.list","params":{"path":"/srv/data"}}`+"\n",
		&fakeClient{entries: []sftpclient.Entry{{
			Name: strings.Repeat("x", MaxFrameBytes),
			Path: "/srv/data/file",
			Type: "file",
		}}},
	)
	if len(frames) != 1 || frames[0].Error == nil || frames[0].Error.Code != "response_too_large" {
		t.Fatalf("unexpected frames: %#v", frames)
	}
}
