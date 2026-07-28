package sftpclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/sftp"
)

func TestClientTransfersExactBytesThroughPipe(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "remote.txt"), []byte("remote bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, root)
	defer client.Close()

	entries, err := client.ReadDir(context.Background(), ".")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "remote.txt" || entries[0].Type != "file" {
		t.Fatalf("entries=%+v", entries)
	}

	var downloaded bytes.Buffer
	if _, err := client.Download(context.Background(), "remote.txt", &downloaded, nil); err != nil {
		t.Fatal(err)
	}
	if got := downloaded.String(); got != "remote bytes\n" {
		t.Fatalf("download=%q", got)
	}

	const upload = "upload \x00 bytes\n"
	if _, err := client.Upload(
		context.Background(),
		bytes.NewBufferString(upload),
		"uploaded.txt",
		0o600,
		int64(len(upload)),
		nil,
	); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "uploaded.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != upload {
		t.Fatalf("uploaded=%q", got)
	}
}

func TestClientPreviewIsBounded(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "remote.txt"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, root)
	defer client.Close()

	preview, err := client.ReadPreview("remote.txt", 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(preview.Data) != "0123" || preview.Size != 10 || !preview.Truncated {
		t.Fatalf("preview=%+v", preview)
	}
}

func TestClientDoesNotFollowSymlinkDuringRecursiveRemove(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "tree"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "tree", "outside")); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, root)
	defer client.Close()

	if err := client.Remove(context.Background(), "tree", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep.txt")); err != nil {
		t.Fatalf("symlink target changed: %v", err)
	}
}

func TestDialRejectsNULArguments(t *testing.T) {
	_, err := Dial(context.Background(), Command{Binary: "/usr/bin/ssh", Args: []string{"bad\x00arg"}})
	if err == nil {
		t.Fatal("expected invalid argument error")
	}
}

func TestDownloadedModesStayPrivate(t *testing.T) {
	if got := privateMode("-rw-r--r--"); got != os.FileMode(0o600) {
		t.Fatalf("regular mode=%o", got)
	}
	if got := privateMode("-rwxr-xr-x"); got != os.FileMode(0o700) {
		t.Fatalf("executable mode=%o", got)
	}
	if got := privateMode("drwxr-xr-x"); got != os.FileMode(0o700) {
		t.Fatalf("directory mode=%o", got)
	}
}

func TestCancelledDownloadPreservesDestinationAndCleansTemporaryFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "remote.txt"), bytes.Repeat([]byte("x"), 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	local := t.TempDir()
	destination := filepath.Join(local, "download.txt")
	if err := os.WriteFile(destination, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, root)
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.DownloadPath(ctx, "remote.txt", destination, TransferOptions{Force: true}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("DownloadPath error=%v", err)
	}
	value, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "keep" {
		t.Fatalf("destination changed to %q", value)
	}
	entries, err := os.ReadDir(local)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "download.txt" {
		t.Fatalf("temporary files remain: %#v", entries)
	}
}

func TestRecursiveUploadRefusesSymlinksWithoutCreatingDestination(t *testing.T) {
	root := t.TempDir()
	local := t.TempDir()
	if err := os.WriteFile(filepath.Join(local, "target.txt"), []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.txt", filepath.Join(local, "link.txt")); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, root)
	defer client.Close()

	if _, err := client.UploadPath(
		context.Background(),
		local,
		"uploaded",
		TransferOptions{Recursive: true},
		nil,
	); err == nil {
		t.Fatal("expected recursive symlink upload to fail")
	}
	if _, err := os.Lstat(filepath.Join(root, "uploaded")); !os.IsNotExist(err) {
		t.Fatalf("destination should not exist: %v", err)
	}
}

func testClient(t *testing.T, root string) *Client {
	t.Helper()
	client, err := Dial(context.Background(), Command{
		Binary: os.Args[0],
		Args:   []string{"-test.run=TestSFTPHelperProcess", "--"},
		Env: append(os.Environ(),
			"GO_WANT_SFTP_HELPER=1",
			"FD0_TEST_SFTP_ROOT="+root,
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestSFTPHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SFTP_HELPER") != "1" {
		return
	}
	if err := os.Chdir(os.Getenv("FD0_TEST_SFTP_ROOT")); err != nil {
		t.Fatal(err)
	}
	server, err := sftp.NewServer(stdioReadWriteCloser{})
	if err != nil {
		t.Fatal(err)
	}
	err = server.Serve()
	_ = server.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

type stdioReadWriteCloser struct{}

func (stdioReadWriteCloser) Read(value []byte) (int, error)  { return os.Stdin.Read(value) }
func (stdioReadWriteCloser) Write(value []byte) (int, error) { return os.Stdout.Write(value) }
func (stdioReadWriteCloser) Close() error                    { return nil }
