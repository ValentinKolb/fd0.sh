package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateVersionHelpers(t *testing.T) {
	cases := []struct {
		in      string
		tag     string
		version string
	}{
		{"0.8.0", "client-v0.8.0", "0.8.0"},
		{"v0.8.0", "client-v0.8.0", "0.8.0"},
		{"client-v0.8.0", "client-v0.8.0", "0.8.0"},
		{"fd0-v1.2.3", "fd0-v1.2.3", "1.2.3"},
	}
	for _, c := range cases {
		if got := canonicalClientReleaseTag(c.in); got != c.tag {
			t.Fatalf("canonicalClientReleaseTag(%q)=%q want %q", c.in, got, c.tag)
		}
		if got := releaseVersionNumber(c.tag); got != c.version {
			t.Fatalf("releaseVersionNumber(%q)=%q want %q", c.tag, got, c.version)
		}
	}
	if cmp, ok := compareVersionStrings("0.8.0", "0.9.0"); !ok || cmp >= 0 {
		t.Fatalf("compare 0.8.0 vs 0.9.0 = %d %v, want less", cmp, ok)
	}
}

func TestRunUpdateCheckUsesLatestClientRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `[
			{"tag_name":"website-v0.0.99","draft":false,"prerelease":false},
			{"tag_name":"client-v0.9.0-rc.1","draft":false,"prerelease":true},
			{"tag_name":"client-v0.9.0","draft":false,"prerelease":false}
		]`)
	}))
	defer srv.Close()
	var out bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		CheckOnly:      true,
		APIBase:        srv.URL,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         &out,
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
		Executable:     filepath.Join(t.TempDir(), "fd0"),
	})
	if !errors.Is(err, ErrUpdateAvailable) {
		t.Fatalf("RunUpdate error=%v, want ErrUpdateAvailable", err)
	}
	if !strings.Contains(out.String(), "fd0 0.9.0 is available") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunUpdateInstallsVerifiedArchive(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	srv := updateFixtureServer(t, archive, hex.EncodeToString(sum[:]))
	var out, stderr bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		Version:        "0.9.0",
		Prefix:         prefix,
		Yes:            true,
		NoVerify:       true,
		APIBase:        srv.URL,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         &out,
		Stderr:         &stderr,
		GOOS:           "linux",
		GOARCH:         "amd64",
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), stderr.String())
	}
	for _, name := range []string{"fd0", "fd0-agent"} {
		path := filepath.Join(prefix, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if st.Mode()&0o111 == 0 {
			t.Fatalf("%s is not executable: %v", name, st.Mode())
		}
	}
	if !strings.Contains(out.String(), "updated fd0 to 0.9.0") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunUpdateRejectsChecksumMismatch(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	prefix := t.TempDir()
	srv := updateFixtureServer(t, archive, strings.Repeat("0", sha256.Size*2))
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		Version:        "client-v0.9.0",
		Prefix:         prefix,
		Yes:            true,
		NoVerify:       true,
		APIBase:        srv.URL,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         ioDiscard{},
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("RunUpdate error=%v, want sha256 mismatch", err)
	}
}

func makeUpdateArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		b := []byte(body)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func updateFixtureServer(t *testing.T, archive []byte, checksum string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/download/client-v0.9.0/fd0_linux_amd64.tar.gz":
			_, _ = w.Write(archive)
		case "/download/client-v0.9.0/checksums.txt":
			fmt.Fprintf(w, "%s  fd0_linux_amd64.tar.gz\n", checksum)
		default:
			http.NotFound(w, r)
		}
	}))
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
