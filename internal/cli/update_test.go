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
		dl      string
		version string
	}{
		{"0.8.0", "client-v0.8.0", "v0.8.0", "0.8.0"},
		{"v0.8.0", "client-v0.8.0", "v0.8.0", "0.8.0"},
		{"client-v0.8.0", "client-v0.8.0", "v0.8.0", "0.8.0"},
		{"fd0-v1.2.3", "fd0-v1.2.3", "v1.2.3", "1.2.3"},
	}
	for _, c := range cases {
		if got := canonicalClientReleaseTag(c.in); got != c.tag {
			t.Fatalf("canonicalClientReleaseTag(%q)=%q want %q", c.in, got, c.tag)
		}
		if got := explicitDownloadTag(c.in); got != c.dl {
			t.Fatalf("explicitDownloadTag(%q)=%q want %q", c.in, got, c.dl)
		}
		if got := releaseVersionNumber(c.tag); got != c.version {
			t.Fatalf("releaseVersionNumber(%q)=%q want %q", c.tag, got, c.version)
		}
	}
	if cmp, ok := compareVersionStrings("0.8.0", "0.9.0"); !ok || cmp >= 0 {
		t.Fatalf("compare 0.8.0 vs 0.9.0 = %d %v, want less", cmp, ok)
	}
	if got := parseFD0VersionOutput("fd0 0.9.0\n"); got.Version != "0.9.0" || got.Flavor != "standard" {
		t.Fatalf("old version parse=%+v, want 0.9.0 standard", got)
	}
	if got := parseFD0VersionOutput("fd0 0.9.0 yubikey\n"); got.Version != "0.9.0" || got.Flavor != "yubikey" {
		t.Fatalf("new version parse=%+v, want 0.9.0 yubikey", got)
	}
	if got := updateArchiveName("standard", "linux_amd64"); got != "fd0_linux_amd64.tar.gz" {
		t.Fatalf("standard archive=%q", got)
	}
	if got := updateArchiveName("yubikey", "linux_amd64"); got != "fd0_yubikey_linux_amd64.tar.gz" {
		t.Fatalf("yubikey archive=%q", got)
	}
}

func TestRunUpdateCheckUsesLatestClientRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `[
			{"name":"website-v0.0.99","tag_name":"website-v0.0.99","draft":false,"prerelease":false},
			{"name":"client-v0.9.0-rc.1","tag_name":"v0.9.0-rc.1","draft":false,"prerelease":true},
			{"name":"client-v0.9.0","tag_name":"v0.9.0","draft":false,"prerelease":false}
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
	if !strings.Contains(out.String(), "fd0 0.9.0 standard is available") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "client-v0.9.0") {
		t.Fatalf("output should show scoped release name:\n%s", out.String())
	}
}

func TestRunUpdateInstallsVerifiedArchive(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
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
	if !strings.Contains(out.String(), "updated fd0 to 0.9.0 standard") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunUpdatePreservesYubikeyFlavor(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0 yubikey\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0 yubikey\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	if err := os.WriteFile(filepath.Join(prefix, "fd0"), []byte("#!/bin/sh\necho fd0 0.8.0 yubikey\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_yubikey_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
	var out, stderr bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		Version:     "0.9.0",
		Prefix:      prefix,
		Yes:         true,
		NoVerify:    true,
		APIBase:     srv.URL,
		ReleaseBase: srv.URL,
		HTTPClient:  srv.Client(),
		Stdout:      &out,
		Stderr:      &stderr,
		GOOS:        "linux",
		GOARCH:      "amd64",
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "fd0_yubikey_linux_amd64.tar.gz") {
		t.Fatalf("update did not fetch yubikey archive:\n%s", stderr.String())
	}
	if !strings.Contains(out.String(), "updated fd0 to 0.9.0 yubikey") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunUpdateExplicitFlavorSwitchAtSameVersion(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0 yubikey\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0 yubikey\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	if err := os.WriteFile(filepath.Join(prefix, "fd0"), []byte("#!/bin/sh\necho fd0 0.9.0 standard\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_yubikey_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
	var out bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		Version:     "0.9.0",
		Flavor:      "yubikey",
		Prefix:      prefix,
		Yes:         true,
		NoVerify:    true,
		APIBase:     srv.URL,
		ReleaseBase: srv.URL,
		HTTPClient:  srv.Client(),
		Stdout:      &out,
		Stderr:      ioDiscard{},
		GOOS:        "linux",
		GOARCH:      "amd64",
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v\nstdout:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "action:  switch flavor") {
		t.Fatalf("expected switch flavor action:\n%s", out.String())
	}
}

func TestRunUpdateRejectsChecksumMismatch(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	prefix := t.TempDir()
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_linux_amd64.tar.gz": {Body: archive, Sum: strings.Repeat("0", sha256.Size*2)},
	})
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

type updateFixtureArchive struct {
	Body []byte
	Sum  string
}

func updateFixtureServer(t *testing.T, archives map[string]updateFixtureArchive) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/download/v0.9.0/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, prefix)
		if name == "checksums.txt" {
			for archiveName, archive := range archives {
				fmt.Fprintf(w, "%s  %s\n", archive.Sum, archiveName)
			}
			return
		}
		archive, ok := archives[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(archive.Body)
	}))
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
