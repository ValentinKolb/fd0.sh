package cli

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/buildinfo"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

const (
	defaultUpdateRepo        = "ValentinKolb/fd0.sh"
	defaultUpdateReleaseBase = "https://github.com/" + defaultUpdateRepo + "/releases"
	defaultUpdateAPIBase     = "https://api.github.com/repos/" + defaultUpdateRepo
	updateArchiveMaxBytes    = 128 << 20
	updateSmallFileMaxBytes  = 4 << 20
)

var ErrUpdateAvailable = errors.New("fd0 update available")

type UpdateOptions struct {
	CurrentVersion   string
	CurrentFlavor    string
	ManagedByDesktop bool
	Version          string
	Flavor           string
	Prefix           string
	System           bool
	CheckOnly        bool
	Yes              bool
	NoVerify         bool

	APIBase     string
	ReleaseBase string
	HTTPClient  *http.Client
	Stdout      io.Writer
	Stderr      io.Writer
	GOOS        string
	GOARCH      string
	Executable  string
}

type updateRelease struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

type updateTarget struct {
	DownloadTag string
	DisplayTag  string
	Version     string
}

type installedClient struct {
	Version string
	Flavor  string
}

type semver struct {
	major int
	minor int
	patch int
}

type stagedUpdateBinary struct {
	name   string
	dst    string
	tmp    string
	backup string
}

func RunUpdate(ctx context.Context, opts UpdateOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.ManagedByDesktop || os.Getenv("FD0_DESKTOP_MANAGED") == "1" {
		fmt.Fprintln(opts.Stdout, "fd0 is managed by fd0 Desktop.")
		fmt.Fprintln(opts.Stdout, "Open fd0 Desktop > Support > Check now to update the app, CLI, and agent together.")
		return nil
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.APIBase == "" {
		opts.APIBase = getenvDefault("FD0_API_BASE", defaultUpdateAPIBase)
	}
	if opts.ReleaseBase == "" {
		opts.ReleaseBase = getenvDefault("FD0_RELEASE_BASE", defaultUpdateReleaseBase)
	}
	if opts.Version == "" {
		opts.Version = "latest"
	}
	if opts.Flavor == "" {
		opts.Flavor = "auto"
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	platform, err := updatePlatform(opts.GOOS, opts.GOARCH)
	if err != nil {
		return err
	}
	prefix, err := resolveUpdatePrefix(opts)
	if err != nil {
		return err
	}
	current, err := detectInstalledFD0(ctx, prefix, opts.CurrentVersion, opts.CurrentFlavor)
	if err != nil {
		return err
	}
	targetFlavor, err := resolveUpdateFlavor(opts.Flavor, current.Flavor, opts.CurrentFlavor)
	if err != nil {
		return err
	}
	target := updateTarget{}
	if opts.Version == "latest" {
		target, err = latestClientReleaseTarget(ctx, opts.HTTPClient, opts.APIBase)
		if err != nil {
			return err
		}
	} else {
		target, err = explicitUpdateTarget(opts.Version)
		if err != nil {
			return err
		}
	}
	archiveName := updateArchiveName(targetFlavor, platform)
	relation, comparable := compareVersionStrings(current.Version, target.Version)
	sameFlavor := current.Flavor == targetFlavor
	if opts.CheckOnly {
		printUpdatePlan(opts.Stdout, prefix, current.Version, current.Flavor, target.Version, targetFlavor, target.DisplayTag, archiveName, "check", false, false)
		if comparable && relation >= 0 && sameFlavor {
			fmt.Fprintln(opts.Stdout, "fd0 is up to date")
			return nil
		}
		fmt.Fprintf(opts.Stdout, "fd0 %s %s is available\n", target.Version, targetFlavor)
		return ErrUpdateAvailable
	}
	if comparable && relation == 0 && sameFlavor {
		fmt.Fprintf(opts.Stdout, "fd0 %s %s already installed at %s\n", target.Version, targetFlavor, prefix)
		return nil
	}
	action := "update"
	if current.Version == "" {
		action = "install"
	} else if comparable && relation > 0 {
		action = "downgrade"
	} else if comparable && relation == 0 && !sameFlavor {
		action = "switch flavor"
	}
	cosignEnabled := !opts.NoVerify && commandExists("cosign")
	printUpdatePlan(opts.Stdout, prefix, current.Version, current.Flavor, target.Version, targetFlavor, target.DisplayTag, archiveName, action, cosignEnabled, !opts.NoVerify)
	if action == "downgrade" && !opts.Yes {
		if err := confirmUpdate(false, fmt.Sprintf("Downgrade fd0 from %s %s to %s %s?", current.Version, current.Flavor, target.Version, targetFlavor)); err != nil {
			return err
		}
	} else if !opts.Yes {
		if err := confirmUpdate(false, fmt.Sprintf("Proceed with fd0 %s to %s %s?", action, target.Version, targetFlavor)); err != nil {
			return err
		}
	}

	tmp, err := os.MkdirTemp("", "fd0-update-*")
	if err != nil {
		return fmt.Errorf("update: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	base := strings.TrimRight(opts.ReleaseBase, "/") + "/download/" + target.DownloadTag
	archivePath := filepath.Join(tmp, archiveName)
	fmt.Fprintf(opts.Stderr, "fetch %s\n", base+"/"+archiveName)
	if err := downloadToFile(ctx, opts.HTTPClient, base+"/"+archiveName, archivePath, updateArchiveMaxBytes); err != nil {
		return err
	}
	checksums, err := downloadBytes(ctx, opts.HTTPClient, base+"/checksums.txt", updateSmallFileMaxBytes)
	if err != nil {
		return err
	}
	expected, err := checksumForArchive(checksums, archiveName)
	if err != nil {
		return err
	}
	actual, err := sha256File(archivePath)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("update: sha256 mismatch for %s", archiveName)
	}
	fmt.Fprintln(opts.Stderr, "verified sha256 manifest")
	if cosignEnabled {
		if err := verifyChecksumsWithCosign(ctx, opts.HTTPClient, base, tmp, checksums); err != nil {
			return err
		}
		fmt.Fprintln(opts.Stderr, "verified cosign signature")
	} else if !opts.NoVerify {
		fmt.Fprintln(opts.Stderr, "warn: cosign not installed; verified sha256 manifest only")
	}
	extractDir := filepath.Join(tmp, "extract")
	if err := os.Mkdir(extractDir, 0o700); err != nil {
		return err
	}
	if err := extractClientBinaries(archivePath, extractDir); err != nil {
		return err
	}
	if err := installClientBinaries(extractDir, prefix); err != nil {
		return err
	}
	if action == "install" {
		fmt.Fprintf(opts.Stdout, "installed fd0 %s %s\n", target.Version, targetFlavor)
	} else {
		fmt.Fprintf(opts.Stdout, "updated fd0 to %s %s\n", target.Version, targetFlavor)
	}
	if updateAgentAppearsRunning() {
		fmt.Fprintln(opts.Stdout, "restart the agent to use the new fd0-agent: fd0 agent restart")
	}
	return nil
}

func getenvDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func updatePlatform(goos, goarch string) (string, error) {
	switch goos {
	case "linux", "darwin":
	default:
		return "", fmt.Errorf("update: unsupported OS %q", goos)
	}
	switch goarch {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("update: unsupported arch %q", goarch)
	}
	return goos + "_" + goarch, nil
}

func resolveUpdatePrefix(opts UpdateOptions) (string, error) {
	if opts.System {
		return "/usr/local/bin", nil
	}
	if opts.Prefix != "" {
		return filepath.Clean(opts.Prefix), nil
	}
	exe := opts.Executable
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("update: resolve current executable: %w", err)
		}
	}
	return filepath.Dir(exe), nil
}

func detectInstalledFD0(ctx context.Context, prefix, fallbackVersion, fallbackFlavor string) (installedClient, error) {
	path := filepath.Join(prefix, "fd0")
	if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cctx, path, "version").Output()
		if err == nil {
			return parseFD0VersionOutput(string(out)), nil
		}
	}
	if fallbackVersion == "dev" {
		return installedClient{Flavor: buildinfo.NormalizeFlavor(fallbackFlavor)}, nil
	}
	return installedClient{
		Version: normalizeVersionNumber(fallbackVersion),
		Flavor:  buildinfo.NormalizeFlavor(fallbackFlavor),
	}, nil
}

func parseFD0VersionOutput(out string) installedClient {
	fields := strings.Fields(out)
	if len(fields) >= 2 && fields[0] == "fd0" {
		flavor := buildinfo.FlavorStandard
		if len(fields) >= 3 {
			flavor = buildinfo.NormalizeFlavor(fields[2])
		}
		return installedClient{
			Version: normalizeVersionNumber(fields[1]),
			Flavor:  flavor,
		}
	}
	return installedClient{Flavor: buildinfo.FlavorStandard}
}

func resolveUpdateFlavor(requested, installed, fallback string) (string, error) {
	switch requested {
	case "", "auto":
		if installed != "" {
			return buildinfo.NormalizeFlavor(installed), nil
		}
		if fallback != "" {
			return buildinfo.NormalizeFlavor(fallback), nil
		}
		return buildinfo.FlavorStandard, nil
	case buildinfo.FlavorStandard, buildinfo.FlavorYubikey:
		return requested, nil
	default:
		return "", fmt.Errorf("update: unknown flavor %q (use auto, standard, or yubikey)", requested)
	}
}

func updateArchiveName(flavor, platform string) string {
	if flavor == buildinfo.FlavorYubikey {
		return "fd0_yubikey_" + platform + ".tar.gz"
	}
	return "fd0_" + platform + ".tar.gz"
}

func latestClientReleaseTarget(ctx context.Context, hc *http.Client, apiBase string) (updateTarget, error) {
	body, err := downloadBytes(ctx, hc, strings.TrimRight(apiBase, "/")+"/releases?per_page=50", updateSmallFileMaxBytes)
	if err != nil {
		return updateTarget{}, err
	}
	var releases []updateRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return updateTarget{}, fmt.Errorf("update: parse releases API: %w", err)
	}
	for _, r := range releases {
		if r.Draft || r.Prerelease {
			continue
		}
		display := clientReleaseDisplayTag(r)
		if display == "" {
			continue
		}
		target, err := updateTargetFromTags(r.TagName, display)
		if err != nil {
			return updateTarget{}, err
		}
		return target, nil
	}
	return updateTarget{}, errors.New("update: no client release found")
}

func explicitUpdateTarget(v string) (updateTarget, error) {
	downloadTag := explicitDownloadTag(v)
	displayTag := canonicalClientReleaseTag(v)
	return updateTargetFromTags(downloadTag, displayTag)
}

func clientReleaseDisplayTag(r updateRelease) string {
	if strings.HasPrefix(r.Name, "client-v") || strings.HasPrefix(r.Name, "fd0-v") {
		return r.Name
	}
	if strings.HasPrefix(r.TagName, "client-v") || strings.HasPrefix(r.TagName, "fd0-v") {
		return r.TagName
	}
	return ""
}

func updateTargetFromTags(downloadTag, displayTag string) (updateTarget, error) {
	version := releaseVersionNumber(displayTag)
	if version == "" {
		return updateTarget{}, fmt.Errorf("update: release tag %q is not a client semver tag", displayTag)
	}
	return updateTarget{DownloadTag: downloadTag, DisplayTag: displayTag, Version: version}, nil
}

func explicitDownloadTag(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "client-v") {
		return "v" + strings.TrimPrefix(v, "client-v")
	}
	if strings.HasPrefix(v, "fd0-v") {
		return "v" + strings.TrimPrefix(v, "fd0-v")
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

func canonicalClientReleaseTag(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "client-v") || strings.HasPrefix(v, "fd0-v") {
		return v
	}
	v = strings.TrimPrefix(v, "v")
	return "client-v" + v
}

func releaseVersionNumber(tag string) string {
	tag = strings.TrimSpace(tag)
	if strings.HasPrefix(tag, "client-v") {
		return normalizeVersionNumber(strings.TrimPrefix(tag, "client-v"))
	}
	if strings.HasPrefix(tag, "fd0-v") {
		return normalizeVersionNumber(strings.TrimPrefix(tag, "fd0-v"))
	}
	return normalizeVersionNumber(strings.TrimPrefix(tag, "v"))
}

func normalizeVersionNumber(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "client-v")
	v = strings.TrimPrefix(v, "fd0-v")
	v = strings.TrimPrefix(v, "v")
	if _, ok := parseSemver(v); !ok {
		return v
	}
	return v
}

func compareVersionStrings(a, b string) (int, bool) {
	av, aok := parseSemver(a)
	bv, bok := parseSemver(b)
	if !aok || !bok {
		return 0, false
	}
	switch {
	case av.major != bv.major:
		return compareInt(av.major, bv.major), true
	case av.minor != bv.minor:
		return compareInt(av.minor, bv.minor), true
	case av.patch != bv.patch:
		return compareInt(av.patch, bv.patch), true
	default:
		return 0, true
	}
}

func parseSemver(v string) (semver, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	nums := [3]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}
	return semver{major: nums[0], minor: nums[1], patch: nums[2]}, true
}

func compareInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func printUpdatePlan(w io.Writer, prefix, currentVersion, currentFlavor, targetVersion, targetFlavor, targetTag, archiveName, action string, cosignEnabled, cosignWanted bool) {
	fmt.Fprintln(w, "fd0 update")
	fmt.Fprintf(w, "  target:  %s\n", prefix)
	if currentVersion != "" {
		fmt.Fprintf(w, "  current: %s %s\n", currentVersion, currentFlavor)
	}
	fmt.Fprintf(w, "  new:     %s %s (%s)\n", targetVersion, targetFlavor, targetTag)
	fmt.Fprintf(w, "  archive: %s\n", archiveName)
	fmt.Fprintf(w, "  action:  %s\n", action)
	switch {
	case action == "check":
		fmt.Fprintln(w, "  verify:  not used in --check")
	case cosignEnabled:
		fmt.Fprintln(w, "  verify:  sha256 + cosign")
	case cosignWanted:
		fmt.Fprintln(w, "  verify:  sha256; cosign unavailable")
	default:
		fmt.Fprintln(w, "  verify:  sha256 only (--no-verify)")
	}
}

func confirmUpdate(yes bool, prompt string) error {
	if yes {
		return nil
	}
	if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return errors.New("update: not a terminal; pass --yes to update non-interactively")
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return err
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "y" && line != "yes" {
		return errors.New("aborted")
	}
	return nil
}

func downloadBytes(ctx context.Context, hc *http.Client, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: fetch %s: HTTP %d", url, resp.StatusCode)
	}
	lr := &io.LimitedReader{R: resp.Body, N: max + 1}
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("update: read %s: %w", url, err)
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("update: fetch %s: response too large", url)
	}
	return body, nil
}

func downloadToFile(ctx context.Context, hc *http.Client, url, path string, max int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("update: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update: fetch %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	lr := &io.LimitedReader{R: resp.Body, N: max + 1}
	n, err := io.Copy(f, lr)
	if err != nil {
		return fmt.Errorf("update: write %s: %w", path, err)
	}
	if n > max {
		return fmt.Errorf("update: fetch %s: response too large", url)
	}
	return nil
}

func checksumForArchive(manifest []byte, archive string) (string, error) {
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == archive {
			sum := strings.ToLower(fields[0])
			if len(sum) != sha256.Size*2 {
				return "", fmt.Errorf("update: malformed sha256 for %s", archive)
			}
			if _, err := hex.DecodeString(sum); err != nil {
				return "", fmt.Errorf("update: malformed sha256 for %s", archive)
			}
			return sum, nil
		}
	}
	return "", fmt.Errorf("update: %s not listed in checksums.txt", archive)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyChecksumsWithCosign(ctx context.Context, hc *http.Client, base, tmp string, checksums []byte) error {
	checksumPath := filepath.Join(tmp, "checksums.txt")
	if err := os.WriteFile(checksumPath, checksums, 0o600); err != nil {
		return err
	}
	sigPath := filepath.Join(tmp, "checksums.txt.sig")
	pemPath := filepath.Join(tmp, "checksums.txt.pem")
	if err := downloadToFile(ctx, hc, base+"/checksums.txt.sig", sigPath, updateSmallFileMaxBytes); err != nil {
		return err
	}
	if err := downloadToFile(ctx, hc, base+"/checksums.txt.pem", pemPath, updateSmallFileMaxBytes); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "cosign", "verify-blob",
		"--certificate", pemPath,
		"--signature", sigPath,
		"--certificate-identity-regexp", "^https://github.com/"+defaultUpdateRepo+"/",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		checksumPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("update: cosign verification failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func extractClientBinaries(archivePath, dst string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("update: open archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	want := map[string]bool{"fd0": false, "fd0-agent": false}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("update: read archive: %w", err)
		}
		name := filepath.Base(h.Name)
		if _, ok := want[name]; !ok {
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return fmt.Errorf("update: archive entry %s is not a regular file", h.Name)
		}
		if h.Size <= 0 || h.Size > updateArchiveMaxBytes {
			return fmt.Errorf("update: archive entry %s has invalid size", h.Name)
		}
		outPath := filepath.Join(dst, name)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
		if err != nil {
			return err
		}
		lr := &io.LimitedReader{R: tr, N: h.Size + 1}
		n, copyErr := io.Copy(out, lr)
		closeErr := out.Close()
		if copyErr != nil {
			return fmt.Errorf("update: extract %s: %w", h.Name, copyErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if n != h.Size {
			return fmt.Errorf("update: extract %s: truncated file", h.Name)
		}
		want[name] = true
	}
	for name, found := range want {
		if !found {
			return fmt.Errorf("update: binary %s missing from release archive", name)
		}
	}
	return nil
}

func installClientBinaries(srcDir, prefix string) error {
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		return fmt.Errorf("update: create install dir %s: %w", prefix, err)
	}
	var staged []stagedUpdateBinary
	for _, name := range []string{"fd0", "fd0-agent"} {
		dst := filepath.Join(prefix, name)
		tmp, err := stageOneBinary(filepath.Join(srcDir, name), dst)
		if err != nil {
			return err
		}
		staged = append(staged, stagedUpdateBinary{name: name, dst: dst, tmp: tmp})
	}
	cleanupTemps := true
	defer func() {
		if cleanupTemps {
			for _, s := range staged {
				_ = os.Remove(s.tmp)
			}
		}
	}()
	var installed []stagedUpdateBinary
	for i := range staged {
		if _, err := os.Stat(staged[i].dst); err == nil {
			backup, err := backupPath(staged[i].dst)
			if err != nil {
				rollbackInstalled(installed)
				return err
			}
			if err := os.Rename(staged[i].dst, backup); err != nil {
				rollbackInstalled(installed)
				return fmt.Errorf("update: backup %s: %w", staged[i].dst, err)
			}
			staged[i].backup = backup
		} else if !errors.Is(err, os.ErrNotExist) {
			rollbackInstalled(installed)
			return fmt.Errorf("update: inspect %s: %w", staged[i].dst, err)
		}
		if err := os.Rename(staged[i].tmp, staged[i].dst); err != nil {
			if staged[i].backup != "" {
				_ = os.Rename(staged[i].backup, staged[i].dst)
			}
			rollbackInstalled(installed)
			return fmt.Errorf("update: install %s: %w", staged[i].dst, err)
		}
		installed = append(installed, staged[i])
	}
	cleanupTemps = false
	for _, s := range staged {
		if s.backup != "" {
			_ = os.Remove(s.backup)
		}
	}
	return nil
}

func stageOneBinary(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".update-*")
	if err != nil {
		return "", fmt.Errorf("update: create temp binary in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("update: write temp binary %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	cleanup = false
	return tmpPath, nil
}

func backupPath(dst string) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".backup-*")
	if err != nil {
		return "", fmt.Errorf("update: create backup path for %s: %w", dst, err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	return name, nil
}

func rollbackInstalled(installed []stagedUpdateBinary) {
	for i := len(installed) - 1; i >= 0; i-- {
		s := installed[i]
		_ = os.Remove(s.dst)
		if s.backup != "" {
			_ = os.Rename(s.backup, s.dst)
		}
	}
}

func updateAgentAppearsRunning() bool {
	paths, err := fdhome.Resolve()
	if err != nil {
		return false
	}
	c := agent.NewClient(paths.AgentSock)
	return c.IsRunning()
}
