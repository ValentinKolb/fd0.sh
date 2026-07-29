package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/valentinkolb/fd0.sh/internal/browserconfig"
)

const developmentBrowserManifestDescription = "fd0 development browser host"

type nativeMessagingManifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

// RunBrowserEnable registers the development Native Messaging host for Chrome
// and Chromium. The extension itself remains unpacked and visible in the
// browser's extension manager.
func RunBrowserEnable(hostPath string) error {
	manifestPaths, err := browserManifestPaths()
	if err != nil {
		return err
	}
	return runBrowserEnableAll(hostPath, manifestPaths, os.Stdout)
}

func runBrowserEnableAll(hostPath string, manifestPaths []string, out io.Writer) error {
	resolvedHost, err := resolveBrowserHostPath(hostPath)
	if err != nil {
		return err
	}
	snapshots, err := snapshotBrowserManifests(manifestPaths, "replace")
	if err != nil {
		return fmt.Errorf("browser enable: %w", err)
	}
	if err := prepareBrowserManifestDirectories(manifestPaths); err != nil {
		return fmt.Errorf("browser enable: prepare native host directories: %w", err)
	}
	for index, manifestPath := range manifestPaths {
		if err := runBrowserEnable(resolvedHost, manifestPath, io.Discard); err != nil {
			if rollbackErr := restoreBrowserManifestSnapshots(snapshots[:index]); rollbackErr != nil {
				return fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
			}
			return err
		}
	}
	for _, manifestPath := range manifestPaths {
		fmt.Fprintf(out, "✓ registered fd0 development browser host at %s\n", manifestPath)
		fmt.Fprintf(out, "  Chrome extension id: %s\n", browserconfig.DevelopmentExtensionID)
	}
	return nil
}

func runBrowserEnable(hostPath, manifestPath string, out io.Writer) error {
	hostPath, err := resolveBrowserHostPath(hostPath)
	if err != nil {
		return err
	}
	manifest := nativeMessagingManifest{
		Name:           browserconfig.HostName,
		Description:    developmentBrowserManifestDescription,
		Path:           hostPath,
		Type:           "stdio",
		AllowedOrigins: []string{browserconfig.DevelopmentExtensionOrigin},
	}
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("browser enable: encode manifest: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o700); err != nil {
		return fmt.Errorf("browser enable: create native host directory: %w", err)
	}
	if err := writeDevelopmentBrowserManifest(manifestPath, payload); err != nil {
		return fmt.Errorf("browser enable: write native host manifest: %w", err)
	}
	fmt.Fprintf(out, "✓ registered fd0 development browser host at %s\n", manifestPath)
	fmt.Fprintf(out, "  Chrome extension id: %s\n", browserconfig.DevelopmentExtensionID)
	return nil
}

func writeDevelopmentBrowserManifest(path string, payload []byte) error {
	if _, err := inspectDevelopmentBrowserManifest(path, "replace"); err != nil {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

// RunBrowserDisable removes only a manifest carrying fd0's development marker.
func RunBrowserDisable() error {
	manifestPaths, err := browserManifestPaths()
	if err != nil {
		return err
	}
	return runBrowserDisableAll(manifestPaths, os.Stdout)
}

func runBrowserDisableAll(manifestPaths []string, out io.Writer) error {
	snapshots, err := snapshotBrowserManifests(manifestPaths, "remove")
	if err != nil {
		return fmt.Errorf("browser disable: %w", err)
	}
	existingPaths := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.exists {
			existingPaths = append(existingPaths, snapshot.path)
		}
	}
	if err := prepareBrowserManifestDirectories(existingPaths); err != nil {
		return fmt.Errorf("browser disable: prepare native host directories: %w", err)
	}
	for index, manifestPath := range manifestPaths {
		if err := runBrowserDisable(manifestPath, io.Discard); err != nil {
			if rollbackErr := restoreBrowserManifestSnapshots(snapshots[:index]); rollbackErr != nil {
				return fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
			}
			return err
		}
	}
	for _, snapshot := range snapshots {
		if snapshot.exists {
			fmt.Fprintf(out, "✓ removed fd0 development browser host from %s\n", snapshot.path)
		} else {
			fmt.Fprintln(out, "(fd0 development browser host is not registered)")
		}
	}
	return nil
}

func runBrowserDisable(manifestPath string, out io.Writer) error {
	exists, err := inspectDevelopmentBrowserManifest(manifestPath, "remove")
	if err != nil {
		return fmt.Errorf("browser disable: %w", err)
	}
	if !exists {
		fmt.Fprintln(out, "(fd0 development browser host is not registered)")
		return nil
	}
	if err := os.Remove(manifestPath); err != nil {
		return fmt.Errorf("browser disable: remove manifest: %w", err)
	}
	fmt.Fprintf(out, "✓ removed fd0 development browser host from %s\n", manifestPath)
	return nil
}

func inspectDevelopmentBrowserManifest(path, action string) (bool, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read manifest at %s: %w", path, err)
	}
	var manifest nativeMessagingManifest
	if json.Unmarshal(payload, &manifest) != nil || !isDevelopmentBrowserManifest(manifest) {
		return false, fmt.Errorf(
			"refusing to %s a Native Messaging manifest not owned by fd0 development at %s",
			action,
			path,
		)
	}
	return true, nil
}

type browserManifestSnapshot struct {
	path    string
	payload []byte
	mode    os.FileMode
	exists  bool
}

func snapshotBrowserManifests(paths []string, action string) ([]browserManifestSnapshot, error) {
	snapshots := make([]browserManifestSnapshot, 0, len(paths))
	for _, path := range paths {
		exists, err := inspectDevelopmentBrowserManifest(path, action)
		if err != nil {
			return nil, err
		}
		snapshot := browserManifestSnapshot{path: path, exists: exists, mode: 0o600}
		if exists {
			snapshot.payload, err = os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("read manifest at %s: %w", path, err)
			}
			info, statErr := os.Stat(path)
			if statErr != nil {
				return nil, fmt.Errorf("stat manifest at %s: %w", path, statErr)
			}
			snapshot.mode = info.Mode().Perm()
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func prepareBrowserManifestDirectories(paths []string) error {
	for _, path := range paths {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		probe, err := os.CreateTemp(dir, ".fd0-browser-write-check-*")
		if err != nil {
			return err
		}
		probePath := probe.Name()
		if closeErr := probe.Close(); closeErr != nil {
			_ = os.Remove(probePath)
			return closeErr
		}
		if err := os.Remove(probePath); err != nil {
			return err
		}
	}
	return nil
}

func restoreBrowserManifestSnapshots(snapshots []browserManifestSnapshot) error {
	var firstErr error
	for _, snapshot := range snapshots {
		var err error
		if snapshot.exists {
			err = writeFileAtomic(snapshot.path, snapshot.payload, snapshot.mode)
		} else {
			err = os.Remove(snapshot.path)
			if os.IsNotExist(err) {
				err = nil
			}
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func isDevelopmentBrowserManifest(manifest nativeMessagingManifest) bool {
	return manifest.Name == browserconfig.HostName &&
		manifest.Description == developmentBrowserManifestDescription &&
		manifest.Type == "stdio" &&
		len(manifest.AllowedOrigins) == 1 &&
		manifest.AllowedOrigins[0] == browserconfig.DevelopmentExtensionOrigin
}

func browserManifestPaths() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("browser integration: home directory: %w", err)
	}
	return browserManifestPathsFor(runtime.GOOS, home)
}

func browserManifestPathsFor(goos, home string) ([]string, error) {
	const manifestDirectory = "NativeMessagingHosts"
	const manifestName = browserconfig.HostName + ".json"
	switch goos {
	case "darwin":
		applicationSupport := filepath.Join(home, "Library", "Application Support")
		return []string{
			filepath.Join(applicationSupport, "Google", "Chrome", manifestDirectory, manifestName),
			filepath.Join(applicationSupport, "Chromium", manifestDirectory, manifestName),
		}, nil
	case "linux":
		config := filepath.Join(home, ".config")
		return []string{
			filepath.Join(config, "google-chrome", manifestDirectory, manifestName),
			filepath.Join(config, "chromium", manifestDirectory, manifestName),
		}, nil
	default:
		return nil, fmt.Errorf("browser integration is not supported on %s", goos)
	}
}

func resolveBrowserHostPath(explicit string) (string, error) {
	var candidates []string
	if explicit != "" {
		candidates = append(candidates, explicit)
	} else {
		if managed := os.Getenv("FD0_BROWSER_HOST_BIN"); managed != "" {
			candidates = append(candidates, managed)
		}
		if executable, err := os.Executable(); err == nil {
			candidates = append(candidates, filepath.Join(filepath.Dir(executable), "fd0-browser-host"))
		}
		if found, err := exec.LookPath("fd0-browser-host"); err == nil {
			candidates = append(candidates, found)
		}
	}
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(absolute)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return absolute, nil
		}
	}
	if explicit != "" {
		return "", fmt.Errorf("browser enable: host %q is not an executable file", explicit)
	}
	return "", errors.New("browser enable: fd0-browser-host not found in the desktop installation, next to fd0, or on PATH (development builds may pass --host)")
}
