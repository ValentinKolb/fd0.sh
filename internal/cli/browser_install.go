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

// RunBrowserEnable registers the development Native Messaging host for Google
// Chrome. The extension itself remains unpacked and visible in chrome://extensions.
func RunBrowserEnable(hostPath string) error {
	manifestPath, err := browserManifestPath()
	if err != nil {
		return err
	}
	return runBrowserEnable(hostPath, manifestPath, os.Stdout)
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
	existing, err := os.ReadFile(path)
	if err == nil {
		var manifest nativeMessagingManifest
		if json.Unmarshal(existing, &manifest) != nil || !isDevelopmentBrowserManifest(manifest) {
			return errors.New("refusing to replace a Native Messaging manifest not owned by fd0 development")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeFileAtomic(path, payload, 0o600)
}

// RunBrowserDisable removes only a manifest carrying fd0's development marker.
func RunBrowserDisable() error {
	manifestPath, err := browserManifestPath()
	if err != nil {
		return err
	}
	return runBrowserDisable(manifestPath, os.Stdout)
}

func runBrowserDisable(manifestPath string, out io.Writer) error {
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(out, "(fd0 development browser host is not registered)")
			return nil
		}
		return fmt.Errorf("browser disable: read manifest: %w", err)
	}
	var manifest nativeMessagingManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		return fmt.Errorf("browser disable: refusing to remove an unreadable manifest at %s", manifestPath)
	}
	if !isDevelopmentBrowserManifest(manifest) {
		return fmt.Errorf("browser disable: refusing to remove a manifest not owned by fd0 development")
	}
	if err := os.Remove(manifestPath); err != nil {
		return fmt.Errorf("browser disable: remove manifest: %w", err)
	}
	fmt.Fprintf(out, "✓ removed fd0 development browser host from %s\n", manifestPath)
	return nil
}

func isDevelopmentBrowserManifest(manifest nativeMessagingManifest) bool {
	return manifest.Name == browserconfig.HostName &&
		manifest.Description == developmentBrowserManifestDescription &&
		manifest.Type == "stdio" &&
		len(manifest.AllowedOrigins) == 1 &&
		manifest.AllowedOrigins[0] == browserconfig.DevelopmentExtensionOrigin
}

func browserManifestPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("browser integration: home directory: %w", err)
	}
	return browserManifestPathFor(runtime.GOOS, home)
}

func browserManifestPathFor(goos, home string) (string, error) {
	switch goos {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Google", "Chrome",
			"NativeMessagingHosts", browserconfig.HostName+".json"), nil
	case "linux":
		return filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts",
			browserconfig.HostName+".json"), nil
	default:
		return "", fmt.Errorf("browser integration is not supported on %s", goos)
	}
}

func resolveBrowserHostPath(explicit string) (string, error) {
	var candidates []string
	if explicit != "" {
		candidates = append(candidates, explicit)
	} else {
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
	return "", errors.New("browser enable: fd0-browser-host not found next to fd0 or on PATH (development builds may pass --host)")
}
