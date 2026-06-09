package cli

import (
	"os"
	"path/filepath"
)

// talosconfPath returns the path fd0 renders its talosconfig to.
//
// FD0_TALOS_CONFIG_PATH overrides for tests / unusual setups.
// Default: ~/.talos/config.fd0 (sits next to ~/.talos/config so
// the on-disk merge is local).
func talosconfPath() string {
	if p := os.Getenv("FD0_TALOS_CONFIG_PATH"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".talos", "config.fd0")
}

// userTalosconfigPath returns the standard ~/.talos/config that
// talosctl reads by default. Honors FD0_TALOS_USER_CONFIG for tests.
func userTalosconfigPath() string {
	if p := os.Getenv("FD0_TALOS_USER_CONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".talos", "config")
}

// kubeconfPath returns the path fd0 renders its kubeconfig to.
//
// FD0_KUBE_CONFIG_PATH overrides. Default: ~/.kube/config.fd0.
func kubeconfPath() string {
	if p := os.Getenv("FD0_KUBE_CONFIG_PATH"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kube", "config.fd0")
}

// userKubeconfigPath returns the standard ~/.kube/config kubectl
// reads by default. Honors $KUBECONFIG-first-entry and
// FD0_KUBE_USER_CONFIG for tests.
func userKubeconfigPath() string {
	if p := os.Getenv("FD0_KUBE_USER_CONFIG"); p != "" {
		return p
	}
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		// Use the first entry — kubectl writes there too.
		for _, p := range filepathSplitList(kc) {
			if p != "" {
				return p
			}
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kube", "config")
}

// filepathSplitList is filepath.SplitList in a tiny wrapper so we
// can stub it in tests later if needed. Splits on os.PathListSeparator.
func filepathSplitList(s string) []string { return filepath.SplitList(s) }
