package cli

import (
	"context"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
)

func refreshEnabledProjections(ctx context.Context) {
	paths, err := fdhome.Resolve()
	if err != nil {
		stderrln("⚠ local refresh: %v", err)
		return
	}
	cfg, err := fdhome.LoadConfig(paths.Config)
	if err != nil {
		stderrln("⚠ local refresh: load config: %v", err)
	}

	sshEnabled, err := sshProjectionEnabled()
	if err != nil {
		stderrln("⚠ ssh render: %v", err)
	}
	kubeEnabled := projectionEnabled(cfg.Kube, kubeconfPath())
	talosEnabled := projectionEnabled(cfg.Talos, talosconfPath())
	if !sshEnabled && !kubeEnabled && !talosEnabled {
		return
	}

	s, err := Open(ctx)
	if err != nil {
		stderrln("⚠ local refresh: %v", err)
		return
	}
	kubeRendered := false
	talosRendered := false
	if sshEnabled {
		if err := renderAndWarn(s); err != nil {
			stderrln("⚠ ssh render: %v", err)
		}
	}
	if kubeEnabled {
		if err := renderAndWarnKube(s); err != nil {
			stderrln("⚠ kube render: %v", err)
		} else {
			kubeRendered = true
		}
	}
	if talosEnabled {
		if err := renderAndWarnTalos(s); err != nil {
			stderrln("⚠ talos render: %v", err)
		} else {
			talosRendered = true
		}
	}
	s.Close()

	if kubeRendered && cfg.Kube.AutoMerge {
		if err := mergeKubeconfigFile(kubeconfPath(), userKubeconfigPath()); err != nil {
			stderrln("⚠ kube merge: %v", err)
		} else {
			stderrln("✓ merged into %s", userKubeconfigPath())
		}
	}
	if talosRendered && cfg.Talos.AutoMerge {
		if err := mergeTalosconfigFile(talosconfPath(), userTalosconfigPath()); err != nil {
			stderrln("⚠ talos merge: %v", err)
		} else {
			stderrln("✓ merged into %s", userTalosconfigPath())
		}
	}
}

func projectionEnabled(cfg fdhome.ProjectionConfig, generatedPath string) bool {
	if cfg.Enabled != nil {
		return *cfg.Enabled
	}
	if cfg.AutoMerge {
		return true
	}
	return fileExists(generatedPath)
}

func projectionAutoMerge(cfg fdhome.ProjectionConfig) bool {
	if cfg.Enabled != nil && !*cfg.Enabled {
		return false
	}
	return cfg.AutoMerge
}

func loadProjectionConfig(section string) (fdhome.ProjectionConfig, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return fdhome.ProjectionConfig{}, err
	}
	cfg, err := fdhome.LoadConfig(paths.Config)
	if err != nil {
		return fdhome.ProjectionConfig{}, err
	}
	switch section {
	case "kube":
		return cfg.Kube, nil
	case "talos":
		return cfg.Talos, nil
	default:
		return fdhome.ProjectionConfig{}, nil
	}
}

func autoMergeKubeIfEnabled() {
	cfg, err := loadProjectionConfig("kube")
	if err != nil {
		stderrln("⚠ kube auto-merge: %v", err)
		return
	}
	if !projectionAutoMerge(cfg) {
		return
	}
	if err := mergeKubeconfigFile(kubeconfPath(), userKubeconfigPath()); err != nil {
		stderrln("⚠ kube merge: %v", err)
		return
	}
	stderrln("✓ merged into %s", userKubeconfigPath())
}

func autoMergeTalosIfEnabled() {
	cfg, err := loadProjectionConfig("talos")
	if err != nil {
		stderrln("⚠ talos auto-merge: %v", err)
		return
	}
	if !projectionAutoMerge(cfg) {
		return
	}
	if err := mergeTalosconfigFile(talosconfPath(), userTalosconfigPath()); err != nil {
		stderrln("⚠ talos merge: %v", err)
		return
	}
	stderrln("✓ merged into %s", userTalosconfigPath())
}

func renderSSHWithSessionIfEnabled(s *Session) error {
	enabled, err := sshProjectionEnabled()
	if err != nil || !enabled {
		return err
	}
	return renderAndWarn(s)
}

func sshProjectionEnabled() (bool, error) {
	enabled, err := sshhost.HasInclude(sshhost.DefaultUserConfigPath(), SSHConfPath())
	if err != nil {
		return false, err
	}
	return enabled, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
