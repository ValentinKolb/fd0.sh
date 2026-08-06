package desktopbridge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

func TestReadinessPersistsIndependentSafetySteps(t *testing.T) {
	paths := fdhome.Paths{Home: t.TempDir()}
	if err := markSyncComplete(paths); err != nil {
		t.Fatal(err)
	}
	state, err := loadReadiness(paths)
	if err != nil {
		t.Fatal(err)
	}
	if state.FirstSyncAt == 0 || state.LastSyncAt != state.FirstSyncAt || state.RecoveryVerifiedAt != 0 {
		t.Fatalf("state=%+v", state)
	}
	if err := markRecoveryVerified(paths, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	state, err = loadReadiness(paths)
	if err != nil {
		t.Fatal(err)
	}
	if state.FirstSyncAt == 0 || state.RecoveryVerifiedAt == 0 || state.RecoveryAuthTip != "010203" {
		t.Fatalf("state=%+v", state)
	}
	info, err := os.Stat(filepath.Join(paths.Home, "desktop-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode=%o", info.Mode().Perm())
	}
}

func TestSyncCompletionPreservesFirstAndUpdatesLastSync(t *testing.T) {
	paths := fdhome.Paths{Home: t.TempDir()}
	if err := updateReadiness(paths, func(state *ReadinessState) {
		state.FirstSyncAt = 123
		state.LastSyncAt = 456
	}); err != nil {
		t.Fatal(err)
	}

	if err := markSyncComplete(paths); err != nil {
		t.Fatal(err)
	}
	state, err := loadReadiness(paths)
	if err != nil {
		t.Fatal(err)
	}
	if state.FirstSyncAt != 123 {
		t.Fatalf("first sync changed: state=%+v", state)
	}
	if state.LastSyncAt <= 456 {
		t.Fatalf("last sync was not updated: state=%+v", state)
	}
}
