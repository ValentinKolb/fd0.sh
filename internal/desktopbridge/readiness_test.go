package desktopbridge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

func TestReadinessPersistsIndependentSafetySteps(t *testing.T) {
	paths := fdhome.Paths{Home: t.TempDir()}
	if err := markFirstSync(paths); err != nil {
		t.Fatal(err)
	}
	state, err := loadReadiness(paths)
	if err != nil {
		t.Fatal(err)
	}
	if state.FirstSyncAt == 0 || state.RecoveryVerifiedAt != 0 {
		t.Fatalf("state=%+v", state)
	}
	if err := markRecoveryVerified(paths); err != nil {
		t.Fatal(err)
	}
	state, err = loadReadiness(paths)
	if err != nil {
		t.Fatal(err)
	}
	if state.FirstSyncAt == 0 || state.RecoveryVerifiedAt == 0 {
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
