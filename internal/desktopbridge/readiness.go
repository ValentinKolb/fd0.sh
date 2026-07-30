package desktopbridge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

type ReadinessState struct {
	FirstSyncAt        int64 `json:"firstSyncAt,omitempty"`
	LastSyncAt         int64 `json:"lastSyncAt,omitempty"`
	RecoveryVerifiedAt int64 `json:"recoveryVerifiedAt,omitempty"`
}

func loadReadiness(paths fdhome.Paths) (ReadinessState, error) {
	var state ReadinessState
	data, err := os.ReadFile(filepath.Join(paths.Home, "desktop-state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(data, &state)
	return state, err
}

func updateReadiness(paths fdhome.Paths, update func(*ReadinessState)) error {
	state, err := loadReadiness(paths)
	if err != nil {
		return err
	}
	update(&state)
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	path := filepath.Join(paths.Home, "desktop-state.json")
	staged := path + ".new"
	if err := os.WriteFile(staged, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(staged, path); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return nil
}

func markSyncComplete(paths fdhome.Paths) error {
	return updateReadiness(paths, func(state *ReadinessState) {
		now := time.Now().Unix()
		if state.FirstSyncAt == 0 {
			state.FirstSyncAt = now
		}
		state.LastSyncAt = now
	})
}

func markRecoveryVerified(paths fdhome.Paths) error {
	return updateReadiness(paths, func(state *ReadinessState) {
		if state.RecoveryVerifiedAt == 0 {
			state.RecoveryVerifiedAt = time.Now().Unix()
		}
	})
}
