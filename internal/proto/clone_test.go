package proto

import (
	"bytes"
	"testing"
)

// TestScopeVaultDataCloneIsDeep guards the reconcile rollback snapshot:
// Clone() must produce a fully independent copy so that in-place
// mutation of the working struct (OEKs backing array, PerServer map,
// ChainTip.Hash / LastSTH byte slices) never leaks into the snapshot.
func TestScopeVaultDataCloneIsDeep(t *testing.T) {
	orig := ScopeVaultData{
		Label:     "work",
		OEKs:      []OEKEntry{{Version: 1, Key: []byte{1, 2, 3}}},
		ChainTip:  ChainTip{Seq: 5, Hash: []byte{9, 9}},
		PushFloor: 2,
		LastSTH:   []byte{7, 7},
		PerServer: map[string]ScopeServerState{
			"https://a": {PushFloor: 3, LastSTH: []byte{4, 4}},
		},
	}
	snap := orig.Clone()

	// Mutate every reference-typed field of the working struct the way
	// reconcile does (upsertOEK in place, SetPushFloorFor/SetLastSTHFor,
	// chain-tip advance).
	orig.OEKs[0].Key[0] = 0xff
	orig.OEKs = append(orig.OEKs, OEKEntry{Version: 2, Key: []byte{5}})
	orig.ChainTip.Hash[0] = 0xff
	orig.ChainTip.Seq = 99
	orig.LastSTH[0] = 0xff
	orig.SetPushFloorFor("https://a", 100)
	orig.SetLastSTHFor("https://a", []byte{0xff})
	orig.SetPushFloorFor("https://b", 1) // new key in the working map

	// Snapshot must be untouched.
	if len(snap.OEKs) != 1 || snap.OEKs[0].Version != 1 || !bytes.Equal(snap.OEKs[0].Key, []byte{1, 2, 3}) {
		t.Errorf("OEKs leaked: %+v", snap.OEKs)
	}
	if snap.ChainTip.Seq != 5 || !bytes.Equal(snap.ChainTip.Hash, []byte{9, 9}) {
		t.Errorf("ChainTip leaked: %+v", snap.ChainTip)
	}
	if !bytes.Equal(snap.LastSTH, []byte{7, 7}) {
		t.Errorf("LastSTH leaked: %v", snap.LastSTH)
	}
	a, ok := snap.PerServer["https://a"]
	if !ok || a.PushFloor != 3 || !bytes.Equal(a.LastSTH, []byte{4, 4}) {
		t.Errorf("PerServer[a] leaked: %+v", a)
	}
	if _, ok := snap.PerServer["https://b"]; ok {
		t.Errorf("PerServer gained key b from the working struct's map")
	}
}

// Clone of a zero value must not panic and must stay nil-clean.
func TestScopeVaultDataCloneZero(t *testing.T) {
	snap := ScopeVaultData{}.Clone()
	if snap.OEKs != nil || snap.PerServer != nil || snap.ChainTip.Hash != nil || snap.LastSTH != nil {
		t.Errorf("zero clone should keep nil reference fields, got %+v", snap)
	}
}
