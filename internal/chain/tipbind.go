package chain

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// VaultTipMismatch is returned when a vault tip and the corresponding chain
// file tip disagree. PROTOCOL.md §6 / STORAGE.md §4 require the client to
// refuse to operate on `file behind` and to advance on `file ahead`.
type VaultTipMismatch struct {
	Chain     string // "user" or "scope:<id>"
	VaultSeq  uint64
	FileSeq   uint64
	VaultHash []byte
	FileHash  []byte
	Direction string // "behind" | "ahead" | "diverged"
}

func (e *VaultTipMismatch) Error() string {
	return fmt.Sprintf("chain %s: vault tip seq=%d hash=%x, file tip seq=%d hash=%x (%s)",
		e.Chain, e.VaultSeq, e.VaultHash, e.FileSeq, e.FileHash, e.Direction)
}

// CompareUserTip compares vault.AuthTip to a freshly replayed user state.
//
// Outcomes (PROTOCOL.md §6):
//
//	match      → return nil
//	file ahead → caller advances vault tip via re-seal (signal nil error,
//	             *VaultTipMismatch with Direction="ahead")
//	file behind → return error; caller refuses to operate.
func CompareUserTip(vault proto.ChainTip, st *UserState) *VaultTipMismatch {
	if st == nil {
		// No file → must match nil vault.
		if vault.Seq == 0 && len(vault.Hash) == 0 {
			return nil
		}
		return &VaultTipMismatch{Chain: "user", VaultSeq: vault.Seq, VaultHash: vault.Hash, Direction: "behind"}
	}
	switch {
	case st.TipSeq == vault.Seq && bytes.Equal(st.TipHash, vault.Hash):
		return nil
	case st.TipSeq > vault.Seq:
		return &VaultTipMismatch{Chain: "user", VaultSeq: vault.Seq, VaultHash: vault.Hash,
			FileSeq: st.TipSeq, FileHash: st.TipHash, Direction: "ahead"}
	case st.TipSeq < vault.Seq:
		return &VaultTipMismatch{Chain: "user", VaultSeq: vault.Seq, VaultHash: vault.Hash,
			FileSeq: st.TipSeq, FileHash: st.TipHash, Direction: "behind"}
	default:
		return &VaultTipMismatch{Chain: "user", VaultSeq: vault.Seq, VaultHash: vault.Hash,
			FileSeq: st.TipSeq, FileHash: st.TipHash, Direction: "diverged"}
	}
}

// CompareScopeTip is the analogue for one scope chain.
func CompareScopeTip(scopeID string, vault proto.ChainTip, st *ScopeState) *VaultTipMismatch {
	tag := "scope:" + scopeID
	if st == nil {
		if vault.Seq == 0 && len(vault.Hash) == 0 {
			return nil
		}
		return &VaultTipMismatch{Chain: tag, VaultSeq: vault.Seq, VaultHash: vault.Hash, Direction: "behind"}
	}
	switch {
	case st.TipSeq == vault.Seq && bytes.Equal(st.TipHash, vault.Hash):
		return nil
	case st.TipSeq > vault.Seq:
		return &VaultTipMismatch{Chain: tag, VaultSeq: vault.Seq, VaultHash: vault.Hash,
			FileSeq: st.TipSeq, FileHash: st.TipHash, Direction: "ahead"}
	case st.TipSeq < vault.Seq:
		return &VaultTipMismatch{Chain: tag, VaultSeq: vault.Seq, VaultHash: vault.Hash,
			FileSeq: st.TipSeq, FileHash: st.TipHash, Direction: "behind"}
	default:
		return &VaultTipMismatch{Chain: tag, VaultSeq: vault.Seq, VaultHash: vault.Hash,
			FileSeq: st.TipSeq, FileHash: st.TipHash, Direction: "diverged"}
	}
}

// ErrRollback wraps a "file behind" tip mismatch so callers can match on it.
var ErrRollback = errors.New("chain: local rollback detected; refusing to operate")
