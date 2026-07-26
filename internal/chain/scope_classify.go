package chain

import (
	"bytes"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// ScopeChainShape is the structural verdict on one scope chain file.
type ScopeChainShape string

const (
	// ScopeShapeEmpty — the file is absent or holds no events. Nothing to
	// replay and nothing to migrate; sync's discovery path owns this case.
	ScopeShapeEmpty ScopeChainShape = "empty"

	// ScopeShapeContiguous — genesis at seq 0, then every event advances the
	// sequence by exactly one and carries the previous event's hash. This is
	// the only shape ReplayScope accepts.
	ScopeShapeContiguous ScopeChainShape = "contiguous"

	// ScopeShapeLegacyCompacted — the retired v1 compactor's signature (see
	// ClassifyScopeEvents for the full argument): genesis, then exactly one
	// forward jump, then a contiguous tail. Nothing else.
	ScopeShapeLegacyCompacted ScopeChainShape = "legacy-compacted"

	// ScopeShapeMalformed — anything else. Reason says what broke. Never
	// migrated automatically.
	ScopeShapeMalformed ScopeChainShape = "malformed"
)

// ScopeChainClassification is the result of inspecting a scope chain file.
//
// Tip is the tip the final event commits to (the same value ScopeFileTip
// returns) so a caller can compare it against the vault's bound ChainTip
// without a second read. Classification itself is deliberately independent
// of the vault: the file's shape is a fact about the file, and mixing the
// trust anchor into it would make "is this the compactor's output?" depend
// on state that a migration has to check separately anyway.
type ScopeChainClassification struct {
	Shape  ScopeChainShape
	Events int

	// Tip / HasTip: the tip committed by the last event. HasTip is false
	// only for ScopeShapeEmpty. Not signature-verified — ReplayScope owns
	// that; this is the same unauthenticated read ScopeFileTip performs.
	Tip    proto.ChainTip
	HasTip bool

	// RetainedFrom is the seq of the first event after the FIRST gap, set only
	// for ScopeShapeLegacyCompacted. It is the low end of the oldest window the
	// compactor kept, i.e. the first seq a migration must be able to bridge
	// back to genesis.
	RetainedFrom uint64

	// Gaps counts the compaction cuts, one per run. Repeated compaction of a
	// long-lived scope leaves several windows and therefore several gaps.
	Gaps int

	// Reason is human-readable and set only for ScopeShapeMalformed.
	Reason string
}

// ClassifyScopeChain reads path and classifies its shape.
//
// An error is returned only for I/O and decode failures — a structurally
// broken but decodable chain comes back as ScopeShapeMalformed with a
// Reason, because "this file is nonsense" is a verdict the caller has to
// render to the user, not an exception to bubble.
func ClassifyScopeChain(path string) (ScopeChainClassification, error) {
	events, err := ReadScopeEvents(path)
	if err != nil {
		return ScopeChainClassification{}, err
	}
	return ClassifyScopeEvents(events)
}

// ClassifyScopeEvents is ClassifyScopeChain over an already-decoded slice.
//
// # Why the legacy shape is recognised this narrowly
//
// ReplayScope (scope.go) requires every event's Seq to be exactly prevTip+1
// with a matching PrevHash, and that rejection is correct: a gap is
// unverifiable from local state alone, so accepting one would let a dropped
// — or suppressed — event pass unnoticed. The rejection must stay. What is
// missing is the ability to tell WHY a particular file has a gap, because
// exactly one cause is benign and repairable.
//
// The retired v1 compactor rewrote a scope chain to "genesis plus a recent
// window": it kept events[0] verbatim (replay derives the scope id from it,
// so it can never be dropped) and the last N events verbatim, and deleted
// everything between. That produces one — and only one — structural
// signature:
//
//   - events[0] is a genesis event: Seq == 0, empty PrevHash, nil Scope.
//   - events[1].Seq > 1, and events[1].PrevHash is a full 32-byte link (to
//     the event the compactor deleted — we cannot check it locally, which
//     is precisely why a migration has to re-fetch the missing span).
//   - every later step is exactly +1 with a matching PrevHash.
//
// Running the compactor twice narrows the window but preserves the shape, so
// the signature is idempotent — which is what lets a migration be idempotent
// too.
//
// Anything else is malformed and is never auto-migrated:
//
//   - No genesis (first Seq != 0, or a non-empty PrevHash on it) — a file
//     truncated from the front. Nothing local pins the scope id, so there is
//     no anchor to migrate against.
//   - A second gap, or a gap anywhere other than immediately after genesis —
//     the compactor could not have produced it. Something else removed
//     events, and "something else" is exactly the case where a silently
//     re-fetched history could hide a dropped write.
//   - Seq advances by one but PrevHash does not link — a substituted or
//     rewritten event, not a missing one. Refetching would paper over
//     tampering.
//   - Seq stalls or moves backwards — reordered or duplicated events.
//
// The bar is deliberately "prove it is the compactor's output", not "rule
// out everything I can think of": a false negative costs a user one manual
// `fd0 sync`, while a false positive would extend automatic, unattended
// history replacement to files whose gaps have no benign explanation.
func ClassifyScopeEvents(events []*proto.ScopeEvent) (ScopeChainClassification, error) {
	out := ScopeChainClassification{Events: len(events)}
	if len(events) == 0 {
		out.Shape = ScopeShapeEmpty
		return out, nil
	}
	last := events[len(events)-1]
	lastInput, err := last.PrevHashInput()
	if err != nil {
		return ScopeChainClassification{}, err
	}
	lastHash := proto.HashPrefix(lastInput)
	out.Tip = proto.ChainTip{Seq: last.SignedPrefix.Seq, Hash: append([]byte(nil), lastHash[:]...)}
	out.HasTip = true

	genesis := &events[0].SignedPrefix
	switch {
	case genesis.Seq != 0:
		return malformedScope(out, fmt.Sprintf("first event has seq %d, want 0 (the genesis event is missing)", genesis.Seq)), nil
	case len(genesis.PrevHash) != 0:
		return malformedScope(out, "first event carries a prev_hash but a genesis event must not"), nil
	case genesis.Scope != nil:
		return malformedScope(out, "first event names a scope but a genesis event must not"), nil
	}

	gaps := 0
	firstGapIndex := -1
	for i := 1; i < len(events); i++ {
		prev := events[i-1]
		sp := &events[i].SignedPrefix
		prevInput, err := prev.PrevHashInput()
		if err != nil {
			return ScopeChainClassification{}, err
		}
		prevHash := proto.HashPrefix(prevInput)
		wantSeq := prev.SignedPrefix.Seq + 1
		switch {
		case sp.Seq == wantSeq && bytes.Equal(sp.PrevHash, prevHash[:]):
			// Ordinary contiguous step.
		case sp.Seq == wantSeq:
			return malformedScope(out, fmt.Sprintf(
				"event %d (seq %d) follows seq %d without a gap but its prev_hash does not link to it",
				i, sp.Seq, prev.SignedPrefix.Seq)), nil
		case sp.Seq <= prev.SignedPrefix.Seq:
			return malformedScope(out, fmt.Sprintf(
				"event %d has seq %d after seq %d — events are out of order or duplicated",
				i, sp.Seq, prev.SignedPrefix.Seq)), nil
		default:
			// Forward jump. A compacted file still links across the gap;
			// a missing link means the event was rewritten, not dropped.
			if len(sp.PrevHash) != len(prevHash) {
				return malformedScope(out, fmt.Sprintf(
					"event %d jumps from seq %d to seq %d without a prev_hash link",
					i, prev.SignedPrefix.Seq, sp.Seq)), nil
			}
			gaps++
			if firstGapIndex < 0 {
				firstGapIndex = i
			}
		}
	}

	switch {
	case gaps == 0:
		out.Shape = ScopeShapeContiguous
		return out, nil
	default:
		// One gap per compaction. Real vaults were compacted repeatedly over
		// their lifetime, so a long-lived scope carries several windows and
		// several gaps — measured against a production vault: 27 retained
		// events across 5 gaps at tip 1372. An earlier rule of "exactly one
		// gap, immediately after genesis" described the compactor's single
		// run rather than its cumulative effect, and refused every real vault.
		//
		// Widening this is safe because classification only decides whether to
		// ATTEMPT a migration. What makes the result trustworthy is downstream
		// and unchanged: the refetched history is verified against the
		// transparency log and must replay to the tip sealed inside the vault.
		// An attacker who drops events cannot move that tip, so a forged or
		// truncated history is refused there, not here.
		out.Shape = ScopeShapeLegacyCompacted
		out.RetainedFrom = events[firstGapIndex].SignedPrefix.Seq
		out.Gaps = gaps
		return out, nil
	}
}

func malformedScope(out ScopeChainClassification, reason string) ScopeChainClassification {
	out.Shape = ScopeShapeMalformed
	out.Reason = reason
	out.RetainedFrom = 0
	return out
}

// ValidateScopeEventContinuity is ValidateScopeContinuity for an in-memory
// candidate history. The migration path needs the check BEFORE it commits —
// validating a file it has already written would mean a server copy that is
// itself gapped gets adopted first and rejected afterwards.
//
// It runs the same validateScopeContinuity used by the on-disk check, so the
// two cannot drift.
func ValidateScopeEventContinuity(events []proto.ScopeEvent) error {
	ptrs := make([]*proto.ScopeEvent, len(events))
	for i := range events {
		ptrs[i] = &events[i]
	}
	return validateScopeContinuity(ptrs)
}
