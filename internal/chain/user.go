package chain

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// UserState is the post-replay state of a user identity chain.
type UserState struct {
	UserSuperPub  []byte
	LatestAuthSet *proto.UserEvent
	TipSeq        uint64
	TipHash       []byte // SHA-256 of cbor(latest event without signature)
}

// ReplayUser decodes and verifies every event in path and returns the final
// state. Verification covers: deterministic CBOR, signature under
// user_super_pub, prev_hash chain, seq monotonicity, payload invariants.
func ReplayUser(path string) (*UserState, error) {
	events, err := ReadUserEvents(path)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, nil
	}
	st := &UserState{}
	var prevHash []byte
	for i, ev := range events {
		if ev.Kind != proto.KindAuthSet {
			return nil, fmt.Errorf("chain user[%d]: bad kind %q", i, ev.Kind)
		}
		if i == 0 {
			if ev.Seq != 0 || len(ev.PrevHash) != 0 {
				return nil, fmt.Errorf("chain user[0]: bad genesis seq/prev_hash")
			}
			st.UserSuperPub = append([]byte(nil), ev.UserSuperPub...)
		} else {
			if ev.Seq != st.TipSeq+1 {
				return nil, fmt.Errorf("chain user[%d]: seq=%d, expected %d", i, ev.Seq, st.TipSeq+1)
			}
			if !bytes.Equal(ev.PrevHash, prevHash) {
				return nil, fmt.Errorf("chain user[%d]: prev_hash mismatch", i)
			}
			if !bytes.Equal(ev.UserSuperPub, st.UserSuperPub) {
				return nil, fmt.Errorf("chain user[%d]: user_super_pub changed", i)
			}
		}
		if err := verifyUserEvent(ev, st.UserSuperPub); err != nil {
			return nil, fmt.Errorf("chain user[%d]: %w", i, err)
		}
		hashIn, err := ev.PrevHashInput()
		if err != nil {
			return nil, err
		}
		h := proto.HashPrefix(hashIn)
		prevHash = h[:]
		st.TipSeq = ev.Seq
		st.TipHash = prevHash
		st.LatestAuthSet = ev
	}
	return st, nil
}

func verifyUserEvent(ev *proto.UserEvent, superPub []byte) error {
	if len(ev.Payload.Active) == 0 {
		return errors.New("auth.set: empty active set")
	}
	seen := map[string]struct{}{}
	for _, m := range ev.Payload.Active {
		if m.MethodID == "" {
			return errors.New("auth.set: empty method_id")
		}
		if _, dup := seen[m.MethodID]; dup {
			return fmt.Errorf("auth.set: duplicate method_id %q", m.MethodID)
		}
		seen[m.MethodID] = struct{}{}
		switch m.MethodType {
		case proto.AuthPassphrase, proto.AuthYubikey:
		default:
			return fmt.Errorf("auth.set: unknown method_type %q", m.MethodType)
		}
	}
	si, err := ev.SignedInput()
	if err != nil {
		return err
	}
	if !crypto.VerifyBytes(superPub, si, ev.Signature) {
		return errors.New("auth.set: bad signature")
	}
	return nil
}
