package cli

import (
	"fmt"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Scope-level metadata is stored as a single secret per scope by convention.
// It rides on the regular secret.set machinery (encryption, OEK rotation,
// sync, auto-discover) — no new event kind needed.
//
//	secret_id: "s_scope_meta"   (reserved; identical across all scopes)
//	name     : "_meta"
//	type     : "scope.meta"
//	payload  : map{"label": "..."}
//
// The CLI filters `_meta` out of regular list/search output.
const (
	MetaSecretID   = "s_scope_meta"
	MetaSecretName = "_meta"
	MetaSecretType = "scope.meta"
	MetaKeyLabel   = "label"
)

// writeScopeMeta updates the _meta secret of scopeID. Performs a replay,
// builds a fresh secret.set, appends, and re-seals.
//
// Caller must hold the session lock; the helper re-uses Session.Agent.
func (s *Session) writeScopeMeta(scopeID string, fields map[string]string) error {
	sd := s.Body.Scopes[scopeID]
	if len(sd.OEKs) == 0 {
		return fmt.Errorf("scope %s: no OEK in vault", scopeName(s, scopeID))
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	var curOEK proto.OEKEntry
	for _, e := range sd.OEKs {
		if e.Version == st.CurrentOEKVer {
			curOEK = e
			break
		}
	}
	if curOEK.Version == 0 {
		return fmt.Errorf("scope %s: no OEK v%d in vault", scopeName(s, scopeID), st.CurrentOEKVer)
	}
	body := &proto.SecretBody{
		ID: MetaSecretID,
		Record: &proto.SecretRecord{
			Name:          MetaSecretName,
			Type:          MetaSecretType,
			SchemaVersion: 1,
			Payload:       fields,
		},
	}
	ev, err := chain.BuildSecretSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub, scopeID,
		st.TipSeq, st.TipHash, curOEK.Key, curOEK.Version, body)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(scopeID), ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd.ChainTip = proto.ChainTip{Seq: st.TipSeq + 1, Hash: tipHash[:]}
	if l := fields[MetaKeyLabel]; l != "" {
		sd.Label = l
	}
	s.Body.Scopes[scopeID] = sd
	return s.ReSeal()
}

// metaLabelFromIndex extracts the scope label from a replayed secret_index.
// Returns "" when no _meta is present or the payload shape isn't recognised.
func metaLabelFromIndex(idx map[string]chain.ScopeSecret) string {
	cur, ok := idx[MetaSecretID]
	if !ok || cur.Record == nil {
		return ""
	}
	if cur.Record.Name != MetaSecretName {
		return ""
	}
	return labelFromPayload(cur.Record.Payload)
}

// labelFromPayload navigates the loose `any`-typed Payload to find a label.
// CBOR decodes string-keyed maps into map[interface{}]interface{} when the
// target is `any`; we accept the common shapes.
func labelFromPayload(p any) string {
	switch m := p.(type) {
	case map[string]string:
		return m[MetaKeyLabel]
	case map[string]interface{}:
		if v, ok := m[MetaKeyLabel]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	case map[interface{}]interface{}:
		if v, ok := m[MetaKeyLabel]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// isMetaSecret reports whether (id, name) refer to the reserved meta entry.
func isMetaSecret(id, name string) bool {
	return id == MetaSecretID || name == MetaSecretName
}
