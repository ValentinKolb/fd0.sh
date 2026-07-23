package proto

const (
	MaxCBORCollectionElements = 131072

	// MaxScopeMembers is the creation/growth bound for v1 scopes.
	MaxScopeMembers = 1000

	// MaxLegacyScopeMembers matches the deterministic CBOR decoder's array
	// bound. Older scopes above MaxScopeMembers remain replayable and can be
	// reduced by removals, but can never grow further.
	MaxLegacyScopeMembers = MaxCBORCollectionElements
	MaxKeyDeliveries      = MaxLegacyScopeMembers
)
