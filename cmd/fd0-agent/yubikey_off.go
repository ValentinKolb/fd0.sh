//go:build !yubikey

package main

import "github.com/valentinkolb/fd0.sh/internal/vault"

// newYubikeyResolverFactory returns nil on the no-tag build. The agent
// surfaces vault.ErrYubikeyNotConfigured to clients that try to unlock
// with a YubiKey method, pointing at the rebuild-with-tag fix.
func newYubikeyResolverFactory() func(pin []byte) vault.MethodResolver {
	return nil
}
