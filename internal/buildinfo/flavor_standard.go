//go:build !yubikey

package buildinfo

const (
	Flavor         = FlavorStandard
	YubikeyEnabled = false
)
