package buildinfo

const (
	FlavorStandard = "standard"
	FlavorYubikey  = "yubikey"
)

func NormalizeFlavor(flavor string) string {
	switch flavor {
	case FlavorYubikey:
		return FlavorYubikey
	default:
		return FlavorStandard
	}
}
