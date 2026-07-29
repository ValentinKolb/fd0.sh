// Package browserconfig contains the identities shared by the Chrome
// extensions, their Native Messaging manifest, and fd0-browser-host.
package browserconfig

const (
	HostName                   = "sh.fd0.browser"
	StoreExtensionID           = "kcbjlgbkgoabcdflpnohkknfbegcigel"
	StoreExtensionOrigin       = "chrome-extension://" + StoreExtensionID + "/"
	DevelopmentExtensionID     = "flkmmllfacmjnhjgdfliahdkhfjmdoec"
	DevelopmentExtensionOrigin = "chrome-extension://" + DevelopmentExtensionID + "/"
)

// AllowedExtensionOrigins returns the exact Chrome extension origins allowed
// to start fd0-browser-host. Wildcards are deliberately unsupported.
func AllowedExtensionOrigins() []string {
	return []string{StoreExtensionOrigin, DevelopmentExtensionOrigin}
}

// AllowsExtensionOrigin reports whether Chrome started the host for an fd0
// extension identity.
func AllowsExtensionOrigin(origin string) bool {
	return origin == StoreExtensionOrigin || origin == DevelopmentExtensionOrigin
}
