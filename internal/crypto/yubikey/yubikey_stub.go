//go:build !yubikey

package yubikey

// Open is the no-op stub when fd0 is built without the `yubikey` tag.
// The real implementation lives in yubikey_piv.go and depends on libpcsc.
func Open(opts OpenOptions) (PivKey, error) { return nil, ErrNotEnabled }

// List is the stub equivalent of yubikey_piv.go's List.
func List() ([]string, error) { return nil, ErrNotEnabled }

// Initialize is the stub equivalent of the on-card init helper.
func Initialize(slot SlotID, pin string, touch TouchPolicy, pinPolicy PinPolicy) ([]byte, error) {
	return nil, ErrNotEnabled
}
