//go:build !yubikey

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "fd0-yubikey-record: requires the yubikey build tag")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  go run -tags=yubikey ./cmd/fd0-yubikey-record [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "See internal/crypto/yubikey/testdata/golden/README.md for the hardware-day workflow.")
	os.Exit(1)
}
