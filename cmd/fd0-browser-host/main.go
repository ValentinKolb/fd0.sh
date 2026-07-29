// fd0-browser-host is the read-only Chrome Native Messaging adapter for fd0.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/browserhost"
)

func main() {
	callerOrigin := ""
	if len(os.Args) > 1 {
		callerOrigin = os.Args[1]
	}
	if err := browserhost.Run(context.Background(), callerOrigin, os.Stdin, os.Stdout); err != nil {
		// stdout is reserved for Native Messaging frames.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
