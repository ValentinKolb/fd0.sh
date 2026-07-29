// fd0-browser-host is the narrow Chrome/Chromium Native Messaging adapter for fd0.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/browserhost"
)

const requestTimeout = 12 * time.Second

func main() {
	callerOrigin := ""
	if len(os.Args) > 1 {
		callerOrigin = os.Args[1]
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := browserhost.Run(ctx, callerOrigin, os.Stdin, os.Stdout); err != nil {
		// stdout is reserved for Native Messaging frames.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
