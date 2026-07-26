package main

import (
	"context"
	"fmt"
	"os"

	"github.com/valentinkolb/fd0.sh/internal/desktopbridge"
)

func main() {
	service, err := desktopbridge.NewServiceFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := desktopbridge.Server{Handler: service}
	if err := server.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
