package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/sftpbridge"
	"github.com/valentinkolb/fd0.sh/internal/sftpclient"
)

func main() {
	host := flag.String("host", "", "fd0 SSH host alias")
	scope := flag.String("scope", "", "fd0 scope label or id")
	flag.Parse()
	if *host == "" {
		fmt.Fprintln(os.Stderr, "fd0 SFTP bridge: host is required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	connection, err := cli.PrepareOpenSSHConnection(ctx, *scope, *host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fd0 SFTP bridge: could not prepare host")
		os.Exit(1)
	}
	client, err := sftpclient.Dial(ctx, sftpclient.Command{
		Binary: connection.SSHBinary,
		Args:   connection.SFTPSubsystemArgs(),
		Env:    os.Environ(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fd0 SFTP bridge: could not connect")
		os.Exit(1)
	}
	defer func() { _ = client.Close() }()
	server := sftpbridge.Server{Client: client}
	if err := server.Serve(ctx, os.Stdin, os.Stdout); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "fd0 SFTP bridge: session ended unexpectedly")
		os.Exit(1)
	}
}
