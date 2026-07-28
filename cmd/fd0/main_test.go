package main

import (
	"testing"

	"github.com/alecthomas/kong"
)

func TestDoctorDoesNotAutoUnlock(t *testing.T) {
	if commandNeedsUnlockedVault("doctor") {
		t.Fatal("doctor must report a locked agent instead of prompting for credentials")
	}
	if !commandNeedsUnlockedVault("pass list") {
		t.Fatal("vault commands must keep their interactive auto-unlock behavior")
	}
}

func TestSSHConnectAcceptsScope(t *testing.T) {
	var command rootCLI
	parser, err := kong.New(&command)
	if err != nil {
		t.Fatal(err)
	}
	context, err := parser.Parse([]string{"ssh", "connect", "--scope", "work", "server"})
	if err != nil {
		t.Fatal(err)
	}
	if got := context.Command(); got != "ssh connect <alias>" {
		t.Fatalf("command=%q", got)
	}
	if command.Ssh.Connect.Scope != "work" || command.Ssh.Connect.Alias != "server" {
		t.Fatalf("scope=%q alias=%q", command.Ssh.Connect.Scope, command.Ssh.Connect.Alias)
	}
}
