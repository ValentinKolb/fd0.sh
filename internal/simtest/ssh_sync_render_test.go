package simtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncRendersSSHConfigWhenEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	bob := h.AddClient("bob")
	h.ShareScope(alice, "shared", bob)
	enableSSHInclude(t, bob)

	if out, err := alice.run("key", "add", "deploy", "--scope", "shared"); err != nil {
		t.Fatalf("alice key add: %v\n%s", err, out)
	}
	if out, err := alice.run("ssh", "add", "prod-db", "app@db.internal", "--key", "deploy", "--scope", "shared"); err != nil {
		t.Fatalf("alice ssh add: %v\n%s", err, out)
	}
	if out, ok := alice.Sync(); !ok {
		t.Fatalf("alice sync failed:\n%s", out)
	}
	if out, ok := bob.Sync(); !ok {
		t.Fatalf("bob sync failed:\n%s", out)
	}

	out, err := bob.run("ssh", "ls")
	if err != nil {
		t.Fatalf("bob ssh ls: %v\n%s", err, out)
	}
	if !strings.Contains(out, "prod-db") {
		t.Fatalf("bob fd0 inventory missing prod-db after sync:\n%s", out)
	}

	confPath := filepath.Join(bob.hostDir, ".ssh", "fd0.conf")
	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read rendered ssh config: %v", err)
	}
	conf := string(data)
	if !strings.Contains(conf, "Host prod-db\n") {
		t.Fatalf("rendered ssh config missing prod-db:\n%s", conf)
	}
	if !strings.Contains(conf, "HostName db.internal\n") {
		t.Fatalf("rendered ssh config missing remote hostname:\n%s", conf)
	}
	pubPath := filepath.Join(bob.hostDir, ".ssh", "fd0.d", "prod-db.pub")
	info, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("expected public-key selector %s: %v", pubPath, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("public-key selector mode: got %o want 0600", got)
	}
}

func TestSSHConnectWorksWithoutSSHEnable(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	if out, err := alice.run("scope", "create", "--label", "shared"); err != nil {
		t.Fatalf("scope create: %v\n%s", err, out)
	}
	if out, err := alice.run("key", "add", "deploy", "--scope", "shared"); err != nil {
		t.Fatalf("key add: %v\n%s", err, out)
	}
	if out, err := alice.run("ssh", "add", "prod-db", "app@db.internal", "--key", "deploy", "--scope", "shared"); err != nil {
		t.Fatalf("ssh add: %v\n%s", err, out)
	}

	sshDir := filepath.Join(alice.hostDir, ".ssh")
	mustMkdir(t, sshDir)
	userCfg := filepath.Join(sshDir, "config")
	mustWrite(t, userCfg, "Host *\n  ServerAliveInterval 10\n")

	fakeBin := filepath.Join(h.dir, "fakebin")
	mustMkdir(t, fakeBin)
	argsPath := filepath.Join(h.dir, "ssh-args.txt")
	script := "#!/bin/sh\nfor arg do printf '%s\\n' \"$arg\"; done > '" + argsPath + "'\n"
	sshPath := filepath.Join(fakeBin, "ssh")
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+pathEnv())

	out, err := alice.run("ssh", "prod-db", "uptime")
	if err != nil {
		t.Fatalf("fd0 ssh should exec fake ssh: %v\n%s", err, out)
	}
	rawArgs, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read fake ssh args: %v\nfd0 output:\n%s", err, out)
	}
	args := strings.Split(strings.TrimSpace(string(rawArgs)), "\n")
	if len(args) != 4 || args[0] != "-F" || args[2] != "prod-db" || args[3] != "uptime" {
		t.Fatalf("unexpected ssh argv: %#v\nfd0 output:\n%s", args, out)
	}
	compositePath := args[1]
	wantComposite := filepath.Join(sshDir, "fd0.connect.conf")
	if compositePath != wantComposite {
		t.Fatalf("unexpected composite config path: got %s want %s", compositePath, wantComposite)
	}
	compositeRaw, err := os.ReadFile(compositePath)
	if err != nil {
		t.Fatalf("read composite config: %v", err)
	}
	composite := string(compositeRaw)
	fd0Conf := filepath.Join(sshDir, "fd0.conf")
	if !strings.Contains(composite, `Include "`+fd0Conf+`"`) {
		t.Fatalf("composite config missing fd0 include:\n%s", composite)
	}
	if !strings.Contains(composite, `Include "`+userCfg+`"`) {
		t.Fatalf("composite config missing user config include:\n%s", composite)
	}
	fd0Raw, err := os.ReadFile(fd0Conf)
	if err != nil {
		t.Fatalf("read fd0 ssh config: %v", err)
	}
	if !strings.Contains(string(fd0Raw), "Host prod-db\n") {
		t.Fatalf("fd0 ssh config missing prod-db:\n%s", fd0Raw)
	}
}

func TestSSHConnectReportsRefusingSSHAgentSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("simtest builds binaries + spawns agents; skipped in -short")
	}

	h := New(t, 1)
	alice := h.AddClient("alice")
	if out, err := alice.run("scope", "create", "--label", "shared"); err != nil {
		t.Fatalf("scope create: %v\n%s", err, out)
	}
	if out, err := alice.run("ssh", "add", "prod-db", "app@db.internal", "--scope", "shared"); err != nil {
		t.Fatalf("ssh add: %v\n%s", err, out)
	}

	staleSock := filepath.Join(h.dir, "stale-connect-ssh.sock")
	leaveStaleUnixSocket(t, staleSock)

	fakeBin := filepath.Join(h.dir, "fakebin-stale")
	mustMkdir(t, fakeBin)
	argsPath := filepath.Join(h.dir, "ssh-should-not-run.txt")
	sshPath := filepath.Join(fakeBin, "ssh")
	script := "#!/bin/sh\nprintf ran > '" + argsPath + "'\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}

	cmd := exec.Command(h.fd0Bin, "ssh", "prod-db")
	cmd.Env = replaceEnv(alice.env(), "FD0_SSH_SOCK", staleSock)
	cmd.Env = replaceEnv(cmd.Env, "PATH", fakeBin+string(os.PathListSeparator)+pathEnv())
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("fd0 ssh should fail before exec with stale socket:\n%s", out)
	}
	text := string(out)
	if !strings.Contains(text, "fd0 SSH agent socket unavailable") || !strings.Contains(text, staleSock) {
		t.Fatalf("fd0 ssh did not report stale socket clearly:\n%s", text)
	}
	if _, err := os.Stat(argsPath); !os.IsNotExist(err) {
		t.Fatalf("fake ssh should not have been executed, stat err=%v", err)
	}
}

func enableSSHInclude(t *testing.T, c *Client) {
	t.Helper()
	sshDir := filepath.Join(c.hostDir, ".ssh")
	mustMkdir(t, sshDir)
	confPath := filepath.Join(sshDir, "fd0.conf")
	userCfg := filepath.Join(sshDir, "config")
	mustWrite(t, userCfg, "Include "+confPath+"\n")
}
