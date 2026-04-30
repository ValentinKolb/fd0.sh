// fd0 is the user-facing CLI. All cryptographic operations route through
// fd0-agent (Unix socket at $FD0_HOME/agent.sock).
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/alecthomas/kong"
	"github.com/awnumar/memguard"

	"github.com/valentinkolb/fd0.sh/internal/cli"
)

// version is overwritten by goreleaser via `-ldflags="-X main.version=..."`.
var version = "dev"

type rootCLI struct {
	Init    initCmd    `cmd:"" help:"Create a new identity and vault."`
	Unlock  unlockCmd  `cmd:"" help:"Start the agent and unlock the vault."`
	Lock    lockCmd    `cmd:"" help:"Lock the vault and stop the agent."`
	Status  statusCmd  `cmd:"" help:"Show agent status."`
	Get     getCmd     `cmd:"" help:"Print a secret to stdout. Interactive when called without NAME."`
	Copy    copyCmd    `cmd:"" help:"Copy a secret to the clipboard with auto-clear."`
	Set     setCmd     `cmd:"" help:"Add or update a secret."`
	Rm      rmCmd      `cmd:"" help:"Remove a secret (writes a tombstone)."`
	List    listCmd    `cmd:"" aliases:"ls" help:"List secrets."`
	Scope   scopeCmd   `cmd:"" help:"Scope management."`
	Sync    syncCmd    `cmd:"" help:"Sync with the fd0 server."`
	Card     cardCmd     `cmd:"" help:"Identity card (export your super_pub for invites)."`
	Recovery recoveryCmd `cmd:"" help:"Offline backup of super_priv for disaster recovery."`
	Auth     authCmd     `cmd:"" help:"Manage unlock methods (passphrases, future yubikeys)."`
	Doctor   doctorCmd   `cmd:"" help:"Diagnose vault, chain, and tip-binding consistency."`
	Version  versionCmd  `cmd:"" help:"Print version and exit."`

	NoAgent bool `name:"no-agent" help:"Disable agent (not implemented in v1)." env:"FD0_NO_AGENT"`
}

type initCmd struct{}
type unlockCmd struct {
	AgentBin string `name:"agent-bin" help:"Path to fd0-agent binary." env:"FD0_AGENT_BIN"`
}
type lockCmd struct{}
type statusCmd struct{}
type getCmd struct {
	Name  string `arg:"" optional:"" help:"Secret name."`
	Scope string `name:"scope" help:"Scope ID."`
	Raw   bool   `name:"raw" help:"Print value without trailing newline."`
}
type copyCmd struct {
	Name       string        `arg:"" optional:"" help:"Secret name."`
	Scope      string        `name:"scope" help:"Scope ID."`
	ClearAfter time.Duration `name:"clear-after" help:"Clear clipboard after this duration (0 = never)." default:"30s"`
}
type setCmd struct {
	Name  string `arg:"" help:"Secret name."`
	Value string `arg:"" help:"Secret value (use - to read from stdin)."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type rmCmd struct {
	Name  string `arg:"" help:"Secret name."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type listCmd struct{}

type scopeCmd struct {
	Create       scopeCreateCmd       `cmd:"" help:"Create a new scope."`
	List         scopeListCmd         `cmd:"" aliases:"ls" help:"List scopes."`
	Members      scopeMembersCmd      `cmd:"" help:"List members of a scope."`
	AddMember    scopeAddMemberCmd    `cmd:"" name:"add-member" help:"Add a member by their card."`
	RemoveMember scopeRemoveMemberCmd `cmd:"" name:"remove-member" help:"Remove a member."`
	Leave        scopeLeaveCmd        `cmd:"" help:"Leave a scope (remove self + drop locally)."`
	Rename       scopeRenameCmd       `cmd:"" help:"Rename a scope's label (local only in v1)."`
}
type scopeCreateCmd struct {
	Label string `name:"label" help:"Optional human-readable label."`
}
type scopeListCmd struct{}
type scopeMembersCmd struct {
	Scope string `arg:"" optional:"" help:"Scope label or id."`
}
type scopeAddMemberCmd struct {
	Card  string `arg:"" help:"Member identity card (base64 super_pub)."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type scopeRemoveMemberCmd struct {
	Card  string `arg:"" help:"Member identity card (base64 super_pub)."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type scopeLeaveCmd struct {
	Scope string `arg:"" optional:"" help:"Scope label or id."`
}
type scopeRenameCmd struct {
	Scope string `arg:"" help:"Scope label or id."`
	NewLabel string `arg:"" name:"new-label" help:"New label."`
}

type cardCmd struct {
	Export cardExportCmd `cmd:"" help:"Print this user's identity card URL."`
	Import cardImportCmd `cmd:"" help:"Import a card URL and pin it under a label."`
	List   cardListCmd   `cmd:"" aliases:"ls" help:"List pinned identities."`
	Remove cardRemoveCmd `cmd:"" name:"rm" help:"Unpin a label."`
}
type cardExportCmd struct{}
type cardImportCmd struct {
	URL   string `arg:"" name:"url" help:"Card URL: fd0://card/..."`
	Label string `name:"label" help:"Local label for this identity (defaults to the card's shortId)."`
	Yes   bool   `name:"yes" short:"y" help:"Skip the safety-number confirm prompt."`
}
type cardListCmd struct{}
type cardRemoveCmd struct {
	Label string `arg:"" help:"Pinned label to unpin."`
}

type recoveryCmd struct {
	Export  recoveryExportCmd  `cmd:"" help:"Encrypt super_priv to a recovery file."`
	Restore recoveryRestoreCmd `cmd:"" help:"Bootstrap a fresh device from a recovery file."`
}
type recoveryExportCmd struct {
	Out string `arg:"" name:"out" help:"Output path for the recovery file."`
}
type recoveryRestoreCmd struct {
	In string `arg:"" name:"in" help:"Path to the recovery file."`
}

type syncCmd struct {
	Server   string `name:"server" help:"fd0-server URL." env:"FD0_SERVER"`
	WaitLock string `name:"wait-lock" help:"Block up to this duration acquiring ~/.fd0/.lock (Go duration string)." env:"FD0_LOCK_WAIT"`
}

type doctorCmd struct{}

type authCmd struct {
	List   authListCmd   `cmd:"" aliases:"ls" help:"List active auth methods."`
	Add    authAddCmd    `cmd:"" help:"Add a new passphrase as an additional auth method."`
	Remove authRemoveCmd `cmd:"" name:"rm" help:"Remove an auth method by id."`
}
type authListCmd struct{}
type authAddCmd struct{}
type authRemoveCmd struct {
	ID string `arg:"" help:"method_id (am_...) — see 'fd0 auth ls'."`
}
type versionCmd struct{}

func main() {
	// Hidden helper: the `fd0 copy` command spawns a detached child of itself
	// that clears the clipboard after a delay. We special-case that branch
	// before kong parses argv so it doesn't show up in help output.
	if len(os.Args) >= 3 && os.Args[1] == cli.ClipboardClearHelperArgv {
		secs, _ := strconv.Atoi(os.Args[2])
		cli.RunClipboardClearHelper(secs)
		return
	}

	memguard.CatchInterrupt()
	defer memguard.Purge()

	var c rootCLI
	ctx := kong.Parse(&c,
		kong.Name("fd0"),
		kong.Description("zero-knowledge secret store · v"+version),
		kong.UsageOnError(),
	)
	if err := dispatch(ctx, &c); err != nil {
		fmt.Fprintln(os.Stderr, "✗ "+err.Error())
		os.Exit(1)
	}
}

func dispatch(kctx *kong.Context, c *rootCLI) error {
	ctx := context.Background()
	switch kctx.Command() {
	case "init":
		return cli.RunInit(ctx)
	case "unlock":
		return cli.RunUnlock(ctx, c.Unlock.AgentBin)
	case "lock":
		return cli.RunLock(ctx)
	case "status":
		return cli.RunStatus(ctx)
	case "get", "get <name>":
		return cli.RunGet(ctx, c.Get.Scope, c.Get.Name, c.Get.Raw)
	case "copy", "copy <name>":
		return cli.RunCopy(ctx, c.Copy.Scope, c.Copy.Name, c.Copy.ClearAfter)
	case "set <name> <value>":
		return cli.RunSecretSet(ctx, c.Set.Scope, c.Set.Name, c.Set.Value)
	case "rm <name>":
		return cli.RunSecretRemove(ctx, c.Rm.Scope, c.Rm.Name)
	case "list", "ls":
		return cli.RunSecretList(ctx)
	case "scope create":
		return cli.RunScopeCreate(ctx, c.Scope.Create.Label)
	case "scope list", "scope ls":
		return cli.RunScopeList(ctx)
	case "scope members", "scope members <scope>":
		return cli.RunScopeMembers(ctx, c.Scope.Members.Scope)
	case "scope add-member <card>":
		return cli.RunScopeAddMember(ctx, c.Scope.AddMember.Scope, c.Scope.AddMember.Card)
	case "scope remove-member <card>":
		return cli.RunScopeRemoveMember(ctx, c.Scope.RemoveMember.Scope, c.Scope.RemoveMember.Card)
	case "scope leave", "scope leave <scope>":
		return cli.RunScopeLeave(ctx, c.Scope.Leave.Scope)
	case "scope rename <scope> <new-label>":
		return cli.RunScopeRename(ctx, c.Scope.Rename.Scope, c.Scope.Rename.NewLabel)
	case "card export":
		return cli.RunCardExport(ctx)
	case "card import <url>":
		return cli.RunCardImport(ctx, c.Card.Import.URL, c.Card.Import.Label, c.Card.Import.Yes)
	case "card list", "card ls":
		return cli.RunCardList(ctx)
	case "card rm <label>":
		return cli.RunCardRemove(ctx, c.Card.Remove.Label)
	case "recovery export <out>":
		return cli.RunRecoveryExport(ctx, c.Recovery.Export.Out)
	case "recovery restore <in>":
		return cli.RunRecoveryRestore(ctx, c.Recovery.Restore.In)
	case "sync":
		if c.Sync.WaitLock != "" {
			os.Setenv("FD0_LOCK_WAIT", c.Sync.WaitLock)
		}
		return cli.RunSync(ctx, c.Sync.Server)
	case "doctor":
		return cli.RunDoctor(ctx)
	case "auth list", "auth ls":
		return cli.RunAuthList(ctx)
	case "auth add":
		return cli.RunAuthAdd(ctx)
	case "auth rm <id>":
		return cli.RunAuthRemove(ctx, c.Auth.Remove.ID)
	case "version":
		fmt.Printf("fd0 %s\n", version)
		return nil
	}
	return fmt.Errorf("unknown command %q", kctx.Command())
}
