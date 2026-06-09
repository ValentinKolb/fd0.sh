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
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
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
	Recovery recoveryCmd `cmd:"" help:"Offline backup of super_priv (for new devices or disaster recovery)."`
	Auth     authCmd     `cmd:"" help:"Manage unlock methods (passphrases, future yubikeys)."`
	Doctor   doctorCmd   `cmd:"" help:"Diagnose vault, chain, and tip-binding consistency."`
	Key      keyCmd      `cmd:"" help:"Manage cryptographic keys (top-level; SSH and future consumers use them)."`
	Ssh      sshCmd      `cmd:"" help:"Manage SSH hosts + connect. Without args opens a fuzzy picker."`
	Talos    talosCmd    `cmd:"" help:"Manage Talos Linux contexts + secrets.yaml DR bundles."`
	Kube     kubeCmd     `cmd:"" help:"Manage Kubernetes kubeconfig clusters (Talos, EKS, GKE, AKS, …)."`
	Version  versionCmd  `cmd:"" help:"Print version and exit."`
}

// ───── key ────────────────────────────────────────────────────────────
type keyCmd struct {
	Add  keyAddCmd  `cmd:"" help:"Generate a new key, or import an existing one with --import."`
	List keyListCmd `cmd:"" aliases:"ls" help:"List all keys across scopes."`
	Show keyShowCmd `cmd:"" help:"Print a key's details, or just the public key with --pub."`
	Rm   keyRmCmd   `cmd:"" help:"Remove a key (tombstone)."`
	Move keyMoveCmd `cmd:"" help:"Move a key between scopes."`
}
type keyAddCmd struct {
	Name       string `arg:"" help:"Key name (no prefix)."`
	Type       string `name:"type" help:"Algorithm: only ed25519 supported for new keys." default:"ed25519"`
	Import     string `name:"import" help:"Path to an existing OpenSSH private-key file to import instead of generating."`
	Passphrase string `name:"passphrase" help:"Passphrase for an encrypted imported key. Not recommended interactively." env:"FD0_KEY_IMPORT_PASSPHRASE"`
	Comment    string `name:"comment" help:"Free-form comment; defaults to <name>@fd0."`
	Scope      string `name:"scope" help:"Scope label or id."`
	Force      bool   `name:"force" help:"Overwrite an existing key with the same name."`
}
type keyListCmd struct {
	Scope string `name:"scope" help:"Scope label or id."`
}
type keyShowCmd struct {
	Name  string `arg:"" help:"Key name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Pub   bool   `name:"pub" help:"Print only the public-key authorized_keys line."`
}
type keyRmCmd struct {
	Name  string `arg:"" help:"Key name."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type keyMoveCmd struct {
	Name    string `arg:"" help:"Key name."`
	From    string `name:"scope" help:"Source scope label or id."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope label or id."`
	Force   bool   `name:"force" help:"Overwrite an existing key in the destination scope."`
}

// ───── ssh ────────────────────────────────────────────────────────────
type sshCmd struct {
	Enable  sshEnableCmd  `cmd:"" help:"One-time setup: writes Include line + creates fd0.conf."`
	Disable sshDisableCmd `cmd:"" help:"Reverse the one-time setup."`
	Sock    sshSockCmd    `cmd:"" help:"Print the agent socket path."`

	Add  sshAddCmd  `cmd:"" help:"Add a host."`
	List sshListCmd `cmd:"" aliases:"ls" help:"List hosts."`
	Show sshShowCmd `cmd:"" help:"Show one host."`
	Rm   sshRmCmd   `cmd:"" help:"Remove a host (tombstone)."`
	Tag  sshTagCmd  `cmd:"" help:"Add or remove tags on a host."`
	Move sshMoveCmd `cmd:"" help:"Move a host between scopes."`

	Connect sshConnectCmd `cmd:"" default:"withargs" help:"Connect to a host, or open the picker."`
}

type sshEnableCmd struct{}
type sshDisableCmd struct{}
type sshSockCmd struct{}

type sshAddCmd struct {
	Alias       string            `arg:"" help:"Host alias (the name you ssh to)."`
	Conn        string            `arg:"" optional:"" help:"Optional [user@]hostname[:port] shorthand."`
	User        string            `name:"user" help:"SSH user (overrides conn-string)."`
	Port        int               `name:"port" help:"SSH port (overrides conn-string)."`
	Hostname    string            `name:"hostname" help:"Override conn-string hostname."`
	Key         string            `name:"key" help:"Name of an existing fd0 key to bind."`
	WithKey     bool              `name:"with-key" help:"Generate a new ed25519 key alongside the host."`
	WithKeyName string            `name:"with-key-name" help:"Custom name for the auto-generated key (default: alias)."`
	Jump        string            `name:"jump" help:"ProxyJump alias."`
	Tag         []string          `name:"tag" help:"Add a tag (repeat for multiple)."`
	Description string            `name:"description" help:"Free-form description."`
	Opt         map[string]string `name:"opt" help:"Verbatim ssh_config option (e.g. --opt ForwardAgent=yes)."`
	Scope       string            `name:"scope" help:"Scope label or id."`
	Force       bool              `name:"force" help:"Overwrite an existing host with the same alias (and auto-generated key)."`
}
type sshListCmd struct {
	Scope string   `name:"scope" help:"Scope label or id."`
	Tag   []string `name:"tag" help:"Filter by tag (AND across multiple)."`
	NoTag []string `name:"no-tag" help:"Exclude hosts with this tag."`
}
type sshShowCmd struct {
	Alias string `arg:"" help:"Host alias."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type sshRmCmd struct {
	Alias string `arg:"" help:"Host alias."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type sshTagCmd struct {
	Alias  string   `arg:"" help:"Host alias."`
	Scope  string   `name:"scope" help:"Scope label or id."`
	Add    []string `name:"add" help:"Add this tag."`
	Remove []string `name:"remove" help:"Remove this tag."`
}
type sshMoveCmd struct {
	Alias   string `arg:"" help:"Host alias."`
	From    string `name:"scope" help:"Source scope label or id."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope label or id."`
	Force   bool   `name:"force" help:"Overwrite an existing host with the same alias in the destination."`
}
type sshConnectCmd struct {
	Alias string   `arg:"" optional:"" help:"Host alias. Empty opens picker."`
	Tag   []string `name:"tag" help:"Pre-filter picker by tag."`
	Cmd   []string `arg:"" optional:"" passthrough:"" help:"Command to execute on the host (passed to ssh)."`
}

// ───── talos ──────────────────────────────────────────────────────────
type talosCmd struct {
	Add  talosAddCmd  `cmd:"" help:"Import an existing talosconfig context (or one from --from-config)."`
	New  talosNewCmd  `cmd:"" help:"Day-0: generate cluster PKI + talosconfig from scratch (calls talosctl)."`
	List talosListCmd `cmd:"" aliases:"ls" help:"List talos contexts."`
	Show talosShowCmd `cmd:"" help:"Show one talos context."`
	Rm   talosRmCmd   `cmd:"" help:"Remove a talos context (tombstone)."`
	Move talosMoveCmd `cmd:"" help:"Move a talos context between scopes."`

	Sync         talosSyncCmd         `cmd:"" help:"Re-render ~/.talos/config.fd0 (and merge with --merge)."`
	RoleAdd      talosRoleAddCmd      `cmd:"" name:"role-add" help:"Mint a role-scoped client cert via talosctl + store it."`
	Kubeconfig   talosKubeconfigCmd   `cmd:"" help:"Fetch a fresh admin kubeconfig from a Talos cluster + store it."`

	Secrets talosSecretsCmd `cmd:"" help:"DR-grade secrets.yaml bundles."`
}

type talosAddCmd struct {
	Name          string   `arg:"" optional:"" help:"Context name. Required unless --from-config."`
	Endpoint      []string `name:"endpoint" help:"Talos machine API endpoint (repeat or comma-separate)."`
	Node          []string `name:"node" help:"Default node target (repeat or comma-separate)."`
	CA            string   `name:"ca" help:"base64-encoded CA cert (or use --ca-file)."`
	CAFile        string   `name:"ca-file" help:"PEM file to read into ca."`
	Crt           string   `name:"crt" help:"base64-encoded client cert (or use --crt-file)."`
	CrtFile       string   `name:"crt-file" help:"PEM file to read into crt."`
	Key           string   `name:"key" help:"base64-encoded client key (or use --key-file)."`
	KeyFile       string   `name:"key-file" help:"PEM file to read into key."`
	FromConfig    string   `name:"from-config" help:"Path to an existing talosconfig YAML to import."`
	ImportContext string   `name:"import-context" help:"With --from-config, import only this named context."`
	Role          string   `name:"role" help:"Cert role (os:admin / os:operator / os:reader / …)."`
	Description   string   `name:"description" help:"Free-form description."`
	Tag           []string `name:"tag" help:"Add a tag (repeat for multiple)."`
	Scope         string   `name:"scope" help:"Scope label or id."`
	Force         bool     `name:"force" help:"Overwrite an existing context with the same name."`
}

type talosNewCmd struct {
	Name        string   `arg:"" help:"Cluster name (becomes the talosconfig context name)."`
	Endpoint    string   `name:"endpoint" required:"" help:"Kubernetes API URL, e.g. https://10.0.1.10:6443."`
	OutputDir   string   `name:"out" help:"Where to write controlplane.yaml + worker.yaml (default: current dir)."`
	Scope       string   `name:"scope" help:"Scope for the talosconfig context."`
	VaultScope  string   `name:"vault-scope" help:"Separate scope for the secrets.yaml DR bundle (default: same as --scope)."`
	Description string   `name:"description" help:"Free-form description."`
	Tag         []string `name:"tag" help:"Add a tag."`
	Force       bool     `name:"force" help:"Overwrite an existing stored cluster with the same name (destructive — see talos secrets export first)."`
}

type talosListCmd struct {
	Scope string   `name:"scope" help:"Scope label or id."`
	Tag   []string `name:"tag" help:"Filter by tag (AND)."`
	NoTag []string `name:"no-tag" help:"Exclude tag."`
}
type talosShowCmd struct {
	Name  string `arg:"" help:"Context name."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type talosRmCmd struct {
	Name  string `arg:"" help:"Context name."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type talosMoveCmd struct {
	Name    string `arg:"" help:"Context name."`
	From    string `name:"scope" help:"Source scope."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope."`
	Force   bool   `name:"force" help:"Overwrite an existing context with the same name in destination."`
}
type talosSyncCmd struct {
	Merge bool `name:"merge" help:"After rendering, call talosctl config merge to fold into ~/.talos/config."`
}
type talosRoleAddCmd struct {
	From        string   `name:"from" required:"" help:"Existing fd0-managed talos context with admin privileges (issuer)."`
	NewName     string   `name:"name" required:"" help:"Name for the new context."`
	Role        string   `name:"role" required:"" help:"Role to embed in the new cert (os:operator, os:reader, …)."`
	TTL         string   `name:"ttl" help:"Cert validity (talosctl --crt-ttl). Empty = default (1y)."`
	Scope       string   `name:"scope" help:"Scope for the new context."`
	Description string   `name:"description" help:"Free-form description."`
	Tag         []string `name:"tag" help:"Tag."`
}
type talosKubeconfigCmd struct {
	Name  string `arg:"" help:"Talos context name to pull kubeconfig from."`
	Scope string `name:"scope" help:"Scope for the resulting kubeconfig record."`
}
type talosSecretsCmd struct {
	Export talosSecretsExportCmd `cmd:"" help:"Write a stored secrets.yaml bundle to a file (DR-grade)."`
	Import talosSecretsImportCmd `cmd:"" help:"Read a secrets.yaml from disk into the vault."`
	List   talosSecretsListCmd   `cmd:"" aliases:"ls" help:"List stored bundles."`
}
type talosSecretsExportCmd struct {
	Name  string `arg:"" help:"Bundle name (matches the cluster name passed to 'fd0 talos new')."`
	Out   string `name:"out" required:"" help:"Output path."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Overwrite an existing file at --out."`
}
type talosSecretsImportCmd struct {
	Name  string `arg:"" help:"Bundle name."`
	In    string `name:"in" required:"" help:"Path to the secrets.yaml file."`
	Scope string `name:"scope" help:"Scope."`
}
type talosSecretsListCmd struct {
	Scope string `name:"scope" help:"Scope."`
}

// ───── kube ───────────────────────────────────────────────────────────
type kubeCmd struct {
	Add  kubeAddCmd  `cmd:"" help:"Add a kubeconfig cluster."`
	List kubeListCmd `cmd:"" aliases:"ls" help:"List kubeconfig clusters."`
	Show kubeShowCmd `cmd:"" help:"Show one kubeconfig."`
	Rm   kubeRmCmd   `cmd:"" help:"Remove a kubeconfig (tombstone)."`
	Move kubeMoveCmd `cmd:"" help:"Move a kubeconfig between scopes."`
	Sync kubeSyncCmd `cmd:"" help:"Re-render ~/.kube/config.fd0 (and merge with --merge)."`
}
type kubeAddCmd struct {
	Name                  string   `arg:"" optional:"" help:"Cluster name. Required unless --from-config."`
	Server                string   `name:"server" help:"https://host:6443"`
	CA                    string   `name:"ca" help:"base64-encoded CA cert."`
	CAFile                string   `name:"ca-file" help:"PEM file to read into CA."`
	ClientCert            string   `name:"client-cert" help:"base64-encoded client cert."`
	ClientCertFile        string   `name:"client-cert-file" help:"PEM file."`
	ClientKey             string   `name:"client-key" help:"base64-encoded client key."`
	ClientKeyFile         string   `name:"client-key-file" help:"PEM file."`
	Token                 string   `name:"token" help:"Bearer token (alternative to client cert)."`
	Namespace             string   `name:"namespace" help:"Default namespace."`
	InsecureSkipTLSVerify bool     `name:"insecure-skip-tls-verify" help:"Disable cluster TLS verification."`
	FromConfig            string   `name:"from-config" help:"Path to existing kubeconfig YAML to import."`
	ImportContext         string   `name:"import-context" help:"With --from-config, import only this named context."`
	Description           string   `name:"description" help:"Free-form description."`
	Tag                   []string `name:"tag" help:"Tag."`
	Scope                 string   `name:"scope" help:"Scope."`
	Force                 bool     `name:"force" help:"Overwrite an existing kubeconfig with the same name."`
}
type kubeListCmd struct {
	Scope string   `name:"scope" help:"Scope."`
	Tag   []string `name:"tag" help:"Filter by tag (AND)."`
	NoTag []string `name:"no-tag" help:"Exclude tag."`
}
type kubeShowCmd struct {
	Name  string `arg:"" help:"Cluster name."`
	Scope string `name:"scope" help:"Scope."`
}
type kubeRmCmd struct {
	Name  string `arg:"" help:"Cluster name."`
	Scope string `name:"scope" help:"Scope."`
}
type kubeMoveCmd struct {
	Name    string `arg:"" help:"Cluster name."`
	From    string `name:"scope" help:"Source scope."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope."`
	Force   bool   `name:"force" help:"Overwrite an existing kubeconfig with the same name in destination."`
}
type kubeSyncCmd struct {
	Merge bool `name:"merge" help:"After rendering, call kubectl config view --merge to fold into ~/.kube/config."`
}

type initCmd struct{}
type unlockCmd struct {
	AgentBin string `name:"agent-bin" help:"Path to fd0-agent binary." env:"FD0_AGENT_BIN"`
	Method   string `name:"method" help:"Auth method to use ('passphrase' or 'yubikey'). Default: pick the only enrolled method, or first by method_id when multiple."`
}
type lockCmd struct{}
type statusCmd struct{}
type getCmd struct {
	Name  string `arg:"" optional:"" help:"Secret name."`
	Scope string `name:"scope" help:"Scope ID."`
	Raw   bool   `name:"raw" help:"Print value without trailing newline."`
}
type copyCmd struct {
	Name       string `arg:"" optional:"" help:"Secret name."`
	Scope      string `name:"scope" help:"Scope label or id."`
	ClearAfter string `name:"clear-after" help:"Override clear delay ('30s', '0' to disable). Default: [clipboard].clear_after_seconds in config, else 30s."`
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
	Export recoveryExportCmd `cmd:"" help:"Encrypt super_priv to a recovery file."`
	Import recoveryImportCmd `cmd:"" help:"Bootstrap a fresh device from a recovery file."`
}
type recoveryExportCmd struct {
	Out string `arg:"" name:"out" help:"Output path for the recovery file."`
}
type recoveryImportCmd struct {
	In string `arg:"" name:"in" help:"Path to the recovery file."`
}

type syncCmd struct {
	Server   string `name:"server" help:"fd0-server URL." env:"FD0_SERVER"`
	WaitLock string `name:"wait-lock" help:"Block up to this duration acquiring ~/.fd0/.lock (Go duration string)." env:"FD0_LOCK_WAIT"`
}

type doctorCmd struct{}

type authCmd struct {
	List   authListCmd   `cmd:"" aliases:"ls" help:"List active auth methods."`
	Add    authAddCmd    `cmd:"" help:"Add a new passphrase or YubiKey as an additional auth method."`
	Remove authRemoveCmd `cmd:"" name:"rm" help:"Remove an auth method by id."`
}
type authListCmd struct{}
type authAddCmd struct {
	Yubikey bool   `name:"yubikey" help:"Enroll a YubiKey instead of a passphrase."`
	Touch   string `name:"touch" help:"YubiKey touch policy: 'always' (default, secure), 'never' (no touch), 'cached' (15s cache after first touch)."`
	Force   bool   `name:"force" help:"Overwrite an existing key on slot 9d without prompting (DESTRUCTIVE: invalidates any prior YubiKey enrollment binding to the same card)."`
}
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
		return cli.RunUnlock(ctx, c.Unlock.AgentBin, c.Unlock.Method)
	case "lock":
		return cli.RunLock(ctx)
	case "status":
		return cli.RunStatus(ctx)
	case "get", "get <name>":
		return cli.RunGet(ctx, c.Get.Scope, c.Get.Name, c.Get.Raw)
	case "copy", "copy <name>":
		clearAfter, err := resolveClipboardClear(c.Copy.ClearAfter)
		if err != nil {
			return err
		}
		return cli.RunCopy(ctx, c.Copy.Scope, c.Copy.Name, clearAfter)
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
	case "recovery import <in>":
		return cli.RunRecoveryImport(ctx, c.Recovery.Import.In)
	case "sync":
		if c.Sync.WaitLock != "" {
			os.Setenv("FD0_LOCK_WAIT", c.Sync.WaitLock)
		}
		return cli.RunSyncAll(ctx, cli.ResolveServers(c.Sync.Server))
	case "doctor":
		return cli.RunDoctor(ctx)
	case "auth list", "auth ls":
		return cli.RunAuthList(ctx)
	case "auth add":
		if c.Auth.Add.Yubikey {
			return cli.RunAuthAddYubikey(ctx, c.Auth.Add.Touch, c.Auth.Add.Force)
		}
		return cli.RunAuthAdd(ctx)
	case "auth rm <id>":
		return cli.RunAuthRemove(ctx, c.Auth.Remove.ID)
	case "version":
		fmt.Printf("fd0 %s\n", version)
		return nil

	// ─── key ──────────────────────────────────────────────────────────
	case "key add <name>":
		return cli.RunKeyAdd(ctx, cli.KeyOpts{
			Name:       c.Key.Add.Name,
			Scope:      c.Key.Add.Scope,
			Type:       c.Key.Add.Type,
			Comment:    c.Key.Add.Comment,
			ImportPath: c.Key.Add.Import,
			Passphrase: c.Key.Add.Passphrase,
			Force:      c.Key.Add.Force,
		})
	case "key list", "key ls":
		return cli.RunKeyList(ctx, c.Key.List.Scope, nil, nil)
	case "key show <name>":
		return cli.RunKeyShow(ctx, c.Key.Show.Scope, c.Key.Show.Name, c.Key.Show.Pub)
	case "key rm <name>":
		return cli.RunKeyRemove(ctx, c.Key.Rm.Scope, c.Key.Rm.Name)
	case "key move <name>":
		return cli.RunKeyMove(ctx, c.Key.Move.Name, c.Key.Move.From, c.Key.Move.ToScope, c.Key.Move.Force)

	// ─── ssh ──────────────────────────────────────────────────────────
	case "ssh enable":
		return cli.RunSSHEnable(ctx)
	case "ssh disable":
		return cli.RunSSHDisable(ctx)
	case "ssh sock":
		return cli.RunSSHSock(ctx)

	case "ssh add <alias>", "ssh add <alias> <conn>":
		return cli.RunHostAdd(ctx, cli.HostAddOpts{
			Alias:       c.Ssh.Add.Alias,
			ConnString:  c.Ssh.Add.Conn,
			User:        c.Ssh.Add.User,
			Port:        c.Ssh.Add.Port,
			Hostname:    c.Ssh.Add.Hostname,
			KeyName:     c.Ssh.Add.Key,
			WithKey:     c.Ssh.Add.WithKey,
			WithKeyName: c.Ssh.Add.WithKeyName,
			ProxyJump:   c.Ssh.Add.Jump,
			Tags:        c.Ssh.Add.Tag,
			Description: c.Ssh.Add.Description,
			Options:     c.Ssh.Add.Opt,
			Scope:       c.Ssh.Add.Scope,
			Force:       c.Ssh.Add.Force,
		})
	case "ssh list", "ssh ls":
		return cli.RunHostList(ctx, c.Ssh.List.Scope, c.Ssh.List.Tag, c.Ssh.List.NoTag)
	case "ssh show <alias>":
		return cli.RunHostShow(ctx, c.Ssh.Show.Scope, c.Ssh.Show.Alias)
	case "ssh rm <alias>":
		return cli.RunHostRemove(ctx, c.Ssh.Rm.Scope, c.Ssh.Rm.Alias)
	case "ssh tag <alias>":
		return cli.RunHostTag(ctx, c.Ssh.Tag.Scope, c.Ssh.Tag.Alias, c.Ssh.Tag.Add, c.Ssh.Tag.Remove)
	case "ssh move <alias>":
		return cli.RunHostMove(ctx, c.Ssh.Move.Alias, c.Ssh.Move.From, c.Ssh.Move.ToScope, c.Ssh.Move.Force)

	case "ssh", "ssh connect", "ssh connect <alias>", "ssh connect <alias> <cmd>":
		return cli.RunSSHConnect(ctx, c.Ssh.Connect.Alias, c.Ssh.Connect.Cmd, c.Ssh.Connect.Tag)

	// ── talos ─────────────────────────────────────────────────
	case "talos add", "talos add <name>":
		return cli.RunTalosAdd(ctx, cli.TalosAddOpts{
			Name:          c.Talos.Add.Name,
			Endpoints:     c.Talos.Add.Endpoint,
			Nodes:         c.Talos.Add.Node,
			CA:            c.Talos.Add.CA,
			CAFile:        c.Talos.Add.CAFile,
			Crt:           c.Talos.Add.Crt,
			CrtFile:       c.Talos.Add.CrtFile,
			Key:           c.Talos.Add.Key,
			KeyFile:       c.Talos.Add.KeyFile,
			FromConfig:    c.Talos.Add.FromConfig,
			ImportContext: c.Talos.Add.ImportContext,
			Role:          c.Talos.Add.Role,
			Description:   c.Talos.Add.Description,
			Tags:          c.Talos.Add.Tag,
			Scope:         c.Talos.Add.Scope,
			Force:         c.Talos.Add.Force,
		})
	case "talos new <name>":
		return cli.RunTalosNew(ctx, cli.TalosNewOpts{
			Name:        c.Talos.New.Name,
			Endpoint:    c.Talos.New.Endpoint,
			OutputDir:   c.Talos.New.OutputDir,
			Scope:       c.Talos.New.Scope,
			VaultScope:  c.Talos.New.VaultScope,
			Description: c.Talos.New.Description,
			Tags:        c.Talos.New.Tag,
			Force:       c.Talos.New.Force,
		})
	case "talos list", "talos ls":
		return cli.RunTalosList(ctx, c.Talos.List.Scope, c.Talos.List.Tag, c.Talos.List.NoTag)
	case "talos show <name>":
		return cli.RunTalosShow(ctx, c.Talos.Show.Scope, c.Talos.Show.Name)
	case "talos rm <name>":
		return cli.RunTalosRemove(ctx, c.Talos.Rm.Scope, c.Talos.Rm.Name)
	case "talos move <name>":
		return cli.RunTalosMove(ctx, c.Talos.Move.Name, c.Talos.Move.From, c.Talos.Move.ToScope, c.Talos.Move.Force)
	case "talos sync":
		return cli.RunTalosSync(ctx, c.Talos.Sync.Merge)
	case "talos role-add":
		return cli.RunTalosRoleAdd(ctx, cli.TalosRoleAddOpts{
			SourceContext: c.Talos.RoleAdd.From,
			NewName:       c.Talos.RoleAdd.NewName,
			Role:          c.Talos.RoleAdd.Role,
			TTL:           c.Talos.RoleAdd.TTL,
			Scope:         c.Talos.RoleAdd.Scope,
			Description:   c.Talos.RoleAdd.Description,
			Tags:          c.Talos.RoleAdd.Tag,
		})
	case "talos kubeconfig <name>":
		return cli.RunTalosKubeconfig(ctx, c.Talos.Kubeconfig.Name, c.Talos.Kubeconfig.Scope)
	case "talos secrets export <name>":
		return cli.RunTalosSecretsExport(ctx,
			c.Talos.Secrets.Export.Scope,
			c.Talos.Secrets.Export.Name,
			c.Talos.Secrets.Export.Out,
			c.Talos.Secrets.Export.Force)
	case "talos secrets import <name>":
		return cli.RunTalosSecretsImport(ctx,
			c.Talos.Secrets.Import.Scope,
			c.Talos.Secrets.Import.Name,
			c.Talos.Secrets.Import.In)
	case "talos secrets list", "talos secrets ls":
		return cli.RunTalosSecretsList(ctx, c.Talos.Secrets.List.Scope)

	// ── kube ──────────────────────────────────────────────────
	case "kube add", "kube add <name>":
		return cli.RunKubeAdd(ctx, cli.KubeAddOpts{
			Name:                  c.Kube.Add.Name,
			Server:                c.Kube.Add.Server,
			CA:                    c.Kube.Add.CA,
			CAFile:                c.Kube.Add.CAFile,
			ClientCert:            c.Kube.Add.ClientCert,
			ClientCertFile:        c.Kube.Add.ClientCertFile,
			ClientKey:             c.Kube.Add.ClientKey,
			ClientKeyFile:         c.Kube.Add.ClientKeyFile,
			Token:                 c.Kube.Add.Token,
			Namespace:             c.Kube.Add.Namespace,
			InsecureSkipTLSVerify: c.Kube.Add.InsecureSkipTLSVerify,
			FromConfig:            c.Kube.Add.FromConfig,
			ImportContext:         c.Kube.Add.ImportContext,
			Description:           c.Kube.Add.Description,
			Tags:                  c.Kube.Add.Tag,
			Scope:                 c.Kube.Add.Scope,
			Force:                 c.Kube.Add.Force,
		})
	case "kube list", "kube ls":
		return cli.RunKubeList(ctx, c.Kube.List.Scope, c.Kube.List.Tag, c.Kube.List.NoTag)
	case "kube show <name>":
		return cli.RunKubeShow(ctx, c.Kube.Show.Scope, c.Kube.Show.Name)
	case "kube rm <name>":
		return cli.RunKubeRemove(ctx, c.Kube.Rm.Scope, c.Kube.Rm.Name)
	case "kube move <name>":
		return cli.RunKubeMove(ctx, c.Kube.Move.Name, c.Kube.Move.From, c.Kube.Move.ToScope, c.Kube.Move.Force)
	case "kube sync":
		return cli.RunKubeSync(ctx, c.Kube.Sync.Merge)
	}
	return fmt.Errorf("unknown command %q", kctx.Command())
}

// resolveClipboardClear returns the effective clear-after duration. Order:
//
//	1. CLI flag (--clear-after=...) when non-empty
//	2. [clipboard].clear_after_seconds from ~/.fd0/config.toml
//	3. 30s default
func resolveClipboardClear(flag string) (time.Duration, error) {
	if flag != "" {
		d, err := time.ParseDuration(flag)
		if err != nil {
			return 0, fmt.Errorf("--clear-after %q: %w", flag, err)
		}
		return d, nil
	}
	paths, err := fdhome.Resolve()
	if err == nil {
		cfg, err := fdhome.LoadConfig(paths.Config)
		if err == nil && cfg.Clipboard.ClearAfterSeconds > 0 {
			return time.Duration(cfg.Clipboard.ClearAfterSeconds) * time.Second, nil
		}
	}
	return 30 * time.Second, nil
}
