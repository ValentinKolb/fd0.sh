package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/desktopbridge"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

const devPassphrase = "fd0-desktop-dev"

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "fd0 desktop seed:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	home, err := filepath.Abs(paths.Home)
	if err != nil {
		return err
	}
	if err := desktopbridge.WriteIsolatedMarker(home); err != nil {
		return err
	}
	if strings.TrimSpace(os.Getenv("FD0_SSH_SOCK")) == "" {
		return errors.New("FD0_SSH_SOCK is required")
	}
	if strings.TrimSpace(os.Getenv("FD0_AGENT_BIN")) == "" {
		return errors.New("FD0_AGENT_BIN is required")
	}
	if err := writeDevConfig(paths.Config); err != nil {
		return err
	}

	if !cli.VaultExists(paths) {
		pass := []byte(devPassphrase)
		if _, err := cli.InitWithPassphrase(ctx, pass); err != nil {
			crypto.Wipe(pass)
			return err
		}
		crypto.Wipe(pass)
	}
	service, err := desktopbridge.NewServiceFromEnv()
	if err != nil {
		return err
	}
	pass := []byte(devPassphrase)
	_, err = service.Handle(ctx, "vault.unlock", mustJSON(map[string][]byte{"passphrase": pass}))
	crypto.Wipe(pass)
	if err != nil {
		return err
	}
	if err := ensureDemoContact(ctx); err != nil {
		return err
	}
	if err := writeDemoContactCard(home); err != nil {
		return err
	}

	session, err := cli.Open(ctx)
	if err != nil {
		return err
	}
	hasScopes := len(session.Body.Scopes) > 0
	session.Close()
	if hasScopes {
		fmt.Println("fd0 desktop development vault ready")
		return nil
	}
	if err := cli.RunScopeCreate(ctx, "Personal"); err != nil {
		return err
	}
	if err := cli.RunScopeCreate(ctx, "Work"); err != nil {
		return err
	}
	if err := seedRecords(ctx); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(home, ".desktop-seeded"), []byte("fd0-desktop-seed-v1\n"), 0o600); err != nil {
		return err
	}
	fmt.Println("fd0 desktop development vault seeded")
	return nil
}

func ensureDemoContact(ctx context.Context) error {
	session, err := cli.Open(ctx)
	if err != nil {
		return err
	}
	defer session.Close()
	const label = "Benny"
	if _, ok := session.Body.PinnedIdentities[label]; ok {
		return nil
	}
	seed := sha256.Sum256([]byte("fd0 desktop deterministic demo contact: Benny"))
	private := ed25519.NewKeyFromSeed(seed[:])
	defer crypto.Wipe(private)
	public := private.Public().(ed25519.PublicKey)
	if session.Body.PinnedIdentities == nil {
		session.Body.PinnedIdentities = map[string]proto.PinnedIdentity{}
	}
	session.Body.PinnedIdentities[label] = proto.PinnedIdentity{
		SuperPub: append([]byte(nil), public...),
		Label:    label,
	}
	return session.ReSeal()
}

func writeDemoContactCard(home string) error {
	seed := sha256.Sum256([]byte("fd0 desktop deterministic demo contact: Carol"))
	private := ed25519.NewKeyFromSeed(seed[:])
	defer crypto.Wipe(private)
	public := private.Public().(ed25519.PublicKey)
	now := time.Now()
	card := &proto.IdentityCard{
		Version:   1,
		ShortID:   "caroldev",
		SuperPub:  append([]byte(nil), public...),
		IssuedAt:  uint64(now.Unix()),
		ExpiresAt: uint64(now.Add(24 * time.Hour).Unix()),
	}
	signedInput, err := card.SignedInput()
	if err != nil {
		return err
	}
	card.Signature = ed25519.Sign(private, signedInput)
	encoded, err := proto.Marshal(card)
	if err != nil {
		return err
	}
	url := "fd0://card/" + base64.RawURLEncoding.EncodeToString(encoded)
	return os.WriteFile(filepath.Join(home, ".desktop-demo-contact-card"), []byte(url+"\n"), 0o600)
}

func writeDevConfig(path string) error {
	content := []byte("[sync]\ninterval = \"\"\non_unlock = false\n\n[agent]\nidle_timeout = \"1h\"\nmax_lifetime = \"12h\"\n\n[client]\nlock_wait = \"5s\"\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

func seedRecords(ctx context.Context) error {
	session, err := cli.Open(ctx)
	if err != nil {
		return err
	}
	defer session.Close()
	var personal, work string
	for id, scope := range session.Body.Scopes {
		switch scope.Label {
		case "Personal":
			personal = id
		case "Work":
			work = id
		}
	}
	if personal == "" || work == "" {
		return errors.New("seed scopes missing")
	}

	github, err := loginItem("GitHub", "https://github.com", "valentin@example.com", "d3v-Vault!GitHub-2026")
	if err != nil {
		return err
	}
	totp, err := passitem.NewTOTPField(passitem.TOTPValue{
		Secret: "JBSWY3DPEHPK3PXP", Issuer: "GitHub", Account: "valentin@example.com",
	})
	if err != nil {
		return err
	}
	if err := github.SetField("one-time password", totp); err != nil {
		return err
	}
	if err := github.AddSection("Recovery"); err != nil {
		return err
	}
	recovery, _ := passitem.NewStringField(passitem.FieldSecret, "GH-4H9K-7M2P")
	if err := github.SetField("Recovery/recovery code", recovery); err != nil {
		return err
	}
	file, err := passitem.NewFileField("github-recovery.txt", "text/plain", []byte("fd0 desktop recovery demo\n"))
	if err != nil {
		return err
	}
	if err := github.SetField("Recovery/backup file", file); err != nil {
		return err
	}
	passkey, err := passitem.NewRawJSONField(passitem.FieldPasskey, []byte(`{"credential_id":"demo-credential","rp_id":"github.com","user":"valentin@example.com"}`))
	if err != nil {
		return err
	}
	if err := github.SetField("passkey", passkey); err != nil {
		return err
	}
	github.Meta["favorite"] = true
	if err := session.SetTypedSecret(ctx, personal, "pass:github", passitem.TypePassItem, github.Marshal()); err != nil {
		return err
	}

	stuve, err := loginItem("Stuve Cloud", "https://cloud.stuve.dev", "admin@stuve.dev", "Stuve-Cloud!Demo-42")
	if err != nil {
		return err
	}
	if err := session.SetTypedSecret(ctx, work, "pass:stuve-cloud", passitem.TypePassItem, stuve.Marshal()); err != nil {
		return err
	}
	hetzner, err := loginItem("Hetzner Cloud", "https://console.hetzner.cloud", "valentin", "Hetzner!Demo-2026")
	if err != nil {
		return err
	}
	if err := session.SetTypedSecret(ctx, personal, "pass:hetzner", passitem.TypePassItem, hetzner.Marshal()); err != nil {
		return err
	}

	key, err := sshkey.NewEd25519("fd0-production", "administrator@fd0")
	if err != nil {
		return err
	}
	defer crypto.Wipe(key.Private)
	if err := session.SetTypedSecret(ctx, work, "ssh:fd0-production", string(key.Type), key.Marshal()); err != nil {
		return err
	}
	hosts := []*sshhost.Host{
		{Alias: "fd0", Hostname: "109.70.197.33", User: "administrator", Port: 22, KeyName: "fd0-production", Description: "fd0 production host"},
		{Alias: "talos-gw", Hostname: "10.0.0.5", User: "root", Port: 22, KeyName: "fd0-production", Description: "Talos cluster gateway"},
	}
	for _, host := range hosts {
		if err := host.Validate(); err != nil {
			return err
		}
		if err := session.SetTypedSecret(ctx, work, "host:"+host.Alias, sshhost.TypeHost, host.Marshal()); err != nil {
			return err
		}
	}

	certificate := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nFD0 DESKTOP DEMO\n-----END CERTIFICATE-----\n"))
	privateKey := base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----\nFD0 DESKTOP DEMO\n-----END PRIVATE KEY-----\n"))
	kube := &kubeconfig.Kubeconfig{
		Name: "kolb-talos", Server: "https://10.0.0.10:6443", CA: certificate,
		ClientCert: certificate, ClientKey: privateKey, Namespace: "default",
		Description: "Kolb Talos production cluster",
	}
	if err := kube.Validate(); err != nil {
		return err
	}
	if err := session.SetTypedSecret(ctx, work, "kube:kolb-talos", kubeconfig.TypeKubeconfig, kube.Marshal()); err != nil {
		return err
	}
	talos := &talosctx.TalosContext{
		Name: "kolb-talos", Endpoints: []string{"10.0.0.11", "10.0.0.12", "10.0.0.13"},
		Nodes: []string{"10.0.0.11"}, CA: certificate, Crt: certificate, Key: privateKey,
		Role: talosctx.RoleAdmin, Description: "Kolb Talos control plane",
	}
	if err := talos.Validate(); err != nil {
		return err
	}
	if err := session.SetTypedSecret(ctx, work, "talos:kolb-talos", talosctx.TypeTalosContext, talos.Marshal()); err != nil {
		return err
	}
	session.Close()

	for _, secret := range []struct {
		scope string
		name  string
		value string
	}{
		{work, "GHCR_TOKEN", "ghp_fd0_desktop_demo_token"},
		{work, "BACKUP_ENCRYPTION_KEY", "age1fd0desktopdemo"},
		{personal, "INWX_API_PASSWORD", "inwx-demo-password"},
	} {
		if err := cli.RunSecretSet(ctx, secret.scope, secret.name, secret.value); err != nil {
			return err
		}
	}
	return nil
}

func loginItem(title, url, username, password string) (*passitem.Item, error) {
	item := passitem.New(title, []string{url})
	userField, err := passitem.NewStringField(passitem.FieldText, username)
	if err != nil {
		return nil, err
	}
	if err := item.SetField("username", userField); err != nil {
		return nil, err
	}
	passwordField, err := passitem.NewStringField(passitem.FieldSecret, password)
	if err != nil {
		return nil, err
	}
	if err := item.SetField("password", passwordField); err != nil {
		return nil, err
	}
	return item, nil
}

func mustJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}
