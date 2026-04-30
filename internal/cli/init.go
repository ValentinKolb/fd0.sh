package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// RunInit performs first-time setup: generate identity, ask for passphrase,
// build a passphrase auth.set genesis, write user.cbor and vault.enc.
func RunInit(ctx context.Context) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	if VaultExists(paths) {
		return fmt.Errorf("vault already exists at %s; refuse to overwrite", paths.Vault)
	}
	if _, err := os.Stat(paths.UserChain); err == nil {
		return fmt.Errorf("user chain already exists at %s; refuse to overwrite", paths.UserChain)
	}
	pass, err := ReadPassphraseConfirm("Choose a passphrase: ", "Confirm passphrase: ")
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)

	pub, priv, err := crypto.GenerateIdentity()
	if err != nil {
		return err
	}
	defer crypto.Wipe(priv)

	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	pp, err := vault.NewPassphraseParams(salt, crypto.DefaultArgon2)
	if err != nil {
		return err
	}
	unlockKey := crypto.DeriveKey(pass, salt, crypto.DefaultArgon2)
	defer crypto.Wipe(unlockKey)

	methodID := "am_" + ulid.Make().String()
	encSP, err := vault.EncryptSuperPriv(priv, pub, methodID, unlockKey)
	if err != nil {
		return err
	}

	// Genesis auth.set.
	g, err := chain.BuildUserAuthSet(priv, pub, 0, nil, []proto.AuthMethod{{
		MethodID:           methodID,
		MethodType:         proto.AuthPassphrase,
		PublicParams:       pp,
		EncryptedSuperPriv: encSP,
	}})
	if err != nil {
		return err
	}
	if err := chain.AppendUser(paths.UserChain, g); err != nil {
		return err
	}
	// Compute auth_tip.
	prefix, err := g.PrevHashInput()
	if err != nil {
		return err
	}
	authTipHash := proto.HashPrefix(prefix)

	// Build initial vault body.
	body := &proto.VaultBody{
		SuperPriv:        priv,
		AuthTip:          proto.ChainTip{Seq: 0, Hash: authTipHash[:]},
		Scopes:           map[string]proto.ScopeVaultData{},
		PinnedIdentities: map[string]proto.PinnedIdentity{},
	}
	if err := vault.Save(paths.Vault, pub, body, []vault.WrapInput{{
		MethodID:     methodID,
		MethodType:   proto.AuthPassphrase,
		PublicParams: pp,
		UnlockKey:    unlockKey,
	}}); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "✓ identity created (%s…)\n", b64sub(pub))
	fmt.Fprintf(os.Stderr, "✓ vault written to %s\n", paths.Vault)
	fmt.Fprintf(os.Stderr, "Run `fd0 unlock` to start the agent.\n")
	return nil
}

// RunUnlock starts the agent if necessary, then sends the credential.
func RunUnlock(ctx context.Context, agentBin string) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	if !VaultExists(paths) {
		return errors.New("no vault found — run `fd0 init` first")
	}
	cli := agent.NewClient(paths.AgentSock)
	if !cli.IsRunning() {
		if err := agent.Spawn(agentBin, paths.AgentLog); err != nil {
			return err
		}
		if err := agent.WaitReady(paths.AgentSock, agentReadyTimeout); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "✓ agent started")
	}
	pass, err := ReadPassphrase("Passphrase: ")
	if err != nil {
		return err
	}
	defer crypto.Wipe(pass)
	if _, err := cli.Unlock(paths.Vault, proto.AuthPassphrase, pass); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "✓ vault unlocked")
	return nil
}

// RunLock asks the agent to lock and exit.
func RunLock(ctx context.Context) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	cli := agent.NewClient(paths.AgentSock)
	if !cli.IsRunning() {
		fmt.Fprintln(os.Stderr, "agent is not running")
		return nil
	}
	if err := cli.Lock(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "✓ vault locked")
	return nil
}

// RunStatus prints agent state.
func RunStatus(ctx context.Context) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	cli := agent.NewClient(paths.AgentSock)
	if !cli.IsRunning() {
		fmt.Println("agent: not running")
		return nil
	}
	st, err := cli.Status()
	if err != nil {
		return err
	}
	if !st.Unlocked {
		fmt.Println("agent: running, locked")
		return nil
	}
	fmt.Printf("agent:  running, unlocked since %d\n", st.SinceUnix)
	fmt.Printf("super_pub: %s\n", b64full(st.UserSuperPub))
	return nil
}

// b64sub returns the first 12 base64 chars of b for human prefixes.
func b64sub(b []byte) string {
	s := b64full(b)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func b64full(b []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, (len(b)+2)/3*4)
	n := len(b)
	for i := 0; i < n; i += 3 {
		var v uint32
		switch {
		case i+3 <= n:
			v = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
		case i+2 == n:
			v = uint32(b[i])<<16 | uint32(b[i+1])<<8
		default:
			v = uint32(b[i]) << 16
		}
		out = append(out, enc[(v>>18)&63], enc[(v>>12)&63], enc[(v>>6)&63], enc[v&63])
	}
	switch n % 3 {
	case 1:
		out = out[:len(out)-2]
		out = append(out, '=', '=')
	case 2:
		out = out[:len(out)-1]
		out = append(out, '=')
	}
	return string(out)
}

const agentReadyTimeout = 5 * 1000_000_000 // 5s in nanoseconds; small enough.

// guard so go vet doesn't flag ed25519 unused if removed by edits.
var _ = ed25519.PublicKeySize
