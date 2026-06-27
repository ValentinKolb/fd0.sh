/**
 * /docs/* - user-facing fd0 documentation.
 *
 * The repository docs are the protocol and operator source of truth. These
 * pages explain how to use fd0 on fd0.sh or against a self-hosted primary.
 */

import { setPageSeo, ssr } from "../../config";
import { Shell } from "../lib/shell";
import { C, FONT_MONO, DocsLayout } from "../lib/chrome";

const H2 = (p: { children: any; id?: string }) => (
  <h2 id={p.id} class="text-xl md:text-[1.45rem] font-medium mt-12 mb-4">
    {p.children}
  </h2>
);

const P = (p: { children: any }) => (
  <p class="text-[15px] leading-relaxed mb-4" style={`color:${C.dim};`}>
    {p.children}
  </p>
);

const Code = (p: { children: any }) => (
  <span style={`color:${C.acc};font-family:${FONT_MONO};`}>{p.children}</span>
);

const Box = (p: { children: any }) => (
  <div
    class="p-4 text-[13px] leading-[1.6] mb-5 overflow-x-auto"
    style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
  >
    <Shell>{p.children}</Shell>
  </div>
);

const Note = (p: { children: any }) => (
  <div
    class="p-4 text-[13.5px] leading-relaxed mb-5"
    style={`background:${C.bgRaised};border-left:2px solid ${C.acc};color:${C.dim};`}
  >
    {p.children}
  </div>
);

const Link = (p: { href: string; children: any }) => (
  <a href={p.href} style={`color:${C.acc};`}>
    {p.children}
  </a>
);

const Cmd = (p: { signature: string; body: any; example?: string }) => (
  <div
    class="p-4 mb-3"
    style={`background:${C.bgRaised};border:1px solid ${C.border};`}
  >
    <div
      class="text-[14px] font-medium mb-2"
      style={`color:${C.acc};font-family:${FONT_MONO};`}
    >
      {p.signature}
    </div>
    <p class="text-sm leading-relaxed mb-3" style={`color:${C.dim};`}>
      {p.body}
    </p>
    {p.example ? (
      <div
        class="p-3 text-[12.5px] leading-[1.55] overflow-x-auto"
        style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
      >
        <Shell>{p.example}</Shell>
      </div>
    ) : null}
  </div>
);

const TileGrid = (p: { children: any }) => (
  <div class="grid sm:grid-cols-2 gap-4 mt-8">{p.children}</div>
);

const Tile = (p: { href: string; title: string; body: string }) => (
  <a
    href={p.href}
    class="block p-4 transition-colors"
    style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};`}
  >
    <div class="font-medium mb-1" style={`color:${C.acc};`}>
      {p.title}
    </div>
    <div class="text-sm leading-relaxed" style={`color:${C.dim};`}>
      {p.body}
    </div>
  </a>
);

const OverviewBody = () => (
  <>
    <P>
      fd0.sh carries the user documentation. These pages cover the normal
      paths: install, unlock, store secrets, share scopes, sync, SSH, Talos,
      Kube, recovery, and basic self-hosting. The repository holds the
      technical specs.
    </P>

    <TileGrid>
      <Tile href="/docs/install" title="Start here" body="Install the client, create a vault, store the first secret, and sync." />
      <Tile href="/docs/concepts" title="Concepts" body="The small vocabulary used by every fd0 command." />
      <Tile href="/docs/cli" title="Daily use" body="Secrets, scopes, cards, membership, and local health checks." />
      <Tile href="/docs/ssh" title="SSH" body="Scope-shared SSH keys and host aliases through fd0-agent." />
      <Tile href="/docs/talos" title="Talos and Kube" body="Store, render, merge, and share Talos and Kubernetes configs." />
      <Tile href="/docs/sync" title="Sync" body="What sync sends, what it verifies, and how automatic refresh works." />
      <Tile href="/docs/server" title="Self-host" body="Run a primary, add a DR backup, and know where the full runbook lives." />
      <Tile href="/docs/troubleshooting" title="Troubleshooting" body="Locked vaults, stale SSH sockets, missing hosts, and config refresh." />
    </TileGrid>

    <H2>The normal path</H2>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh
$ fd0 init
$ fd0 unlock
$ fd0 scope create --label work
$ fd0 set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxx" --scope work
$ fd0 sync
$ fd0 get DEPLOY_KEY --scope work`}</Box>

    <H2>Where details live</H2>
    <P>
      Use these pages when you want to operate fd0. Use{" "}
      <Link href="/spec">/spec</Link> or the GitHub files when you need exact
      wire formats, storage invariants, threat IDs, or benchmark baselines.
    </P>
  </>
);

const ConceptsBody = () => {
  const rows = [
    {
      term: "identity",
      text: (
        <>
          Your long-term Ed25519 keypair. The public key appears in cards and
          event authorship. The private key stays encrypted locally and is held
          only by the agent after unlock.
        </>
      ),
    },
    {
      term: "vault",
      text: (
        <>
          The encrypted local file at <Code>~/.fd0/vault.enc</Code>. It stores
          your identity key, pinned cards, per-scope keys, and accepted chain
          tips.
        </>
      ),
    },
    {
      term: "agent",
      text: (
        <>
          The local daemon started by <Code>fd0 unlock</Code>. It signs,
          decrypts, and serves SSH agent requests without exposing private
          bytes to normal CLI commands.
        </>
      ),
    },
    {
      term: "scope",
      text: (
        <>
          A group of secrets with its own encryption key. Adding or removing a
          member rotates that key.
        </>
      ),
    },
    {
      term: "card",
      text: (
        <>
          A signed <Code>fd0://card/...</Code> identity record. Import a card
          only after checking its safety number out of band.
        </>
      ),
    },
    {
      term: "sync",
      text: (
        <>
          The event exchange with one configured primary. The server stores
          ciphertext and signed events; it does not receive plaintext secrets.
        </>
      ),
    },
    {
      term: "witness",
      text: (
        <>
          An independent observer for transparency-log heads. Witnesses help
          clients detect server equivocation.
        </>
      ),
    },
  ];

  return (
    <>
      <P>
        fd0 has a small model: local identity, encrypted vault, scope keys,
        signed events, one primary server, and optional witnesses. Once those
        terms are clear, the commands are direct.
      </P>

      {rows.map((row) => (
        <div
          class="grid sm:grid-cols-[9rem_1fr] gap-x-6 gap-y-2 py-4"
          style={`border-top:1px solid ${C.border};`}
        >
          <div class="text-sm font-medium" style={`color:${C.acc};font-family:${FONT_MONO};`}>
            {row.term}
          </div>
          <div class="text-[15px] leading-relaxed" style={`color:${C.dim};`}>
            {row.text}
          </div>
        </div>
      ))}
    </>
  );
};

const InstallBody = () => (
  <>
    <P>
      Install the fd0 client on each machine that should hold secrets. The
      hosted service at fd0.sh is the default backend; self-hosted clients use
      the same binary with a different <Code>[sync].server</Code>.
    </P>

    <H2>Install the client</H2>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh
$ fd0 version`}</Box>
    <P>
      The installer picks Linux or macOS, amd64 or arm64, verifies the release
      manifest with cosign when available, and writes <Code>fd0</Code> plus{" "}
      <Code>fd0-agent</Code> to <Code>~/.local/bin</Code>. Use{" "}
      <Code>--system</Code> to install into <Code>/usr/local/bin</Code>.
    </P>
    <H2>Update the client</H2>
    <Box>{`$ fd0 update --check
$ fd0 update`}</Box>
    <P>
      <Code>fd0 update</Code> updates <Code>fd0</Code> and{" "}
      <Code>fd0-agent</Code> from the latest client release. It verifies the
      archive checksum and uses cosign when available. If the agent is running,
      restart it after the update with <Code>fd0 agent restart</Code>.
    </P>
    <Note>
      Windows is not supported yet. The binaries cross-compile, but the agent
      socket path has not been validated on Windows.
    </Note>

    <H2>Create a vault</H2>
    <Box>{`$ fd0 init
$ fd0 unlock
$ fd0 scope create --label work
$ fd0 set API_TOKEN "secret-value" --scope work
$ fd0 sync`}</Box>
    <P>
      <Code>fd0 init</Code> creates your identity and seals the vault under a
      passphrase. <Code>fd0 unlock</Code> starts the agent.{" "}
      <Code>fd0 sync</Code> publishes encrypted events to the configured
      primary and pulls changes from other devices.
    </P>

    <H2>Configure another backend</H2>
    <Box>{`$ mkdir -p ~/.fd0
$ cat >~/.fd0/config.toml <<'EOF'
[sync]
server = "https://fd0.example.com"
interval = "1h"
on_unlock = true
EOF`}</Box>

  </>
);

const CliBody = () => (
  <>
    <P>
      The CLI works mostly from local state. <Code>fd0 sync</Code> is the
      explicit network command; the agent can also sync after unlock when{" "}
      <Code>on_unlock = true</Code>.
    </P>

    <H2>Secrets</H2>
    <Cmd signature="fd0 set <NAME> <value> [--scope <scope>]" body="Store a string secret in a scope. Without --scope, fd0 uses the only live scope, asks interactively, or requires --scope in non-interactive use." />
    <Cmd signature="fd0 get [<NAME>] [--scope <scope>]" body="Print a secret. Without a name, fd0 opens the interactive picker." />
    <Cmd signature="fd0 copy <NAME> [--clear-after=30s]" body="Copy a secret to the clipboard and clear it after the timeout." />
    <Cmd signature="fd0 ls" body="List visible secret names across scopes. Values stay encrypted until you request one." />
    <Cmd signature="fd0 rm <NAME> [--scope <scope>]" body="Write a tombstone for a secret. The old event remains audit history." />

    <H2>Scopes and sharing</H2>
    <P>
      A scope is the sharing boundary. Add a member to share every current
      secret in the scope. Remove a member to rotate the scope key for future
      writes.
    </P>
    <Box>{`# Alice exports her card.
$ fd0 card export

# Bob imports Alice, Alice imports Bob, then Alice grants access.
$ fd0 card import "fd0://card/..." --label bob
$ fd0 scope add-member bob --scope work
$ fd0 sync

# Bob discovers the scope on his next sync.
$ fd0 sync
$ fd0 ls`}</Box>
    <Cmd signature="fd0 card export" body="Print your signed card and safety number. Share the card over any channel; verify the safety number over a trusted channel." />
    <Cmd signature="fd0 card import <fd0://card/...> --label <name>" body="Pin another identity under a local label." />
    <Cmd signature="fd0 scope add-member <label> --scope <scope>" body="Grant a pinned card access to the scope." />
    <Cmd signature="fd0 scope remove-member <label> --scope <scope>" body="Remove access and rotate the scope key." />

    <H2>Local health</H2>
    <Cmd signature="fd0 status" body="Show whether the agent is running and whether the vault is unlocked." />
    <Cmd signature="fd0 doctor" body="Replay local chains, check vault tips, auth wraps, scope keys, orphan chain files, and SSH socket health." />
    <Cmd signature="fd0 lock" body="Lock the vault in the running agent and zeroize in-memory keys." />
    <Cmd signature="fd0 agent status" body="Show fd0-agent process, vault, agent socket, and SSH socket state." />
    <Cmd signature="fd0 agent restart" body="Replace fd0-agent with the current binary and repair stale agent sockets." />
    <Cmd signature="fd0 agent stop" body="Stop fd0-agent and clean stale sockets when safe." />
    <Note>
      If a command needs an unlocked vault in an interactive terminal, fd0
      prompts for the passphrase instead of failing immediately.
    </Note>
  </>
);

const SshBody = () => (
  <>
    <P>
      fd0 stores SSH keys and host entries as scope-shared secrets. The agent
      serves keys over the standard ssh-agent protocol. Host entries render to{" "}
      <Code>~/.ssh/fd0.conf</Code>.
    </P>

    <H2>Enable native ssh</H2>
    <Box>{`$ fd0 ssh enable
$ export SSH_AUTH_SOCK="$(fd0 ssh sock)"`}</Box>
    <P>
      <Code>fd0 ssh enable</Code> writes the fd0 config file and adds an
      Include line to <Code>~/.ssh/config</Code> with confirmation. After that,
      normal <Code>ssh</Code>, <Code>git</Code>, <Code>scp</Code>, and
      compatible tools can use fd0 keys.
    </P>

    <H2>Add a key and host</H2>
    <Box>{`$ fd0 key add laptop --scope work
$ fd0 ssh add prod-db app@db.internal --key laptop --scope work
$ fd0 sync

$ fd0 ssh prod-db
$ ssh prod-db`}</Box>
    <Cmd signature="fd0 key add <name> [--import <path>]" body="Generate an ed25519 key, or import an existing OpenSSH key. Private bytes stay encrypted in fd0." />
    <Cmd signature="fd0 ssh add <alias> [user@]host[:port] --key <name>" body="Create a structured host entry and re-render ~/.ssh/fd0.conf." />
    <Cmd signature="fd0 ssh ls" body="List host aliases." />
    <Cmd signature="fd0 ssh show <alias>" body="Show the host record and rendered ssh_config block." />
    <Cmd signature="fd0 ssh rm <alias>" body="Remove the host entry and re-render the config." />

    <H2>Team sharing</H2>
    <P>
      Keys and hosts belong to scopes. Add a teammate to the scope and their
      next <Code>fd0 sync</Code> pulls the same key and host inventory. Native
      <Code>ssh</Code> works after that teammate enables fd0 SSH once on their
      device so their SSH config includes fd0 and <Code>SSH_AUTH_SOCK</Code>{" "}
      points at the fd0 agent. Remove them and the scope key rotates for future
      changes.
    </P>

    <H2>What fd0 does not do</H2>
    <P>
      fd0 does not edit remote <Code>sshd_config</Code>, deploy
      <Code>authorized_keys</Code>, or run <Code>ssh-copy-id</Code>. Use your
      normal provisioning tool for remote machines.
    </P>
  </>
);

const TalosKubeBody = () => (
  <>
    <P>
      fd0 stores Talos contexts and Kubernetes configs as typed secrets. It
      renders deterministic config files and can merge them into your normal
      tool config after sync.
    </P>

    <H2>Talos</H2>
    <Box>{`$ fd0 talos add --from-config ~/.talos/config \\
    --import-context prod --scope work
$ fd0 talos enable --merge
$ fd0 sync

$ talosctl --talosconfig ~/.talos/config.fd0 config contexts`}</Box>
    <P>
      Enabled Talos refresh means every <Code>fd0 sync</Code> re-renders{" "}
      <Code>~/.talos/config.fd0</Code>. With <Code>--merge</Code>, fd0 also
      folds those contexts into <Code>~/.talos/config</Code>.
    </P>

    <H2>Kubernetes</H2>
    <Box>{`$ fd0 kube add prod --from-config ~/.kube/config \\
    --import-context admin@prod --scope work
$ fd0 kube enable --merge
$ fd0 sync

$ kubectl --kubeconfig ~/.kube/config.fd0 get nodes`}</Box>
    <P>
      Enabled Kube refresh means every <Code>fd0 sync</Code> re-renders{" "}
      <Code>~/.kube/config.fd0</Code>. With <Code>--merge</Code>, fd0 also
      folds those entries into <Code>~/.kube/config</Code>.
    </P>

    <H2>Current context</H2>
    <P>
      When fd0 renders exactly one Talos or Kube context, it marks that context
      current. When it merges into an existing user config, it preserves your
      existing current context unless you change it yourself.
    </P>

    <H2>Day-0 Talos credentials</H2>
    <P>
      <Code>fd0 talos new</Code> can generate cluster PKI and store the
      disaster-recovery <Code>secrets.yaml</Code> bundle. That path shells out
      to <Code>talosctl</Code>. Normal add/list/render/merge paths are pure Go.
    </P>
  </>
);

const SyncBody = () => (
  <>
    <P>
      Sync moves signed encrypted events between your local files and one
      primary server. It also refreshes enabled local projections: SSH config,
      Talos config, and Kube config.
    </P>

    <H2>What sync does</H2>
    <Box>{`$ fd0 sync
-> push local events
-> pull remote events
-> verify signatures, hash links, STHs, and witness policy
-> discover new scopes
-> refresh enabled SSH/Talos/Kube projections`}</Box>

    <H2>One primary</H2>
    <P>
      A client reads and writes exactly one primary. That keeps each scope in
      one ordered history. Redundancy is handled by server-side disaster
      recovery, not by writing to multiple primaries.
    </P>

    <H2>Automatic sync</H2>
    <Box>{`[sync]
server = "https://api.fd0.sh"
interval = "1h"
on_unlock = true`}</Box>
    <P>
      <Code>interval</Code> enables background sync from the agent.{" "}
      <Code>on_unlock</Code> runs sync after a successful unlock.
    </P>

    <H2>Scope discovery</H2>
    <P>
      When someone adds you to a scope, your next sync discovers the scope,
      pulls its full event chain, decrypts your key delivery, and stores the
      scope locally.
    </P>
  </>
);

const ServerBody = () => (
  <>
    <P>
      You can use the hosted primary at fd0.sh or run your own primary. The
      client command surface is the same.
    </P>

    <H2>Hosted</H2>
    <Box>{`[sync]
server = "https://api.fd0.sh"`}</Box>
    <P>
      fd0.sh stores ciphertext and signed events only. The operator cannot
      decrypt user secrets.
    </P>

    <H2>Self-host</H2>
    <Box>{`$ mkdir fd0-server
$ cd fd0-server
$ curl -fsSLO https://fd0.sh/files/compose.yml
$ umask 077
$ printf 'METRICS_TOKEN=%s\\n' "$(openssl rand -hex 32)" > .env
$ case "$(uname -m)" in arm64|aarch64) printf 'FD0_SERVER_IMAGE=%s\\n' 'ghcr.io/valentinkolb/fd0-server:latest-arm64' >> .env ;; esac
$ docker compose up -d`}</Box>
    <P>
      This starts one <Code>fd0-server</Code> on localhost port{" "}
      <Code>4048</Code>.
      Put your own TLS terminator in front before pointing real clients at it.
      Use{" "}
      <Link href="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/HOSTING.md">
        the production hosting runbook
      </Link>{" "}
      for backup, TLS, metrics, witness, and key-rotation details.
    </P>

    <H2>Disaster recovery</H2>
    <P>
      A standby can mirror the primary with <Code>FD0_REPLICATE_FROM</Code>.
      The standby is a recovery source, not a second writable primary.
    </P>
    <Box>{`# standby
FD0_REPLICATE_FROM=https://fd0.example.com
FD0_REPLICATE_INTERVAL=30s

# primary
FD0_PEERS=https://fd0-backup.example.com`}</Box>
    <Note>
      The quickstart writes the arm64 image override when it detects an ARM
      host. For production, pin a released image tag in <Code>.env</Code>.
    </Note>
  </>
);

const YubikeyBody = () => (
  <>
    <P>
      fd0 can use a YubiKey PIV slot as an unlock method. The slot private key
      stays on the device. Build fd0 with <Code>-tags=yubikey</Code>.
    </P>

    <H2>Enroll</H2>
    <Box>{`$ fd0 auth add --yubikey
$ fd0 lock
$ fd0 unlock --method=yubikey`}</Box>

    <H2>Multiple readers</H2>
    <P>
      If more than one compatible reader is present, set{" "}
      <Code>FD0_YUBIKEY_CARD=&lt;substring&gt;</Code>. Without it, fd0 refuses
      to choose a card silently.
    </P>
  </>
);

const RecoveryBody = () => (
  <>
    <P>
      Recovery exports your identity key into a separate encrypted file. Keep
      the file and recovery passphrase offline.
    </P>

    <H2>Export</H2>
    <Box>{`$ fd0 recovery export ~/fd0-recovery.cbor`}</Box>

    <H2>Restore</H2>
    <Box>{`$ fd0 recovery import ~/fd0-recovery.cbor
$ fd0 unlock
$ fd0 sync`}</Box>
    <P>
      After import, sync discovers every scope where the restored identity is a
      member.
    </P>
  </>
);

const TroubleshootingBody = () => (
  <>
    <P>
      Start with <Code>fd0 doctor</Code>. It checks local chain state, vault
      bindings, auth wraps, orphan chain files, and the SSH agent socket.
    </P>

    <H2>Vault is locked</H2>
    <P>
      Interactive commands prompt for the passphrase when the agent is locked.
      Non-interactive commands fail instead of reading a secret from an unsafe
      input stream.
    </P>
    <Box>{`$ fd0 unlock
$ fd0 status`}</Box>

    <H2>ssh says unknown host</H2>
    <P>
      Run sync. If SSH integration is enabled, sync refreshes{" "}
      <Code>~/.ssh/fd0.conf</Code>. If this is the first setup on the machine,
      check that <Code>~/.ssh/config</Code> includes the fd0 config.
    </P>
    <Box>{`$ fd0 sync
$ ssh -G prod-db | grep -E 'hostname|identityagent|identityfile'`}</Box>
    <P>
      Run <Code>fd0 ssh enable</Code> once if the Include line is missing.
      You should not need to repeat it after normal fd0 SSH changes.
    </P>

    <H2>SSH agent socket is stale</H2>
    <P>
      If <Code>ssh-add -L</Code> returns connection refused, restart{" "}
      <Code>fd0-agent</Code>. <Code>fd0 doctor</Code> reports this state.
    </P>
    <Box>{`$ fd0 agent restart
$ SSH_AUTH_SOCK="$(fd0 ssh sock)" ssh-add -L`}</Box>

    <H2>kubectl or talosctl has no current context</H2>
    <P>
      Re-render the fd0 config. A single rendered context becomes current in
      the <Code>*.fd0</Code> file. Merges preserve your existing primary config
      current context.
    </P>
    <Box>{`$ fd0 kube sync --merge
$ fd0 talos sync --merge`}</Box>

    <H2>A new member cannot see a scope</H2>
    <P>
      The inviter must sync after adding the member. The new member then runs
      sync to discover and replay the scope.
    </P>
    <Box>{`# inviter
$ fd0 scope add-member bob --scope work
$ fd0 sync

# new member
$ fd0 sync`}</Box>
  </>
);

export const DocsOverview = ssr(async (c) => {
  setPageSeo(c, "docs");
  return () => (
    <DocsLayout current="overview" title="Documentation" kicker="Use fd0">
      <OverviewBody />
    </DocsLayout>
  );
});

export const DocsConcepts = ssr(async (c) => {
  setPageSeo(c, "docsConcepts");
  return () => (
    <DocsLayout current="concepts" title="Concepts" kicker="Mental model">
      <ConceptsBody />
    </DocsLayout>
  );
});

export const DocsInstall = ssr(async (c) => {
  setPageSeo(c, "docsInstall");
  return () => (
    <DocsLayout current="install" title="Install and start" kicker="First run">
      <InstallBody />
    </DocsLayout>
  );
});

export const DocsCli = ssr(async (c) => {
  setPageSeo(c, "docsCli");
  return () => (
    <DocsLayout current="cli" title="Daily use" kicker="CLI">
      <CliBody />
    </DocsLayout>
  );
});

export const DocsSsh = ssr(async (c) => {
  setPageSeo(c, "docsSsh");
  return () => (
    <DocsLayout current="ssh" title="SSH keys and hosts" kicker="Integration">
      <SshBody />
    </DocsLayout>
  );
});

export const DocsTalos = ssr(async (c) => {
  setPageSeo(c, "docsTalos");
  return () => (
    <DocsLayout current="talos" title="Talos and Kube" kicker="Integration">
      <TalosKubeBody />
    </DocsLayout>
  );
});

export const DocsSync = ssr(async (c) => {
  setPageSeo(c, "docsSync");
  return () => (
    <DocsLayout current="sync" title="Sync" kicker="State exchange">
      <SyncBody />
    </DocsLayout>
  );
});

export const DocsServer = ssr(async (c) => {
  setPageSeo(c, "docsServer");
  return () => (
    <DocsLayout current="server" title="Hosted or self-hosted" kicker="Backend">
      <ServerBody />
    </DocsLayout>
  );
});

export const DocsYubikey = ssr(async (c) => {
  setPageSeo(c, "docsYubikey");
  return () => (
    <DocsLayout current="yubikey" title="YubiKey unlock" kicker="Hardware">
      <YubikeyBody />
    </DocsLayout>
  );
});

export const DocsRecovery = ssr(async (c) => {
  setPageSeo(c, "docsRecovery");
  return () => (
    <DocsLayout current="recovery" title="Recovery" kicker="Backup identity">
      <RecoveryBody />
    </DocsLayout>
  );
});

export const DocsTroubleshooting = ssr(async (c) => {
  setPageSeo(c, "docsTroubleshooting");
  return () => (
    <DocsLayout current="troubleshooting" title="Troubleshooting" kicker="Fix common states">
      <TroubleshootingBody />
    </DocsLayout>
  );
});

export default DocsOverview;
