/**
 * /docs/* — Operator reference, split per topic with a Docusaurus-
 * style sidebar.
 *
 * Each topic is its own SSR-rendered page (no client routing) so
 * deep-links work, browser back/forward works, and there is zero JS
 * cost for navigation. The DocsLayout component owns the sidebar +
 * prev/next pager; this file owns the per-topic content.
 */

import { ssr } from "../../config";
import { Shell } from "../lib/shell";
import { C, FONT_MONO, DocsLayout } from "../lib/chrome";

/* ─── shared content primitives ─────────────────────────────────── */

const H2 = (p: { children: any; id?: string }) => (
  <h2
    id={p.id}
    class="text-xl md:text-[1.45rem] font-medium tracking-tight mt-12 mb-4"
  >
    {p.children}
  </h2>
);

const H3 = (p: { children: any; id?: string }) => (
  <h3
    id={p.id}
    class="text-[15px] tracking-widest uppercase mt-8 mb-3 font-medium"
    style={`color:${C.fg};`}
  >
    {p.children}
  </h3>
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
    class="p-4 text-[13px] leading-[1.6] mb-5"
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
        class="p-3 text-[12.5px] leading-[1.55]"
        style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
      >
        <Shell>{p.example}</Shell>
      </div>
    ) : null}
  </div>
);

/* ─── 1 · overview ─────────────────────────────────────────────── */

const OverviewBody = () => (
  <>
    <P>
      Operator reference. Commands, config, sync, hardware unlock,
      recovery, SSH. Identical whether you self-host{" "}
      <Code>fd0-server</Code> or point the client at <Code>fd0.sh</Code>.
      The <a href="/spec" style={`color:${C.acc};`}>specification</a>{" "}
      covers the protocol underneath.
    </P>

    <div class="grid sm:grid-cols-2 gap-4 mt-8">
      {[
        { href: "/docs/concepts", t: "Concepts", d: "Eight terms used everywhere below." },
        { href: "/docs/cli", t: "CLI reference", d: "fd0 init, set, get, ls, sync, …" },
        { href: "/docs/ssh", t: "SSH", d: "Keys + hosts as scope-shared secrets." },
        { href: "/docs/sync", t: "Sync", d: "Multi-device, multi-server, replica failover." },
        { href: "/docs/server", t: "Self-host server", d: "docker-compose, replicas, witness." },
        { href: "/docs/yubikey", t: "YubiKey unlock", d: "On-card X25519, PIV slot 9d." },
        { href: "/docs/recovery", t: "Recovery", d: "Restore identity on a fresh device." },
      ].map((c) => (
        <a
          href={c.href}
          class="block p-4 transition-colors"
          style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};`}
        >
          <div class="font-medium mb-1" style={`color:${C.acc};`}>{c.t}</div>
          <div class="text-sm" style={`color:${C.dim};`}>{c.d}</div>
        </a>
      ))}
    </div>

    <H2>One install. Two flavours.</H2>
    <P>
      The CLI is the same binary either way. You pick a backend by
      pointing the client at the URLs in <Code>~/.fd0/config.toml</Code>{" "}
      — defaults are the hosted <Code>fd0.sh</Code> replicas.
    </P>
    <Box>{`# hosted (default; no config needed)
$ fd0 init && fd0 unlock && fd0 sync

# self-hosted (point at your server)
$ cat >~/.fd0/config.toml <<EOF
[sync]
servers = ["https://fd0.example.com"]
EOF`}</Box>
  </>
);

/* ─── 2 · concepts ─────────────────────────────────────────────── */

const ConceptsBody = () => (
  <>
    <P>
      Eight terms used in every section below. Read once, then skim
      this page when a term in a later page feels unfamiliar.
    </P>

    {[
      { t: "identity", d: <>Ed25519 keypair generated locally. Anchors the account across devices. Never leaves your machine unencrypted.</> },
      { t: "vault", d: <>Local encrypted file at <Code>~/.fd0/vault.enc</Code>. Holds super_priv, per-scope keys, chain tips. Sealed under every active auth method.</> },
      { t: "agent", d: <>Local daemon. Holds super_priv mlocked in memory after unlock; signs and decrypts on demand for the CLI.</> },
      { t: "scope", d: <>Group of secrets with its own encryption key (OEK). Adding or removing a member rotates the OEK atomically.</> },
      { t: "secret", d: <>Typed name → value pair inside a scope. AEAD-sealed with the current OEK. Holds passwords, SSH keys, hosts, anything that fits the protocol.</> },
      { t: "card", d: <>Shareable identity (<Code>fd0://card/…</Code>). Signed once by you, pinned by a safety number out of band.</> },
      { t: "member", d: <>A card pinned in your vault and added to one or more scopes.</> },
      { t: "sync", d: <>Event exchange with the server. Idempotent. Concurrent writes from multiple devices auto-retry against the chain tip.</> },
    ].map((c) => (
      <div
        class="grid sm:grid-cols-[8rem_1fr] gap-x-6 gap-y-2 py-4"
        style={`border-top:1px solid ${C.border};`}
      >
        <div class="text-sm font-medium" style={`color:${C.acc};font-family:${FONT_MONO};`}>
          {c.t}
        </div>
        <div class="text-[15px] leading-relaxed" style={`color:${C.dim};`}>
          {c.d}
        </div>
      </div>
    ))}
  </>
);

/* ─── 3 · CLI ──────────────────────────────────────────────────── */

const CliBody = () => (
  <>
    <P>
      Every command operates on local files except <Code>fd0 sync</Code>,
      which talks to the configured server.
    </P>

    <H3>Identity &amp; vault</H3>
    <Cmd signature="fd0 init" body="Generate a fresh identity and seal the vault under a passphrase. Refuses to overwrite an existing vault." example={`$ fd0 init
Choose a passphrase: …
✓ identity created (upIamMlsgn…)
✓ vault written to ~/.fd0/vault.enc`} />
    <Cmd signature="fd0 unlock [--method=passphrase|yubikey]" body="Start the agent, decrypt the vault, hold super_priv mlocked. With multiple methods, picks deterministically by id; --method forces a specific one." />
    <Cmd signature="fd0 lock" body="Zeroize the agent's in-memory keys and exit. Vault on disk stays sealed." />

    <H3>Scopes &amp; secrets</H3>
    <Cmd signature="fd0 scope create --label <name>" body="Create an empty scope with a fresh OEK. The scope is yours alone until you add members." />
    <Cmd signature="fd0 set <NAME> <value> [--scope <s>]" body="Store a string secret. Without --scope, uses your default." />
    <Cmd signature="fd0 get [<NAME>] [--scope <s>]" body="Retrieve a secret. Without a name, opens fuzzy search across all scopes." />
    <Cmd signature="fd0 copy <NAME> [--scope <s>] [--clear-after=30s]" body="Copy to clipboard with a configurable auto-clear timeout." />
    <Cmd signature="fd0 ls [--scope <s>]" body="List secrets across all scopes (or one). Names only — values stay in the vault." />
    <Cmd signature="fd0 rm <NAME> [--scope <s>]" body="Remove a secret. Writes a tombstone event; the bytes vanish on the next compaction." />

    <H3>Cards &amp; membership</H3>
    <Cmd signature="fd0 card export" body="Print your shareable card (fd0://card/…) to stdout and the safety number to stderr. Show the safety number out-of-band when a teammate pins it." />
    <Cmd signature="fd0 card import <fd0://card/…> --label <name>" body="Pin a teammate's card. Pass --yes to skip the safety-number confirmation." />
    <Cmd signature="fd0 scope add-member <label> --scope <s>" body="Wrap the scope OEK to the named card and append a member.change event." />
    <Cmd signature="fd0 scope remove-member <label> --scope <s>" body="Rotate the scope OEK so the named card can no longer decrypt subsequent writes." />

    <H3>Auth methods</H3>
    <Cmd signature="fd0 auth add --yubikey [--touch=always|cached|never]" body={<>Enroll a YubiKey (slot 9d, X25519) as an unlock method. See <a href="/docs/yubikey" style={`color:${C.acc};`}>YubiKey unlock</a> for details. Build the client with <Code>-tags=yubikey</Code>.</>} />
    <Cmd signature="fd0 auth list" body="List enrolled methods with their ids and policies." />
    <Cmd signature="fd0 auth remove <method_id>" body="Remove an auth method. Refuses if it's the only one — removing the last method would seal the vault permanently." />

    <H3>Sync &amp; ops</H3>
    <Cmd signature="fd0 sync" body={<>Push local events to the configured servers, pull what's new, verify the returned STH against each pinned server pubkey + witness cosign. See <a href="/docs/sync" style={`color:${C.acc};`}>Sync</a>.</>} />
    <Cmd signature="fd0 doctor" body="Audit local state — vault integrity, chain tips, OEK consistency, no orphan files. Exits non-zero on any issue." />
    <Cmd signature="fd0 recovery export <file>" body={<>Encrypted backup of super_priv under a separate recovery passphrase. See <a href="/docs/recovery" style={`color:${C.acc};`}>Recovery</a>.</>} />

    <H3>SSH</H3>
    <P>
      Top-level <Code>fd0 key</Code> and <Code>fd0 ssh</Code> commands —
      see the <a href="/docs/ssh" style={`color:${C.acc};`}>SSH page</a> for
      the full reference.
    </P>
  </>
);

/* ─── 4 · SSH (NEW) ────────────────────────────────────────────── */

const SshBody = () => (
  <>
    <P>
      SSH in fd0 is two things: <Code>fd0 key</Code> manages SSH private
      keys as typed secrets, and <Code>fd0 ssh</Code> manages structured
      host entries that render to a regular{" "}
      <Code>~/.ssh/fd0.conf</Code> you Include from your own config.
      Keys are served over the standard ssh-agent protocol by{" "}
      <Code>fd0-agent</Code>, so <Code>ssh</Code>, <Code>git</Code>,{" "}
      <Code>scp</Code>, <Code>rsync</Code>, VS Code Remote — anything
      that respects <Code>SSH_AUTH_SOCK</Code> — just work.
    </P>
    <P>
      Both keys and hosts are scope-shared. Add a teammate to a scope
      and their next <Code>fd0 sync</Code> gives them the keys + hosts.
      Remove them and the per-scope OEK rotates atomically.
    </P>

    <H2>Enable once</H2>
    <P>
      The agent always opens its SSH socket on unlock. To make{" "}
      <Code>ssh</Code> pick up the rendered hosts, add an{" "}
      <Code>Include</Code> line to your <Code>~/.ssh/config</Code>:
    </P>
    <Box>{`$ fd0 ssh enable
✓ wrote ~/.ssh/fd0.conf (stub)
? add 'Include ~/.ssh/fd0.conf' to ~/.ssh/config? [Y/n] y
✓ Include line added (with marker, so fd0 ssh disable can reverse it)

$ export SSH_AUTH_SOCK="$(fd0 ssh sock)"   # add to your shell rc`}</Box>
    <Note>
      <strong>Won't touch your ssh_config without permission.</strong>{" "}
      <Code>fd0 ssh enable</Code> always asks; in non-interactive mode it
      prints the line for you to paste manually. Every host mutation
      re-renders <Code>fd0.conf</Code> and warns if the Include line is
      missing.
    </Note>

    <H2>Keys</H2>
    <P>
      Generated inside the agent with <Code>crypto/ed25519</Code> + a
      fresh OS-RNG read. The private bytes never touch disk in
      plaintext, and they never leave the agent over the wire — only
      Sign and List are served over the ssh-agent socket (Add /
      Remove / Lock / Unlock are explicitly disabled).
    </P>

    <Cmd signature="fd0 key add <name> [--import <path>]" body={<>Generate a new ed25519 key, or import an existing OpenSSH PEM. Imports accept ed25519 / RSA (≥ 3072 bit) / ECDSA-p256; DSA and weak-RSA are refused. Prints the <Code>authorized_keys</Code> line on stdout.</>} example={`$ fd0 key add laptop
✓ generated ed25519 (scope: personal)

ssh-ed25519 AAAAC3NzaC1lZD… laptop@fd0`} />
    <Cmd signature="fd0 key ls [--scope <s>]" body="List keys across all scopes (or one). Names + types only; private bytes stay in the vault." />
    <Cmd signature="fd0 key show <name> [--pub]" body={<>Print metadata for a key. <Code>--pub</Code> prints the bare <Code>authorized_keys</Code> line — pipe it into a server, copy it into a UI, or just inspect.</>} />
    <Cmd signature="fd0 key rm <name>" body="Tombstone the key. Hosts that referenced it will warn on next render but stay valid." />
    <Cmd signature="fd0 key move <name> --to <scope>" body="Move a key between scopes you own. Hosts referencing it follow." />

    <H2>Hosts</H2>
    <P>
      A host is a structured record: alias, hostname, user, port, the
      key to use, optional jump host, tags, description, and any
      verbatim ssh_config options. It renders into{" "}
      <Code>~/.ssh/fd0.conf</Code> with{" "}
      <Code>IdentityAgent {`{fd0-sock}`}</Code> +{" "}
      <Code>IdentitiesOnly yes</Code> baked in.
    </P>

    <Cmd signature="fd0 ssh add <alias> [user@]host[:port] [...flags]" body={<><Code>--key &lt;name&gt;</Code> picks the key (must exist). <Code>--with-key</Code> generates a fresh key named after the alias in the same call. <Code>--jump &lt;alias&gt;</Code> sets ProxyJump. <Code>--tag</Code> repeatable. <Code>--description</Code> single-line note. <Code>--opt KEY=VALUE</Code> repeatable verbatim option.</>} example={`$ fd0 ssh add prod-db app@db.internal \\
    --jump bastion --key deploy --tag prod --tag db \\
    --description "Main prod DB" --scope work
✓ host added (scope: work)
✓ re-rendered ~/.ssh/fd0.conf

$ fd0 ssh add staging-web app@stage.internal --with-key \\
    --scope work --tag staging
✓ generated key "staging-web"
✓ host added (scope: work)`} />
    <Cmd signature="fd0 ssh ls [--tag <t>...] [--no-tag <t>...]" body={<>List hosts. Multiple <Code>--tag</Code> flags AND together; <Code>--no-tag</Code> excludes. Use <Code>--scope</Code> to limit to one scope.</>} />
    <Cmd signature="fd0 ssh show <alias>" body="Pretty-print the host record plus the rendered ssh_config block." />
    <Cmd signature="fd0 ssh rm <alias>" body="Tombstone the host and re-render fd0.conf." />
    <Cmd signature="fd0 ssh tag <alias> --add <t> | --remove <t>" body="Repeatable add/remove. Tags are shared with the scope; never per-user." />
    <Cmd signature="fd0 ssh move <alias> --to <scope>" body="Move a host between scopes you own. Its key reference resolves in the new scope; warns if it can't." />

    <H2>Connect — the picker</H2>
    <P>
      <Code>fd0 ssh</Code> with no name opens an interactive picker
      over all hosts. With a name it connects directly; with a unique
      prefix it autocompletes. With multiple matches it opens the
      picker pre-filtered. Anything after the alias is passed verbatim
      to <Code>ssh</Code>.
    </P>
    <Box>{`$ fd0 ssh              # picker
$ fd0 ssh prod-db      # direct connect
$ fd0 ssh prod         # prefix → picker if ambiguous, direct if unique
$ fd0 ssh prod-db "uname -a"   # run a one-shot command

$ git push origin main        # picks up fd0's ssh-agent for git@…
$ scp dump.sql prod-db:/tmp/  # standard scp via the rendered alias`}</Box>

    <H2>Team sharing</H2>
    <P>
      Keys and hosts both belong to a scope. Onboarding a teammate is
      the same op as sharing a password — they pin your card, you add
      them to the scope, their next sync gives them everything.
    </P>
    <Box>{`$ fd0 scope add-member bob --scope work
$ fd0 sync                       # publishes the member.change
# … bob's next sync …
$ fd0 sync                       # bob now has the deploy key + prod-db host
$ ssh prod-db                    # works for bob too`}</Box>
    <Note>
      <strong>Removing a teammate rotates the scope OEK.</strong> The
      symbolic key bytes don't change, but everything sealed after the
      rotation is unreadable to the removed member. To force a real
      key rotation, <Code>fd0 key rm laptop &amp;&amp; fd0 key add laptop</Code>{" "}
      generates fresh bytes.
    </Note>

    <H2>What fd0 won't do</H2>
    <P>
      Deliberately not in scope: <Code>ssh-copy-id</Code> automation,
      remote <Code>sshd_config</Code> edits, server-side bootstrap.
      Deploy your <Code>authorized_keys</Code> with whatever you
      normally use (cloud-init, Ansible, Tailscale, NixOS, …) — pipe
      it from <Code>fd0 key show laptop --pub</Code>.
    </P>
  </>
);

/* ─── 5 · sync ─────────────────────────────────────────────────── */

const SyncBody = () => (
  <>
    <P>
      Sync is the only command that talks to the server. Everything
      else is local. <Code>fd0 sync</Code> pushes new events to every
      configured server, pulls what's new, and verifies the returned
      STH against the pinned server pubkey + witness cosign.
    </P>

    <H2>Manual vs automatic</H2>
    <div class="grid md:grid-cols-2 gap-5 mt-2">
      <div>
        <div class="text-xs mb-2" style={`color:${C.dim};`}>Manual</div>
        <Box>{`$ fd0 sync
→ POST /v1/sync  scope=work  push=3
← 200 OK  pull=0  sth=cosigned@43
✓ chain advanced (seq=7)`}</Box>
      </div>
      <div>
        <div class="text-xs mb-2" style={`color:${C.dim};`}>Automatic — ~/.fd0/config.toml</div>
        <Box>{`[sync]
servers   = ["https://api.fd0.sh", "https://api2.fd0.sh"]
interval  = "1h"
on_unlock = true`}</Box>
      </div>
    </div>

    <H2>Multi-server</H2>
    <P>
      A client can target multiple servers — fd0 pushes events to each
      and reads from whichever responds first. The transparency log
      is per-server but their chain tips converge because all clients
      multi-push. Replicas cross-pin via peer discovery.
    </P>
    <Note>
      <strong>Concurrent-write safety.</strong> The server returns{" "}
      <Code>409 divergence</Code> for stale pushes; the client
      refreshes, re-signs, and retries up to three times. Linear log
      with optimistic concurrency — not CRDT commutativity.
    </Note>
  </>
);

/* ─── 6 · server ───────────────────────────────────────────────── */

const ServerBody = () => (
  <>
    <P>
      Self-host with Docker. The recommended path is the
      docker-compose blocks in <Code>deploy/</Code>. To use the hosted
      instance instead, skip this section — the client defaults to{" "}
      <Code>api.fd0.sh</Code> + <Code>api2.fd0.sh</Code>.
    </P>

    <H2>Compose blocks</H2>
    <div class="grid md:grid-cols-2 gap-5">
      <div>
        <div class="text-xs mb-2" style={`color:${C.dim};`}>
          deploy/server/compose.yml — env
        </div>
        <Box>{`FD0_BIND=:8080
FD0_DB=/data/fd0.db
FD0_BASE_URL=https://fd0.example.com
FD0_LABEL=primary
FD0_PEERS=https://fd0-2.example.com`}</Box>
      </div>
      <div>
        <div class="text-xs mb-2" style={`color:${C.dim};`}>
          deploy/witness/compose.yml — env
        </div>
        <Box>{`FD0_BIND=:8081
FD0_WATCHED=https://fd0.example.com
FD0_DB=/data/witness.db`}</Box>
      </div>
    </div>

    <H2>Endpoints exposed</H2>
    <P>
      Server: <Code>/v1/sync</Code>, <Code>/v1/info</Code>,{" "}
      <Code>/health</Code>, <Code>/version</Code>,{" "}
      <Code>/metrics</Code> (token-auth). Witness adds{" "}
      <Code>/v1/observed</Code> + the same ops endpoints. Reverse-
      proxy with whatever you already operate.
    </P>
    <Note>
      For the full hosting walkthrough (compose, TLS, peer discovery,
      Prometheus, alert rules) see{" "}
      <a href="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/HOSTING.md" style={`color:${C.acc};`}>
        docs/HOSTING.md
      </a>{" "}
      in the repo.
    </Note>
  </>
);

/* ─── 7 · yubikey ──────────────────────────────────────────────── */

const YubikeyBody = () => (
  <>
    <P>
      Hardware-backed unlock via PIV slot 9d. On-card X25519 ECDH; the
      slot private key never leaves the device. Requires firmware 5.7
      or later. Build the client with <Code>-tags=yubikey</Code>.
    </P>

    <H2>Enroll + use</H2>
    <Box>{`$ fd0 auth add --yubikey --touch=never
✓ YubiKey detected: Yubico YubiKey OTP+FIDO+CCID
Set a PIN? [y/N]: y
Enter PIN (6-8 ASCII): ……
✓ added YubiKey auth method am_01KR… (policy: PIN+touch(none))

$ fd0 lock
$ fd0 unlock --method=yubikey
YubiKey PIN (empty for touch-only): ……
Touch your YubiKey if it blinks…
✓ vault unlocked (yubikey)`}</Box>

    <H2>Multiple readers</H2>
    <P>
      On hosts with more than one reader, set{" "}
      <Code>FD0_YUBIKEY_CARD=&lt;substring&gt;</Code> to pick by name.
      Without the env var, fd0 refuses to act when more than one
      YubiKey-shaped reader is present — to avoid acting on the wrong
      card.
    </P>
  </>
);

/* ─── 8 · recovery ─────────────────────────────────────────────── */

const RecoveryBody = () => (
  <>
    <P>
      Recovery is a separate offline file sealed under its own
      passphrase. Treat both the file and the passphrase as full
      credentials.
    </P>

    <H2>Export once, store offline</H2>
    <Box>{`$ fd0 recovery export ~/recovery.cbor
Recovery passphrase: …
Confirm recovery passphrase: …
✓ recovery file written to ~/recovery.cbor`}</Box>

    <H2>Restore on a fresh device</H2>
    <Box>{`$ fd0 recovery import ~/recovery.cbor
Recovery passphrase: …
Choose new device passphrase: …
✓ identity restored

$ fd0 unlock && fd0 sync   # auto-discovers scope memberships`}</Box>

    <Note>
      The recovery file is sealed independently of your day-to-day
      passphrase. Losing it doesn't lock you out as long as another
      enrolled auth method is still reachable; losing both means the
      vault is unrecoverable by design.
    </Note>
  </>
);

/* ─── route exports ────────────────────────────────────────────── */

export const DocsOverview = ssr(async (c) => {
  c.get("page").title = "fd0 — Documentation";
  return () => (
    <DocsLayout current="overview" title="Documentation." kicker="Reference · v1.0">
      <OverviewBody />
    </DocsLayout>
  );
});

export const DocsConcepts = ssr(async (c) => {
  c.get("page").title = "fd0 — Concepts";
  return () => (
    <DocsLayout current="concepts" title="Concepts." kicker="01 · Foundations">
      <ConceptsBody />
    </DocsLayout>
  );
});

export const DocsCli = ssr(async (c) => {
  c.get("page").title = "fd0 — CLI reference";
  return () => (
    <DocsLayout current="cli" title="CLI reference." kicker="02 · Daily use">
      <CliBody />
    </DocsLayout>
  );
});

export const DocsSsh = ssr(async (c) => {
  c.get("page").title = "fd0 — SSH";
  return () => (
    <DocsLayout current="ssh" title="SSH — keys + hosts." kicker="03 · Built on top">
      <SshBody />
    </DocsLayout>
  );
});

export const DocsSync = ssr(async (c) => {
  c.get("page").title = "fd0 — Sync";
  return () => (
    <DocsLayout current="sync" title="Sync." kicker="04 · Multi-device, multi-server">
      <SyncBody />
    </DocsLayout>
  );
});

export const DocsServer = ssr(async (c) => {
  c.get("page").title = "fd0 — Self-host";
  return () => (
    <DocsLayout current="server" title="Self-host the server." kicker="05 · Deploy">
      <ServerBody />
    </DocsLayout>
  );
});

export const DocsYubikey = ssr(async (c) => {
  c.get("page").title = "fd0 — YubiKey unlock";
  return () => (
    <DocsLayout current="yubikey" title="YubiKey unlock." kicker="06 · Hardware-backed identity">
      <YubikeyBody />
    </DocsLayout>
  );
});

export const DocsRecovery = ssr(async (c) => {
  c.get("page").title = "fd0 — Recovery";
  return () => (
    <DocsLayout current="recovery" title="Recovery." kicker="07 · Restore on a fresh device">
      <RecoveryBody />
    </DocsLayout>
  );
});

export default DocsOverview;
