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
      recovery, SSH, Talos &amp; Kube. Identical whether you self-host{" "}
      <Code>fd0-server</Code> or point the client at <Code>fd0.sh</Code>.
      The <a href="/spec" style={`color:${C.acc};`}>specification</a>{" "}
      covers the protocol underneath.
    </P>

    <div class="grid sm:grid-cols-2 gap-4 mt-8">
      {[
        { href: "/docs/concepts", t: "Concepts", d: "Eight terms used everywhere below." },
        { href: "/docs/install", t: "Install", d: "The client script + the agent skill." },
        { href: "/docs/cli", t: "CLI reference", d: "fd0 init, set, get, ls, sync, …" },
        { href: "/docs/ssh", t: "SSH", d: "Keys + hosts as scope-shared secrets." },
        { href: "/docs/talos", t: "Talos & Kube", d: "Talos contexts, secrets.yaml DR, kubeconfigs." },
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

/* ─── install ──────────────────────────────────────────────────── */

const InstallBody = () => (
  <>
    <P>
      Two separate installs: the <strong>fd0 client</strong> (the
      binaries on your machine) and — if you drive fd0 through an AI
      agent — the <strong>fd0 skill</strong> (so the agent uses the CLI
      correctly). Neither needs the other; install whichever you need.
    </P>

    <H2>The client</H2>
    <P>
      One script. It downloads the right build for your platform,
      cosign-verifies the release manifest when <Code>cosign</Code> is
      available, and drops <Code>fd0</Code> + <Code>fd0-agent</Code>{" "}
      into <Code>~/.local/bin</Code>.
    </P>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh
✓ fd0 0.3.0 → ~/.local/bin/fd0
✓ fd0-agent 0.3.0 → ~/.local/bin/fd0-agent
✓ cosign-verified

$ fd0 version`}</Box>
    <P>
      Supported platforms: Linux and macOS on amd64 and arm64. Pass{" "}
      <Code>--system</Code> to install into <Code>/usr/local/bin</Code>{" "}
      instead. If <Code>~/.local/bin</Code> isn't on your{" "}
      <Code>$PATH</Code>, the script prints the exact one-line fix for
      your shell.
    </P>
    <Note>
      <strong>Windows isn't built yet.</strong> The binaries
      cross-compile, but the agent's AF_UNIX socket is unvalidated on
      Windows. Track progress on GitHub.
    </Note>

    <H2>The agent skill</H2>
    <P>
      If you let an AI agent (Claude Code, etc.) run fd0 for you, the
      skill teaches it the command surface, the security rules, and
      the sharing flows — so "save my deploy key" or "share the prod
      password with bob" resolves to the right <Code>fd0</Code>{" "}
      commands instead of guesswork.
    </P>
    <H3>Recommended — bunx skills</H3>
    <Box>{`$ bunx skills add ValentinKolb/fd0.sh`}</Box>
    <P>
      Clones the repo, finds <Code>skills/fd0/</Code>, and copies it to
      your local skill directory (typically{" "}
      <Code>~/.claude/skills/fd0/</Code>). The agent picks it up on the
      next session.
    </P>
    <H3>Manual</H3>
    <Box>{`$ git clone https://github.com/ValentinKolb/fd0.sh.git /tmp/fd0.sh
$ mkdir -p ~/.claude/skills
$ cp -r /tmp/fd0.sh/skills/fd0 ~/.claude/skills/
$ ls ~/.claude/skills/fd0/SKILL.md`}</Box>

    <H2>Updating</H2>
    <P>
      Re-run the install script to update the client; re-run{" "}
      <Code>bunx skills add</Code> to update the skill. The client and
      skill version independently — the CLI under{" "}
      <Code>client-vX.Y.Z</Code> tags, the skill alongside the repo.
    </P>
    <Box>{`$ curl -fsSL https://fd0.sh/install | sh   # client
$ bunx skills add ValentinKolb/fd0.sh      # skill`}</Box>

    <Note>
      Next:{" "}
      <a href="/docs/cli" style={`color:${C.acc};`}>CLI reference</a> for
      the full command set, or jump straight to{" "}
      <a href="/docs/sync" style={`color:${C.acc};`}>Sync</a> to point
      the client at a backend.
    </Note>
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

    <H3>SSH, Talos &amp; Kube</H3>
    <P>
      Top-level <Code>fd0 key</Code> + <Code>fd0 ssh</Code> manage SSH
      keys and hosts — see the{" "}
      <a href="/docs/ssh" style={`color:${C.acc};`}>SSH page</a>.{" "}
      <Code>fd0 talos</Code> + <Code>fd0 kube</Code> manage Talos Linux
      contexts and kubeconfigs — see the{" "}
      <a href="/docs/talos" style={`color:${C.acc};`}>Talos &amp; Kube page</a>.
    </P>
    <Note>
      <strong>--force on every add / new / move.</strong> Across all
      four families (<Code>key</Code>, <Code>ssh</Code>,{" "}
      <Code>talos</Code>, <Code>kube</Code>) an <Code>add</Code>,{" "}
      <Code>new</Code>, or <Code>move</Code> refuses to overwrite an
      existing name by default. Pass <Code>--force</Code> to overwrite
      knowingly.
    </Note>
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
    <Cmd signature="fd0 key move <name> --to-scope <s>" body={<>Move a key between scopes you own. Hosts referencing it follow. Refuses to overwrite a same-named key in the destination unless you pass <Code>--force</Code>.</>} />

    <H2>Hosts</H2>
    <P>
      A host is a structured record: alias, hostname, user, port, the
      key to use, optional jump host, tags, description, and any
      verbatim ssh_config options. It renders into{" "}
      <Code>~/.ssh/fd0.conf</Code> with{" "}
      <Code>IdentityAgent {`{fd0-sock}`}</Code> baked in.
    </P>
    <Note>
      <strong>Public-key selector files.</strong> For each host with an
      fd0 key, fd0 also renders a public-key file to{" "}
      <Code>~/.ssh/fd0.d/&lt;alias&gt;.pub</Code> and points{" "}
      <Code>IdentityFile</Code> at it, alongside{" "}
      <Code>IdentitiesOnly yes</Code>. That's what makes OpenSSH pick
      the right agent identity deterministically — without a selector,
      <Code>IdentitiesOnly</Code> would fall back to your default{" "}
      <Code>~/.ssh/id_*</Code> keys and the connection fails with{" "}
      <Code>Permission denied (publickey)</Code>. These are public keys
      only (no private material ever on disk), fully fd0-managed, and
      regenerated on every change — including pruning when a host is
      removed. Hosts <em>without</em> an fd0 key get{" "}
      <Code>IdentityAgent</Code> alone, so your own keys still work.
    </Note>

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
    <Cmd signature="fd0 ssh move <alias> --to-scope <s>" body={<>Move a host between scopes you own. Refuses to overwrite an existing host in the destination — pass <Code>--force</Code> to overwrite.</>} />

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
server    = "https://api.fd0.sh"
interval  = "1h"
on_unlock = true`}</Box>
      </div>
    </div>

    <H2>One primary per client</H2>
    <P>
      A client writes and reads to exactly <strong>one</strong> server —
      its primary. Every scope has a single ordering authority, so two
      servers can never disagree about a scope's history. Listing more
      than one server in <Code>[sync]</Code> is a hard error, not a
      silent fallback: a second write target could diverge, and resolving
      that means discarding a write.
    </P>
    <P>
      Redundancy comes from a server-side disaster-recovery backup (see
      the self-host section), not a second write target. The trade-off is
      explicit: a scope's availability is its primary's uptime — there is
      no live failover to a replica (reading a possibly-stale replica is
      the inconsistency we avoid).
    </P>
    <Note>
      <strong>Concurrent-write safety.</strong> Two members writing the
      same scope hit the one primary; it returns <Code>409 divergence</Code>{" "}
      for a stale push, and the client refreshes, re-signs, and retries.
      Linear log with optimistic concurrency — one authority, so it always
      converges.
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

    <H2>Disaster-recovery backup</H2>
    <P>
      An optional standby mirrors a primary's chains into a write-once
      local archive — if the primary's disk dies, no event is lost. Point
      the standby at the primary, and list the standby in the primary's{" "}
      <Code>FD0_PEERS</Code> so it authorises the pull. The standby never
      serves the backed-up chains; promotion is an operator restore.
    </P>
    <Box>{`# standby server — env
FD0_REPLICATE_FROM=https://fd0.example.com
FD0_REPLICATE_INTERVAL=30s

# on the primary, trust the standby as a peer:
FD0_PEERS=https://fd0-backup.example.com
# (FD0_PEER_RESOLVE_INTERVAL — how fast peers get pinned; default 1h)`}</Box>

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

/* ─── talos & kube ─────────────────────────────────────────────── */

const TalosKubeBody = () => (
  <>
    <P>
      Two consumers built on the same "everything is a typed secret"
      foundation as <a href="/docs/ssh" style={`color:${C.acc};`}>SSH</a>.{" "}
      <Code>fd0 talos</Code> manages Talos Linux client contexts and the
      DR-grade <Code>secrets.yaml</Code> bundle;{" "}
      <Code>fd0 kube</Code> manages kubeconfigs for any cluster (Talos,
      EKS, GKE, AKS, k3s). Both render to a deterministic file you
      merge with the native tool, and both are scope-shared — onboarding
      a teammate is the same <Code>scope add-member</Code> flow as
      sharing a password.
    </P>
    <Note>
      <strong>No extra tools for the everyday path.</strong> Storing,
      listing, rendering, and merging configs — including{" "}
      <Code>talos sync --merge</Code> and <Code>kube sync --merge</Code>{" "}
      — is pure Go: <Code>kubectl</Code> is never needed, and{" "}
      <Code>talosctl</Code> isn't either. Only the three cluster-admin
      paths that need Talos PKI crypto or a live API connection —{" "}
      <Code>talos new</Code> (day-0), <Code>talos role-add</Code>{" "}
      (onboarding), and <Code>talos kubeconfig</Code> (fetch) — shell
      out to <Code>talosctl</Code>. Anyone bootstrapping a Talos cluster
      already has it.
    </Note>

    <H2>fd0 talos — contexts</H2>
    <P>
      A Talos context is the per-cluster entry under{" "}
      <Code>contexts:</Code> in <Code>~/.talos/config</Code>: endpoints,
      nodes, and the operator's mTLS material (CA + client cert + key)
      issued by the cluster's Talos OS CA. fd0 renders them to{" "}
      <Code>~/.talos/config.fd0</Code> and folds them into your primary
      config with <Code>talos sync --merge</Code>.
    </P>
    <Cmd signature="fd0 talos add <name> [--from-config <path>] [...flags]" body={<>Import contexts from an existing talosconfig (<Code>--from-config</Code>, optionally <Code>--import-context NAME</Code>), or build one from <Code>--endpoint</Code> + <Code>--ca-file</Code> / <Code>--crt-file</Code> / <Code>--key-file</Code>. <Code>--role</Code>, <Code>--tag</Code>, <Code>--scope</Code> apply. Refuses an existing name unless <Code>--force</Code>.</>} example={`$ fd0 talos add --from-config ~/.talos/config \\
    --scope work --role os:admin
✓ imported "prod-1" (scope: work)
✓ imported "staging" (scope: work)
✓ rendered ~/.talos/config.fd0 (2 contexts)`} />
    <Cmd signature="fd0 talos ls [--tag <t>...] [--no-tag <t>...]" body="List contexts; surfaces endpoints + role + tags. Filter by tag, limit by --scope." />
    <Cmd signature="fd0 talos show <name>" body="Print the context — endpoints, nodes, role, tags; CA/cert sizes (the private key stays hidden)." />
    <Cmd signature="fd0 talos rm <name>" body="Tombstone the context and re-render the config file." />
    <Cmd signature="fd0 talos move <name> --to-scope <s>" body={<>Move a context between scopes you own. Refuses to overwrite a same-named context in the destination unless <Code>--force</Code>.</>} />
    <Cmd signature="fd0 talos sync [--merge]" body={<>Re-render <Code>~/.talos/config.fd0</Code>. With <Code>--merge</Code>, folds it into <Code>~/.talos/config</Code> via a pure-Go structural merge (no <Code>talosctl</Code> needed) — fd0's contexts overwrite same-named ones; your other contexts and active-context pointer are preserved.</>} />

    <H2>fd0 talos — day-0 + day-N</H2>
    <P>
      <Code>talos new</Code> bootstraps a cluster's full credential set
      from scratch; <Code>role-add</Code> mints a role-scoped operator
      cert for a teammate; <Code>kubeconfig</Code> pulls a fresh admin
      kubeconfig off the cluster and stores it for{" "}
      <Code>fd0 kube</Code>.
    </P>
    <Cmd signature="fd0 talos new <name> --endpoint https://IP:6443" body={<>Generates root PKI + controlplane.yaml + worker.yaml + talosconfig via <Code>talosctl gen secrets|config</Code>. Stores the admin context + the DR <Code>secrets.yaml</Code> bundle (under <Code>--vault-scope</Code> if you want it in a separate least-privilege scope). All generated files are written 0600. Refuses an existing cluster name unless <Code>--force</Code> (overwrite = destruction — export the secrets first).</>} example={`$ fd0 talos new prod --endpoint https://10.0.1.10:6443 \\
    --scope work --vault-scope work-dr
→ talosctl gen secrets …
→ talosctl gen config "prod" …
✓ stored talos context "prod" (role: os:admin)
✓ stored secrets.yaml (DR bundle) in scope work-dr
→ controlplane.yaml + worker.yaml written to ./
  shred -u secrets.yaml once you've handed off the install configs`} />
    <Cmd signature="fd0 talos role-add --from <ctx> --name <new> --role os:operator" body={<>Mints a fresh role-scoped client cert via <Code>talosctl config new</Code> against an admin issuer, and stores it under the new name. The issuer must be an <Code>os:admin</Code> context — fd0 rejects known non-admin roles up front. <Code>--ttl</Code> passes through to the cert validity.</>} />
    <Cmd signature="fd0 talos kubeconfig <ctx>" body={<>Runs <Code>talosctl kubeconfig</Code> against the cluster and stores the resulting kubeconfig under the same name. A cert refresh — preserves your namespace / tags / description, overwrites only the rotated server / CA / cert / key.</>} />

    <H2>fd0 talos — DR secrets.yaml</H2>
    <P>
      The <Code>secrets.yaml</Code> bundle is the cluster's root PKI —
      the four CAs, service-account key, and at-rest encryption keys.
      Lose it and the cluster cannot be regenerated or re-issued
      operator certs offline. fd0 stores it under a separate typed
      secret so the day-to-day <Code>talos sync</Code> path never
      touches it.
    </P>
    <Cmd signature="fd0 talos secrets import <name> --in <file>" body="Stash an existing secrets.yaml into the vault (for a cluster you had before fd0)." />
    <Cmd signature="fd0 talos secrets export <name> --out <file> [--force]" body="Write a stored bundle back to disk. Refuses to overwrite an existing file unless --force — losing a fresh export on top of an old one would be the worst foot-gun." />
    <Cmd signature="fd0 talos secrets ls" body="List stored bundles by name + size. Never prints contents." />

    <H2>fd0 kube — kubeconfigs</H2>
    <P>
      A kubeconfig entry is one logical "I can talk to this cluster":
      server URL + CA, a client credential (cert+key or bearer token),
      optional default namespace. fd0 renders them to{" "}
      <Code>~/.kube/config.fd0</Code> and folds them into your primary
      config with <Code>kube sync --merge</Code> (pure Go, no{" "}
      <Code>kubectl</Code>).
    </P>
    <Cmd signature="fd0 kube add <name> [--from-config <path>] [...flags]" body={<>Import every supported context from a kubeconfig (<Code>--from-config</Code>; exec / auth-provider entries are skipped with a note), or build one from <Code>--server</Code> + <Code>--ca-file</Code> + (<Code>--client-cert-file</Code>/<Code>--client-key-file</Code> or <Code>--token</Code>). <Code>--namespace</Code>, <Code>--insecure-skip-tls-verify</Code>, <Code>--tag</Code>, <Code>--scope</Code> apply. Refuses an existing name unless <Code>--force</Code>.</>} example={`$ fd0 kube add prod --server https://10.0.1.10:6443 \\
    --ca-file ca.crt --client-cert-file me.crt \\
    --client-key-file me.key --namespace default --scope work
✓ added kubeconfig "prod" (scope: work)
✓ rendered ~/.kube/config.fd0 (1 clusters)`} />
    <Cmd signature="fd0 kube ls [--tag <t>...] [--no-tag <t>...]" body="List clusters; surfaces server + auth type + namespace + tags." />
    <Cmd signature="fd0 kube show <name>" body="Print the cluster — server, auth method, namespace, CA size. Token/key stay hidden." />
    <Cmd signature="fd0 kube rm <name>" body="Tombstone the cluster and re-render the config file." />
    <Cmd signature="fd0 kube move <name> --to-scope <s>" body={<>Move a kubeconfig between scopes you own. Refuses to overwrite a same-named entry in the destination unless <Code>--force</Code>.</>} />
    <Cmd signature="fd0 kube sync [--merge]" body={<>Re-render <Code>~/.kube/config.fd0</Code>. With <Code>--merge</Code>, folds it into <Code>~/.kube/config</Code> via a pure-Go structural merge (no <Code>kubectl</Code> needed) — fd0's clusters replace same-named entries while your other clusters, including exec / auth-provider (EKS / GKE) ones, and your current-context are preserved.</>} />
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

export const DocsInstall = ssr(async (c) => {
  c.get("page").title = "fd0 — Install";
  return () => (
    <DocsLayout current="install" title="Install." kicker="02 · Get the client">
      <InstallBody />
    </DocsLayout>
  );
});

export const DocsCli = ssr(async (c) => {
  c.get("page").title = "fd0 — CLI reference";
  return () => (
    <DocsLayout current="cli" title="CLI reference." kicker="03 · Daily use">
      <CliBody />
    </DocsLayout>
  );
});

export const DocsSsh = ssr(async (c) => {
  c.get("page").title = "fd0 — SSH";
  return () => (
    <DocsLayout current="ssh" title="SSH — keys + hosts." kicker="04 · Built on top">
      <SshBody />
    </DocsLayout>
  );
});

export const DocsTalos = ssr(async (c) => {
  c.get("page").title = "fd0 — Talos & Kube";
  return () => (
    <DocsLayout current="talos" title="Talos &amp; Kube." kicker="05 · Built on top">
      <TalosKubeBody />
    </DocsLayout>
  );
});

export const DocsSync = ssr(async (c) => {
  c.get("page").title = "fd0 — Sync";
  return () => (
    <DocsLayout current="sync" title="Sync." kicker="06 · Multi-device, multi-server">
      <SyncBody />
    </DocsLayout>
  );
});

export const DocsServer = ssr(async (c) => {
  c.get("page").title = "fd0 — Self-host";
  return () => (
    <DocsLayout current="server" title="Self-host the server." kicker="07 · Deploy">
      <ServerBody />
    </DocsLayout>
  );
});

export const DocsYubikey = ssr(async (c) => {
  c.get("page").title = "fd0 — YubiKey unlock";
  return () => (
    <DocsLayout current="yubikey" title="YubiKey unlock." kicker="08 · Hardware-backed identity">
      <YubikeyBody />
    </DocsLayout>
  );
});

export const DocsRecovery = ssr(async (c) => {
  c.get("page").title = "fd0 — Recovery";
  return () => (
    <DocsLayout current="recovery" title="Recovery." kicker="09 · Restore on a fresh device">
      <RecoveryBody />
    </DocsLayout>
  );
});

export default DocsOverview;
