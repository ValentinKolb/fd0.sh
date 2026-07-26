/**
 * / — Landing + Quickstart.
 *
 * Design language: V1 (dark amber, polished SaaS register, Geist sans
 * + Geist Mono for code). Wording is technical and concrete — no
 * editorial framing, no condescension, no story-telling, no padding.
 * The marketing register is OK because fd0 is professional-grade;
 * not because we're selling anything (it's Apache-2.0 open source).
 *
 * fd0 ships in two flavours sharing one protocol:
 *   - self-host  — run fd0-server on your own infrastructure
 *   - fd0.sh     — managed instance we operate; same ciphertext-only
 *                  contract, just one less binary to run
 *
 * Section flow: hero → verifiable properties → three guarantees →
 *   install + backend choice → quickstart → small compare → architecture →
 *   docs CTA.
 */

import { setPageSeo, ssr } from "../../config";
import { Shell } from "../lib/shell";
import { C, FONT_SANS, FONT_MONO, Nav, Footer } from "../lib/chrome";

const Btn = (p: {
  href: string;
  primary?: boolean;
  children: any;
}) => (
  <a
    href={p.href}
    class="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-medium transition-colors"
    style={
      p.primary
        ? `background:${C.acc};color:#0a0a0a;border:1px solid ${C.acc};`
        : `color:${C.fg};border:1px solid ${C.border};`
    }
  >
    {p.children}
  </a>
);

const Feature = (p: { kicker: string; title: string; body: string }) => (
  <div
    class="p-7 flex flex-col gap-3"
    style={`background:${C.bgRaised};border:1px solid ${C.border};`}
  >
    <div
      class="text-[11px] tracking-[0.18em] uppercase"
      style={`color:${C.acc};`}
    >
      {p.kicker}
    </div>
    <div class="text-lg font-medium">{p.title}</div>
    <p class="text-sm leading-relaxed" style={`color:${C.dim};`}>
      {p.body}
    </p>
  </div>
);

const PropertyCard = (p: { label: string; value: string; sub?: string }) => (
  <div class="px-2">
    <div
      class="text-[10px] tracking-[0.22em] uppercase mb-2"
      style={`color:${C.dim};`}
    >
      {p.label}
    </div>
    <div
      class="text-base font-medium leading-snug"
      style={`color:${C.fg};font-family:${FONT_MONO};`}
    >
      {p.value}
    </div>
    {p.sub ? (
      <div class="text-[11px] mt-1" style={`color:${C.dim};`}>
        {p.sub}
      </div>
    ) : null}
  </div>
);

const TermFrame = (p: { title: string; children: any }) => (
  <div
    class="text-[13px] leading-[1.7] self-start"
    style={`background:${C.bg};border:1px solid ${C.border};box-shadow:0 30px 80px -40px ${C.acc}33,inset 0 1px 0 ${C.border};font-family:${FONT_MONO};`}
  >
    <div
      class="flex items-center gap-1.5 px-4 py-3 border-b"
      style={`color:${C.dim};border-color:${C.border};`}
    >
      <span class="w-2.5 h-2.5 rounded-full" style="background:#ff5f56;" />
      <span class="w-2.5 h-2.5 rounded-full" style="background:#ffbd2e;" />
      <span class="w-2.5 h-2.5 rounded-full" style="background:#27c93f;" />
      <span class="ml-3 text-[11px]">{p.title}</span>
    </div>
    <div class="p-5">{p.children}</div>
  </div>
);

const BackendCol = (p: {
  badge: string;
  title: string;
  body: string;
  code: string;
  codeNote: string;
}) => (
  <div
    class="p-6 flex flex-col gap-4"
    style={`background:${C.bg};border:1px solid ${C.border};`}
  >
    <div class="flex items-center justify-between">
      <span
        class="text-[10px] tracking-widest uppercase px-2 py-0.5"
        style={`background:${C.acc}22;color:${C.acc};border:1px solid ${C.acc}44;`}
      >
        {p.badge}
      </span>
    </div>
    <div>
      <div class="text-lg font-medium mb-2">{p.title}</div>
      <p class="text-sm leading-relaxed" style={`color:${C.dim};`}>
        {p.body}
      </p>
    </div>
    <div
      class="p-4 text-[13px] leading-[1.6]"
      style={`background:${C.bgRaised};border:1px solid ${C.border};font-family:${FONT_MONO};`}
    >
      <Shell>{p.code}</Shell>
    </div>
    <div class="text-xs leading-relaxed mt-1" style={`color:${C.dim};`}>
      {p.codeNote}
    </div>
  </div>
);

const Step = (p: {
  n: string;
  title: string;
  body: string;
  code: string;
}) => (
  <div class="grid md:grid-cols-[5rem_1fr] gap-x-6 gap-y-3">
    <div
      class="text-3xl tracking-tight font-medium"
      style={`color:${C.acc};font-family:${FONT_MONO};`}
    >
      {p.n}
    </div>
    <div>
      <div class="text-lg font-medium mb-1.5">{p.title}</div>
      <p class="text-sm leading-relaxed mb-4" style={`color:${C.dim};`}>
        {p.body}
      </p>
      <div
        class="p-4 text-[13px] leading-[1.6]"
        style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
      >
        <Shell>{p.code}</Shell>
      </div>
    </div>
  </div>
);

const Home = () => (
  <div
    class="min-h-screen"
    style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;`}
  >
    <Nav current="home" />

    {/* ─── hero ──────────────────────────────────────────────────────── */}
    <header class="px-6 md:px-10 pt-20 md:pt-28 pb-20 max-w-6xl mx-auto">
      <div class="grid md:grid-cols-[1.1fr_0.9fr] gap-12 items-start">
        <div>
          <div
            class="inline-flex items-center gap-2 px-3 py-1 text-[11px] tracking-widest uppercase mb-7"
            style={`color:${C.acc};border:1px solid ${C.border};`}
          >
            <span
              class="inline-block w-1.5 h-1.5 rounded-full"
              style={`background:${C.acc};`}
            />
            Apache-2.0 · client-side encrypted
          </div>
          <h1 class="text-[2.6rem] md:text-[3.4rem] leading-[1.05] tracking-tight font-medium">
            <span class="fd0-rotword-wrap">
              <span id="fd0-rotword" class="fd0-rotword">Secrets</span>
              <span id="fd0-rotbar" class="fd0-rotbar" />
            </span>{" "}
            you keep,
            <br />
            <span style={`color:${C.acc};`}>not secrets you trust.</span>
          </h1>
          <style innerHTML={`
            .fd0-rotword-wrap {
              display: inline-block;
              position: relative;
              padding-bottom: 6px;
            }
            .fd0-rotword {
              display: inline-block;
              transition: opacity 380ms ease, transform 380ms ease;
            }
            .fd0-rotword.fade-out { opacity: 0; transform: translateY(-6px); }
            .fd0-rotbar {
              position: absolute;
              left: 0;
              bottom: 0;
              height: 3px;
              width: 0;
              background: ${C.acc};
              border-radius: 2px;
              animation: fd0-rotbar 4500ms linear infinite;
            }
            .fd0-rotbar.paused { animation-play-state: paused; }
            @keyframes fd0-rotbar {
              0%   { width: 0; opacity: 1; }
              92%  { width: 100%; opacity: 1; }
              100% { width: 100%; opacity: 0; }
            }
            @media (prefers-reduced-motion: reduce) {
              .fd0-rotbar { animation: none; width: 100%; }
            }
          `} />
          <script innerHTML={`(function(){
            var words = ['Secrets','SSH keys','SSH hosts','Kube configs'];
            var el  = document.getElementById('fd0-rotword');
            var bar = document.getElementById('fd0-rotbar');
            if (!el || !bar) return;
            var idx = 0;
            var paused = false;
            var wrap = el.parentElement;
            wrap.addEventListener('mouseenter', function(){
              paused = true;
              bar.classList.add('paused');
            });
            wrap.addEventListener('mouseleave', function(){
              paused = false;
              bar.classList.remove('paused');
            });
            setInterval(function(){
              if (paused) return;
              el.classList.add('fade-out');
              setTimeout(function(){
                idx = (idx + 1) % words.length;
                el.textContent = words[idx];
                el.classList.remove('fade-out');
                // Restart bar animation in sync with the word change so
                // they never drift after many cycles.
                bar.style.animation = 'none';
                void bar.offsetWidth;
                bar.style.animation = '';
              }, 380);
            }, 4500);
          })();`} />
          <p
            class="mt-6 text-lg leading-relaxed max-w-xl"
            style={`color:${C.dim};`}
          >
            One zero-knowledge vault for the credentials you'd otherwise
            scatter across <span style={`color:${C.acc};`}>.ssh</span>,{" "}
            <span style={`color:${C.acc};`}>kubeconfig</span>, Talos config,
            and someone's Notion page. The server stores ciphertext and signed
            events only. Sharing membership rotates per-scope keys atomically.
            Configured witnesses can detect server-side forks.
          </p>
          <div class="mt-8 flex flex-wrap items-center gap-3">
            <Btn href="#install" primary>
              Get started →
            </Btn>
            <Btn href="https://github.com/ValentinKolb/fd0.sh">
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="currentColor"
                aria-hidden="true"
              >
                <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.1.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.34-1.28-1.69-1.28-1.69-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.03 1.76 2.69 1.25 3.35.95.1-.74.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.09-.12-.29-.51-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.04 11.04 0 0 1 5.78 0c2.21-1.49 3.18-1.18 3.18-1.18.62 1.59.23 2.76.11 3.05.74.8 1.18 1.83 1.18 3.09 0 4.42-2.7 5.39-5.27 5.68.41.35.78 1.04.78 2.1 0 1.52-.02 2.74-.02 3.11 0 .3.21.66.8.55C20.21 21.38 23.5 17.07 23.5 12 23.5 5.65 18.35.5 12 .5z" />
              </svg>
              Source on GitHub
            </Btn>
            <span class="text-xs ml-2" style={`color:${C.dim};`}>
              No telemetry. Ciphertext only on either backend.
            </span>
          </div>
        </div>

        <TermFrame title="example — fd0 sync">
          <Shell>{`$ fd0 sync
→ POST /v1/sync  scope=work  push=3
← 200 OK  pull=0  sth=verified@43
✓ chain advanced (seq=7)
✓ STH verified

$ fd0 get DEPLOY_KEY
ghp_xxxxxxxxxxxxxxxxxxxx`}</Shell>
        </TermFrame>
      </div>
    </header>

    {/* ─── verifiable properties strip ───────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-10 border-y"
      style={`border-color:${C.border};background:${C.bgRaised};`}
    >
      <div class="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-8">
        <PropertyCard
          label="Cryptography"
          value="Ed25519 · X25519"
          sub="AES-256-GCM AEAD"
        />
        <PropertyCard
          label="Transparency"
          value="RFC 6962 + witness"
          sub="independent cosigner"
        />
        <PropertyCard
          label="Releases"
          value="signed installer"
          sub="cosign-verifiable manifest"
        />
        <PropertyCard
          label="Source"
          value="Apache-2.0"
          sub="github.com/ValentinKolb/fd0.sh"
        />
      </div>
    </section>

    {/* ─── three guarantees ──────────────────────────────────────────── */}
    <section
      id="how"
      class="px-6 md:px-10 py-20"
    >
      <div class="max-w-6xl mx-auto">
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-3"
          style={`color:${C.acc};`}
        >
          Three guarantees
        </div>
        <h2 class="text-3xl md:text-4xl font-medium tracking-tight mb-12 max-w-2xl">
          Built into the protocol, not the deployment.
        </h2>
        <div class="grid md:grid-cols-3 gap-6">
          <Feature
            kicker="Encryption"
            title="The server cannot decrypt."
            body="Every secret is sealed by the client before it leaves the device. The server stores ciphertext and signed event metadata — an operator with full database access reads no secret values or secret names."
          />
          <Feature
            kicker="Membership"
            title="Add or remove members atomically."
            body="Each scope has its own key. Adding a member wraps the key to their card; removing one rotates it. Cryptographic, not policy-enforced."
          />
          <Feature
            kicker="Transparency"
            title="Forks are detectable."
            body="The server signs every tree head. With configured witnesses or clients comparing notes, divergent histories become publishable evidence."
          />
        </div>
      </div>
    </section>

    {/* ─── install + backend choice ──────────────────────────────────── */}
    <section
      id="install"
      class="px-6 md:px-10 py-20 border-y"
      style={`border-color:${C.border};background:${C.bgRaised};`}
    >
      <div class="max-w-6xl mx-auto">
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-3"
          style={`color:${C.acc};`}
        >
          Install
        </div>
        <h2 class="text-3xl md:text-4xl font-medium tracking-tight mb-5 max-w-2xl">
          Install the client. Pick a backend.
        </h2>
        <p class="text-base leading-relaxed max-w-2xl mb-10" style={`color:${C.dim};`}>
          Same client either way. The main difference is who runs the server.
          Client-side encryption and scope membership work the
          same; witness enforcement depends on your client config.
        </p>

        {/* step 1: install client */}
        <div class="mb-10">
          <div
            class="text-xs tracking-[0.18em] uppercase mb-3"
            style={`color:${C.dim};`}
          >
            01 · Install the client
          </div>
          <div
            class="p-4 text-[14px] select-all cursor-text max-w-2xl"
            style={`background:${C.bg};border:1px solid ${C.acc};font-family:${FONT_MONO};`}
          >
            <Shell>curl -fsSL https://fd0.sh/install | sh</Shell>
          </div>
          <div class="text-xs mt-2" style={`color:${C.dim};`}>
            Installs <span style={`color:${C.acc};`}>fd0</span> and{" "}
            <span style={`color:${C.acc};`}>fd0-agent</span> to{" "}
            <span style={`color:${C.acc};`}>~/.local/bin</span>.
            Requires <span style={`color:${C.acc};`}>cosign</span> and
            authenticates the SHA-256 manifest against the exact release
            workflow and tag. Add{" "}
            <span style={`color:${C.acc};`}>--desktop</span> for one signed app bundle that also owns the CLI and agent.
          </div>
        </div>

        {/* step 2: pick backend */}
        <div>
          <div
            class="text-xs tracking-[0.18em] uppercase mb-3"
            style={`color:${C.dim};`}
          >
            02 · Pick a backend
          </div>
          <div class="grid md:grid-cols-2 gap-5">
            <BackendCol
              badge="Self-host"
              title="Run fd0-server yourself."
              body="Download the minimal compose file, run one fd0-server on localhost, and put your own TLS terminator in front. Pin image tags for production."
              code={`mkdir fd0-server && cd fd0-server
curl -fsSLO https://fd0.sh/files/compose.yml
umask 077
printf 'METRICS_TOKEN=%s\\n' "$(openssl rand -hex 32)" > .env
case "$(uname -m)" in arm64|aarch64) printf 'FD0_SERVER_IMAGE=%s\\n' 'ghcr.io/valentinkolb/fd0-server:latest-arm64' >> .env ;; esac
docker compose up -d`}
              codeNote="One primary per client — clients set [sync].server. For redundancy run a standby with FD0_REPLICATE_FROM=<primary> (the primary lists it in FD0_PEERS); it mirrors the primary read-only for disaster recovery."
            />
            <BackendCol
              badge="Hosted at fd0.sh"
              title="Use the managed instance."
              body="A managed primary plus a disaster-recovery backup operated by Kolb Antik GmbH in Germany. Same ciphertext-only contract: the operator cannot decrypt secrets."
              code={`# ~/.fd0/config.toml — this is the default
[sync]
server    = "https://api.fd0.sh"
on_unlock = true`}
              codeNote="The production runbook linked from /docs/server covers hosting topology, backups, metrics, witnesses, and key rotation."
            />
          </div>
        </div>
      </div>
    </section>

    {/* ─── quickstart ────────────────────────────────────────────────── */}
    <section id="quickstart" class="px-6 md:px-10 py-20">
      <div class="max-w-4xl mx-auto">
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-3"
          style={`color:${C.acc};`}
        >
          Quickstart
        </div>
        <h2 class="text-3xl md:text-4xl font-medium tracking-tight mb-10 max-w-2xl">
          Four steps.
        </h2>
        <div class="flex flex-col gap-12">
          <Step
            n="01"
            title="Generate identity, seal the vault"
            body="fd0 init writes a fresh Ed25519 keypair to ~/.fd0/vault.enc, sealed under a passphrase. The passphrase only protects the file at rest — it never reaches the server."
            code={`$ fd0 init
Choose a passphrase: ********
✓ identity created (upIamMlsgn…)
✓ vault written to ~/.fd0/vault.enc`}
          />
          <Step
            n="02"
            title="Unlock once per session"
            body="The agent holds the unlocked identity in memory. The CLI signs and decrypts through it without re-prompting until you run fd0 lock."
            code={`$ fd0 unlock
Passphrase: ********
✓ agent started
✓ vault unlocked (passphrase)`}
          />
          <Step
            n="03"
            title="Create a scope, store a secret"
            body="A scope is a group of secrets with its own encryption key. Adding or removing members rotates that key."
            code={`$ fd0 scope create --label work
$ fd0 set DEPLOY_KEY "ghp_xxxxxxxxxxxxxxxxxxxx" --scope work
$ fd0 get DEPLOY_KEY
ghp_xxxxxxxxxxxxxxxxxxxx`}
          />
          <Step
            n="04"
            title="Sync — local goes to the server"
            body="fd0 sync is the explicit network command. The agent can also sync after unlock when on_unlock is enabled."
            code={`$ fd0 sync
→ POST /v1/sync  scope=work  push=3 events
← 200 OK         pull=0      sth=verified@tree_size=43
✓ local chain updated
✓ STH verified against the pinned server key`}
          />
        </div>
      </div>
    </section>

    {/* ─── small compare strip ───────────────────────────────────────── */}
    <section
      id="compare"
      class="px-6 md:px-10 py-20 border-y"
      style={`border-color:${C.border};background:${C.bgRaised};`}
    >
      <div class="max-w-6xl mx-auto">
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-3"
          style={`color:${C.acc};`}
        >
          Compare
        </div>
        <h2 class="text-3xl md:text-4xl font-medium tracking-tight mb-10 max-w-2xl">
          Same shape, different trust model.
        </h2>
        <div class="grid md:grid-cols-2 gap-x-12 gap-y-6 text-sm">
          {[
            {
              k: "vs. Bitwarden / Vaultwarden",
              v: "Same use case. fd0's server cannot decrypt under any operator access — cryptographic, not policy.",
            },
            {
              k: "vs. 1Password Teams",
              v: "Same team-sharing model. fd0 keys live on devices you control; the server is yours or fd0.sh.",
            },
            {
              k: "vs. 1Password SSH / Bitwarden SSH",
              v: "Same per-sign agent protocol pattern. fd0 adds team-scoped keys — sharing an SSH key is the same op as sharing a password, cryptographic at scope membership.",
            },
            {
              k: "vs. pass (Git + GPG)",
              v: "fd0 has cryptographic membership built in: add/remove rotates the per-scope key atomically.",
            },
            {
              k: "vs. HashiCorp Vault",
              v: "Different scope. fd0 is a human-facing secret store; Vault is a policy engine for service-to-service auth.",
            },
          ].map((c) => (
            <div class="flex flex-col gap-1.5">
              <div style={`color:${C.acc};`} class="font-medium">
                {c.k}
              </div>
              <div style={`color:${C.dim};`}>{c.v}</div>
            </div>
          ))}
        </div>
      </div>
    </section>

    {/* ─── architecture ──────────────────────────────────────────────── */}
    <section class="px-6 md:px-10 py-20">
      <div class="max-w-6xl mx-auto">
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-3"
          style={`color:${C.acc};`}
        >
          Architecture
        </div>
        <h2 class="text-3xl md:text-4xl font-medium tracking-tight mb-3 max-w-2xl">
          Four binaries. Keys stay on your device.
        </h2>
        <p class="text-base mb-10 max-w-2xl" style={`color:${C.dim};`}>
          The client and the agent run locally. After unlock, private key
          material stays in the agent and is never written to disk in
          plaintext. Standard tools (ssh, git, scp) attach through the
          ssh-agent socket. The server holds ciphertext and signed events; the
          witness holds signed tree heads. Neither holds secret keys.
        </p>
        <div class="overflow-x-auto -mx-6 px-6 flex justify-center">
          <div class="w-fit">
            <pre
              class="shell p-6 pb-2 text-[12px] leading-[1.55]"
              style={`background:${C.bgRaised};border:1px solid ${C.border};border-bottom:none;color:${C.fg};font-family:${FONT_MONO};`}
            >{`consumers           your device           server                  observer
┌────────────────┐  ┌─────────────────┐   ┌────────────────────┐   ┌────────────────────┐
│ ssh, scp,      │  │ fd0  (CLI)      │   │ fd0-server         │   │ fd0-witness        │
│ git, rsync,    │ ─│ fd0-agent       │ ─▶│ ciphertext +       │ ─▶│ cosigns verified   │
│ kubectl …      │ ◀│   unlocked keys │   │ signed events      │ ✓ │ archives forks     │
│                │  │   vault.enc     │   │                    │   │ independent host   │
└────────────────┘  └─────────────────┘   └────────────────────┘   └────────────────────┘
   ssh-agent         single primary (api.fd0.sh) · DR backup mirrors it read-only
   protocol`}</pre>
            <div
              class="text-[12px] text-center px-6 pb-6 pt-1"
              style={`background:${C.bgRaised};border:1px solid ${C.border};border-top:none;color:${C.dim};font-family:${FONT_MONO};`}
            >
              standard protocols on both sides · zero-knowledge contract end-to-end
            </div>
          </div>
        </div>
      </div>
    </section>

    {/* ─── built on top: SSH ─────────────────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-20 border-t"
      style={`border-color:${C.border};background:${C.bgRaised}55;`}
    >
      <div class="max-w-6xl mx-auto">
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-3"
          style={`color:${C.acc};`}
        >
          Built on top — fd0 ssh
        </div>
        <h2 class="text-3xl md:text-4xl font-medium tracking-tight mb-3 max-w-2xl">
          SSH keys + host inventory, scope-shared, zero on disk.
        </h2>
        <p class="text-base mb-10 max-w-2xl" style={`color:${C.dim};`}>
          Keys are generated inside fd0-agent and served via the standard
          ssh-agent protocol. Hosts are structured entries that render to
          a regular <span style={`color:${C.acc};`}>~/.ssh/fd0.conf</span> you
          Include from your own config. Native SSH features (jump hosts,
          agent forwarding, port forwarding) all work because we are just
          an agent. Add a teammate to the scope and they get the same SSH
          access on their next sync — cryptographic, not policy.
        </p>

        <div class="grid md:grid-cols-3 gap-5">
          <div
            class="p-5 text-[13px] leading-[1.6] min-w-0 overflow-hidden"
            style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <div class="text-[11px] mb-3" style={`color:${C.dim};`}>
              01 · Generate a key
            </div>
            <Shell>{`$ fd0 key add laptop
✓ ed25519 (scope: personal)

ssh-ed25519 AAAAC3NzaC1lZD…
laptop@fd0`}</Shell>
          </div>
          <div
            class="p-5 text-[13px] leading-[1.6] min-w-0 overflow-hidden"
            style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <div class="text-[11px] mb-3" style={`color:${C.dim};`}>
              02 · Add a host
            </div>
            <Shell>{`$ fd0 ssh add prod-db \\
    app@db.internal \\
    --jump bastion \\
    --key laptop \\
    --scope work

✓ host added
✓ ~/.ssh/fd0.conf rendered`}</Shell>
          </div>
          <div
            class="p-5 text-[13px] leading-[1.6] min-w-0 overflow-hidden"
            style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <div class="text-[11px] mb-3" style={`color:${C.dim};`}>
              03 · Use native ssh
            </div>
            <Shell>{`$ ssh prod-db
$ ssh prod-db "uname -a"
$ scp dump.sql prod-db:/tmp/
$ git push origin main`}</Shell>
          </div>
        </div>

        <div class="grid md:grid-cols-2 gap-5 mt-5">
          <div
            class="p-5 text-sm"
            style={`background:${C.bg};border:1px solid ${C.border};`}
          >
            <div
              class="text-[11px] mb-2"
              style={`color:${C.acc};`}
            >
              For your team
            </div>
            <div style={`color:${C.fg};`}>
              <Shell>{`$ fd0 scope add-member bob --scope work
$ fd0 sync`}</Shell>
            </div>
            <p class="mt-3 text-[13px]" style={`color:${C.dim};`}>
              Bob's next sync gives him the key, the host, and the
              tags. <span style={`color:${C.acc};`}>fd0 scope remove-member</span>{" "}
              rotates the per-scope key — his next sync drops access.
            </p>
          </div>
          <div
            class="p-5 text-sm"
            style={`background:${C.bg};border:1px solid ${C.border};`}
          >
            <div
              class="text-[11px] mb-2"
              style={`color:${C.acc};`}
            >
              Standard ssh-agent protocol
            </div>
            <p class="text-[13px]" style={`color:${C.dim};`}>
              fd0-agent talks the same protocol as OpenSSH ssh-agent.
              <span style={`color:${C.acc};`}> ssh, git, scp, rsync, VS Code Remote</span> —
              anything that respects <code style={`color:${C.acc};font-family:${FONT_MONO};`}>SSH_AUTH_SOCK</code>
              works. fd0 never writes anything to the remote server.
            </p>
          </div>
        </div>
      </div>
    </section>

    {/* ─── docs CTA ──────────────────────────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-24 border-t"
      style={`border-color:${C.border};`}
    >
      <div class="max-w-4xl mx-auto text-center">
        <h2 class="text-3xl md:text-4xl font-medium tracking-tight mb-4">
          Specified, not implied.
        </h2>
        <p class="text-base mb-9 max-w-2xl mx-auto" style={`color:${C.dim};`}>
          Docs cover the common workflows. <code style={`color:${C.acc};font-family:${FONT_MONO};`}>fd0 --help</code>{" "}
          covers the full command surface. The specification covers the wire
          format, cryptographic constructions, on-disk format, transparency log,
          and threat model.
        </p>
        <div class="flex flex-wrap justify-center gap-3">
          <Btn href="/docs" primary>
            Read the docs →
          </Btn>
          <Btn href="/spec">Read the spec →</Btn>
        </div>
      </div>
    </section>

    <Footer />
  </div>
);

export default ssr(async (c) => {
  setPageSeo(c, "home");
  return () => <Home />;
});
