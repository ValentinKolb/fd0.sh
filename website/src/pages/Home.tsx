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

import { ssr } from "../../config";
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
      class="p-4 text-[13px] leading-[1.6] mt-auto"
      style={`background:${C.bgRaised};border:1px solid ${C.border};font-family:${FONT_MONO};`}
    >
      <Shell>{p.code}</Shell>
    </div>
    <div class="text-xs leading-relaxed" style={`color:${C.dim};`}>
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
            v1.0 · Apache-2.0 · zero-knowledge
          </div>
          <h1 class="text-[2.6rem] md:text-[3.4rem] leading-[1.05] tracking-tight font-medium">
            Secrets you keep,
            <br />
            <span style={`color:${C.acc};`}>not secrets you trust.</span>
          </h1>
          <p
            class="mt-6 text-lg leading-relaxed max-w-xl"
            style={`color:${C.dim};`}
          >
            Zero-knowledge secrets manager. Run the server yourself, or
            point your client at the hosted instance at{" "}
            <span style={`color:${C.acc};`}>fd0.sh</span> — either way the
            server stores ciphertext and signed events only. Membership
            changes rotate the per-scope key atomically. Hardware-backed
            identity via YubiKey. End-to-end transparency log with
            independent witness verification.
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

        <TermFrame title="~ — fd0 sync">
          <Shell>{`$ fd0 sync
→ POST /v1/sync  scope=work  push=3
← 200 OK  pull=0  sth=cosigned@43
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
          sub="XChaCha20-Poly1305 AEAD"
        />
        <PropertyCard
          label="Transparency"
          value="RFC 6962 + witness"
          sub="independent cosigner"
        />
        <PropertyCard
          label="Releases"
          value="cosign-signed"
          sub="keyless, GitHub Actions OIDC"
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
            body="Every secret is sealed by the client before it leaves the device. The server stores ciphertext and signed event headers — an operator with full database access reads nothing."
          />
          <Feature
            kicker="Membership"
            title="Add or remove members atomically."
            body="Each scope has its own key. Adding a member wraps the key to their card; removing one rotates it. Cryptographic, not policy-enforced."
          />
          <Feature
            kicker="Transparency"
            title="The server cannot equivocate."
            body="Every signed tree head is cosigned by an independent witness. Two clients comparing notes — or a third-party observer — detect server-side forks."
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
          Same client either way. The two backends differ only in who
          runs the server — the protocol guarantees are identical.
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
            <Shell>curl -fsSL https://fd0.sh/install.sh | sh</Shell>
          </div>
          <div class="text-xs mt-2" style={`color:${C.dim};`}>
            Installs <span style={`color:${C.acc};`}>fd0</span> and{" "}
            <span style={`color:${C.acc};`}>fd0-agent</span> to{" "}
            <span style={`color:${C.acc};`}>~/.local/bin</span>.
            Cosign-verified.
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
              body="One script installs fd0-server and fd0-witness, drops a hardened systemd unit, creates the fd0 system user. The server refuses to upgrade while active — stop it first."
              code="curl -fsSL https://fd0.sh/install-server.sh | sudo sh"
              codeNote="Listens on :4048 by default. State in /var/lib/fd0. Configure via /etc/default/fd0-server."
            />
            <BackendCol
              badge="Hosted at fd0.sh"
              title="Use the managed instance."
              body="Same fd0-server binary, run on hardened infrastructure. Same ciphertext-only contract — fd0.sh operators cannot decrypt either. No registration; first sync auto-registers your super_pub."
              code={`# ~/.fd0/config.toml
[sync]
server = "https://fd0.sh"
on_unlock = true`}
              codeNote="Default rate limits apply. Bring your own witness or point at the public one at witness.fd0.sh."
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
            body="The agent holds super_priv in mlocked memory after unlock. The CLI signs and decrypts through it without re-prompting until you fd0 lock."
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
            body="Sync is the only command that talks to the server. Ciphertext goes up, signed events come back, the transparency log advances."
            code={`$ fd0 sync
→ POST /v1/sync  scope=work  push=3 events
← 200 OK         pull=0      sth=cosigned@tree_size=43
✓ events written to ~/.fd0/chains/scope_work.cbor
✓ STH verified against pinned server pubkey + witness cosign`}
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
          The client and the agent run locally; super_priv is mlocked
          into the agent and never written to disk. The server and
          witness hold ciphertext and signatures — never keys.
        </p>
        <pre
          class="shell p-6 text-[12.5px] leading-[1.55]"
          style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};font-family:${FONT_MONO};`}
        >{`         your device                                server (yours or fd0.sh)             observer
   ┌───────────────────────┐                  ┌────────────────────────┐         ┌──────────────────┐
   │ fd0  (CLI)            │                  │ fd0-server             │         │ fd0-witness      │
   │ fd0-agent  (mlocked)  │  ◀── ciphertext ─│ ciphertext + signed    │  ── ✓ ──│ cosigns honest   │
   │  ↑ super_priv         │     + signed     │ events                 │   STH   │ archives forks   │
   │  ↑ vault.enc          │     events       │ no plaintext, no keys  │         │ independent host │
   └───────────────────────┘                  └────────────────────────┘         └──────────────────┘`}</pre>
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
          Reference covers every command and config option. The
          specification covers the wire format, cryptographic
          constructions, on-disk format, transparency log, and threat
          model. Both versioned with the binaries.
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
  c.get("page").title = "fd0 — secrets you keep, not secrets you trust";
  return () => <Home />;
});
