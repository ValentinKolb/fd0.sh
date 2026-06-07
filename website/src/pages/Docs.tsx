/**
 * /docs — Operator reference.
 *
 * Reference content for someone with the binaries installed: concepts,
 * CLI commands, server config, hardware unlock, sync, recovery.
 *
 * The /spec page is the protocol-level companion — wire format,
 * cryptographic constructions, threat model.
 */

import { ssr } from "../../config";
import { Shell } from "../lib/shell";
import { C, FONT_SANS, FONT_MONO, Nav, Footer } from "../lib/chrome";

const SectionHead = (p: { id: string; kicker: string; title: string; body?: string }) => (
  <div id={p.id} class="mb-12">
    <div
      class="text-[11px] tracking-[0.18em] uppercase mb-3"
      style={`color:${C.acc};`}
    >
      {p.kicker}
    </div>
    <h2 class="text-3xl md:text-[2.4rem] font-medium tracking-tight leading-[1.1] mb-4">
      {p.title}
    </h2>
    {p.body ? (
      <p class="text-base leading-relaxed max-w-3xl" style={`color:${C.dim};`}>
        {p.body}
      </p>
    ) : null}
  </div>
);

const Cmd = (p: { signature: string; body: string; example?: string }) => (
  <div
    class="p-5 mb-3 grid md:grid-cols-[1.1fr_0.9fr] gap-x-8 gap-y-3"
    style={`background:${C.bgRaised};border:1px solid ${C.border};`}
  >
    <div>
      <div
        class="text-[14px] font-medium mb-2"
        style={`color:${C.acc};font-family:${FONT_MONO};`}
      >
        {p.signature}
      </div>
      <p class="text-sm leading-relaxed" style={`color:${C.dim};`}>
        {p.body}
      </p>
    </div>
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

const ConceptRow = (p: { term: string; def: any }) => (
  <div class="grid md:grid-cols-[8rem_1fr] gap-x-6 gap-y-2 py-4" style={`border-top:1px solid ${C.border};`}>
    <div
      class="text-sm font-medium"
      style={`color:${C.acc};font-family:${FONT_MONO};`}
    >
      {p.term}
    </div>
    <div class="text-sm leading-relaxed" style={`color:${C.dim};`}>
      {p.def}
    </div>
  </div>
);

const Docs = () => (
  <div
    class="min-h-screen"
    style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;`}
  >
    <Nav current="docs" />

    {/* ─── header ────────────────────────────────────────────────────── */}
    <header class="px-6 md:px-10 pt-16 md:pt-24 pb-12 max-w-6xl mx-auto">
      <div
        class="text-[11px] tracking-[0.18em] uppercase mb-4"
        style={`color:${C.acc};`}
      >
        Reference · v1.0
      </div>
      <h1 class="text-[2.4rem] md:text-[3rem] leading-[1.05] tracking-tight font-medium">
        Documentation.
      </h1>
      <p class="mt-5 text-lg leading-relaxed max-w-2xl" style={`color:${C.dim};`}>
        Operator reference. Commands, config, sync, hardware unlock,
        recovery. Identical whether you self-host fd0-server or point
        the client at <span style={`color:${C.acc};`}>fd0.sh</span>. The{" "}
        <a href="/spec" style={`color:${C.acc};`}>
          specification
        </a>{" "}
        covers the protocol underneath.
      </p>

      {/* ─── jump nav ────────────────────────────────────────────────── */}
      <nav
        class="mt-10 flex flex-wrap gap-x-5 gap-y-2 text-sm pt-6"
        style={`border-top:1px solid ${C.border};color:${C.dim};`}
      >
        {[
          ["#concepts", "Concepts"],
          ["#cli", "CLI"],
          ["#server", "Server"],
          ["#yubikey", "YubiKey"],
          ["#sync", "Sync"],
          ["#recovery", "Recovery"],
        ].map(([href, label]) => (
          <a href={href} class="hover:text-white">
            {label}
          </a>
        ))}
      </nav>
    </header>

    {/* ─── concepts ──────────────────────────────────────────────────── */}
    <section class="px-6 md:px-10 py-16 max-w-6xl mx-auto">
      <SectionHead
        id="concepts"
        kicker="01 · Concepts"
        title="Eight terms used in every section below."
      />
      <div>
        <ConceptRow
          term="identity"
          def="Ed25519 keypair generated locally. Anchors the account across devices. Never leaves your machine unencrypted."
        />
        <ConceptRow
          term="vault"
          def={
            <>
              Local encrypted file at{" "}
              <span style={`color:${C.acc};font-family:${FONT_MONO};`}>
                ~/.fd0/vault.enc
              </span>
              . Holds super_priv, per-scope keys, chain tips. Sealed under
              every active auth method.
            </>
          }
        />
        <ConceptRow
          term="agent"
          def="Local daemon. Holds super_priv mlocked in memory after unlock; signs and decrypts on demand for the CLI."
        />
        <ConceptRow
          term="scope"
          def="Group of secrets with its own encryption key (OEK). Adding or removing a member rotates the OEK atomically."
        />
        <ConceptRow
          term="secret"
          def="Name → value pair inside a scope. AEAD-sealed individually with the current OEK."
        />
        <ConceptRow
          term="card"
          def={
            <>
              Shareable identity (
              <span style={`color:${C.acc};font-family:${FONT_MONO};`}>
                fd0://card/…
              </span>
              ). Signed once by you, pinned by a safety number out of band.
            </>
          }
        />
        <ConceptRow
          term="member"
          def="A card pinned in your vault and added to one or more scopes."
        />
        <ConceptRow
          term="sync"
          def="Event exchange with the server. Idempotent. Concurrent writes from multiple devices auto-retry against the chain tip."
        />
      </div>
    </section>

    {/* ─── CLI ───────────────────────────────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-16 border-t"
      style={`border-color:${C.border};background:${C.bgRaised}99;`}
    >
      <div class="max-w-6xl mx-auto">
        <SectionHead
          id="cli"
          kicker="02 · CLI"
          title="The fd0 command, grouped by what it touches."
          body="Every command operates on local files except fd0 sync, which talks to the configured server."
        />

        <h3
          class="text-sm tracking-widest uppercase mt-4 mb-3 font-medium"
          style={`color:${C.fg};`}
        >
          Identity & vault
        </h3>
        <Cmd
          signature="fd0 init"
          body="Generate a fresh identity and seal the vault under a passphrase. Refuses to overwrite an existing vault."
          example={`$ fd0 init
Choose a passphrase: …
✓ identity created (upIamMlsgn…)
✓ vault written to ~/.fd0/vault.enc`}
        />
        <Cmd
          signature="fd0 unlock [--method=passphrase|yubikey]"
          body="Start the agent, decrypt the vault, hold super_priv mlocked. With multiple methods, picks deterministically by id; --method forces a specific one."
          example={`$ fd0 unlock
✓ agent started
✓ vault unlocked (passphrase)`}
        />
        <Cmd
          signature="fd0 lock"
          body="Zeroize the agent's in-memory keys and exit. Vault on disk stays sealed."
        />

        <h3
          class="text-sm tracking-widest uppercase mt-9 mb-3 font-medium"
          style={`color:${C.fg};`}
        >
          Scopes & secrets
        </h3>
        <Cmd
          signature="fd0 scope create --label <name>"
          body="Create an empty scope with a fresh OEK. The scope is yours alone until you add members."
          example={`$ fd0 scope create --label work
✓ scope work created (s_01h…)`}
        />
        <Cmd
          signature="fd0 set <NAME> <value> [--scope <s>]"
          body="Store a secret. Without --scope, uses your default."
          example={`$ fd0 set DEPLOY_KEY "ghp_xxx" --scope work`}
        />
        <Cmd
          signature="fd0 get [<NAME>] [--scope <s>]"
          body="Retrieve a secret. Without a name, opens fuzzy search across all scopes."
          example={`$ fd0 get DEPLOY_KEY
ghp_xxxxxxxxxxxxxxxxxxxx`}
        />
        <Cmd
          signature="fd0 copy <NAME> [--scope <s>] [--clear-after=30s]"
          body="Copy to clipboard with a configurable auto-clear timeout."
        />
        <Cmd
          signature="fd0 ls [--scope <s>]"
          body="List secrets across all scopes (or one). Names only — values stay in the vault."
        />
        <Cmd
          signature="fd0 rm <NAME> [--scope <s>]"
          body="Remove a secret. Writes a tombstone event; the bytes vanish on the next compaction."
        />

        <h3
          class="text-sm tracking-widest uppercase mt-9 mb-3 font-medium"
          style={`color:${C.fg};`}
        >
          Cards & membership
        </h3>
        <Cmd
          signature="fd0 card export"
          body="Print your shareable card (fd0://card/…) to stdout and the safety number to stderr. Show the safety number out-of-band when a teammate pins it."
        />
        <Cmd
          signature="fd0 card import <fd0://card/…> --label <name>"
          body="Pin a teammate's card. Pass --yes to skip the safety-number confirmation."
        />
        <Cmd
          signature="fd0 scope add-member <label> --scope <s>"
          body="Wrap the scope OEK to the named card and append a member.change event."
        />
        <Cmd
          signature="fd0 scope remove-member <label> --scope <s>"
          body="Rotate the scope OEK so the named card can no longer decrypt subsequent writes."
        />

        <h3
          class="text-sm tracking-widest uppercase mt-9 mb-3 font-medium"
          style={`color:${C.fg};`}
        >
          Auth methods
        </h3>
        <Cmd
          signature="fd0 auth add --yubikey [--touch=always|cached|never]"
          body="Enroll a YubiKey (slot 9d, X25519) as an unlock method. Touch policy defaults to always. Build with -tags=yubikey."
        />
        <Cmd
          signature="fd0 auth list"
          body="List enrolled methods with their ids and policies."
        />
        <Cmd
          signature="fd0 auth remove <method_id>"
          body="Remove an auth method. Refuses if it's the only one — removing the last method would seal the vault permanently."
        />

        <h3
          class="text-sm tracking-widest uppercase mt-9 mb-3 font-medium"
          style={`color:${C.fg};`}
        >
          Sync & operations
        </h3>
        <Cmd
          signature="fd0 sync"
          body="Push local events to the configured server, pull what's new, verify the returned STH against the pinned server pubkey and witness cosign."
          example={`$ fd0 sync
→ POST /v1/sync  push=3
← 200 OK  pull=0  sth=cosigned@43
✓ STH verified`}
        />
        <Cmd
          signature="fd0 doctor"
          body="Audit local state — vault integrity, chain tips, OEK consistency, no orphan files. Exits non-zero on any issue."
        />
        <Cmd
          signature="fd0 recovery export <file>"
          body="Encrypted backup of super_priv under a separate recovery passphrase. Store offline."
        />
        <Cmd
          signature="fd0 recovery import <file>"
          body="Restore identity on a fresh device. After import, fd0 sync auto-discovers your scope memberships."
        />
      </div>
    </section>

    {/* ─── server ────────────────────────────────────────────────────── */}
    <section class="px-6 md:px-10 py-16 max-w-6xl mx-auto">
      <SectionHead
        id="server"
        kicker="03 · Server"
        title="Self-host with Docker, or use the hosted fd0.sh."
        body={`The recommended path is the docker-compose blocks in deploy/. To use the hosted instance instead, skip this section — the client defaults to api.fd0.sh + api2.fd0.sh, no extra config needed.`}
      />

      <div class="grid md:grid-cols-2 gap-4">
        <div>
          <div class="text-xs mb-2" style={`color:${C.dim};`}>
            deploy/server/compose.yml — env
          </div>
          <div
            class="p-4 text-[13px] leading-[1.6]"
            style={`background:${C.bgRaised};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <Shell>{`FD0_METRICS_TOKEN=<openssl rand -hex 32>

# Multi-server (optional)
# FD0_LABEL=primary
# FD0_PEERS=https://your-replica.example

# Defaults shown
# FD0_BIND=:4048
# FD0_DB=/data/fd0.db
# FD0_RATELIMIT_WRITES_PER_MIN=60
# FD0_RATELIMIT_REGISTER_PER_HOUR=5`}</Shell>
          </div>
        </div>
        <div>
          <div class="text-xs mb-2" style={`color:${C.dim};`}>
            Service lifecycle
          </div>
          <div
            class="p-4 text-[13px] leading-[1.6]"
            style={`background:${C.bgRaised};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <Shell>{`$ cd deploy/server
$ METRICS_TOKEN=$(openssl rand -hex 32) docker compose up -d
$ docker compose logs -f fd0-server

# upgrade
$ docker compose pull
$ docker compose up -d`}</Shell>
          </div>
        </div>
      </div>

      <p class="text-sm mt-7 leading-relaxed max-w-3xl" style={`color:${C.dim};`}>
        Put your own TLS terminator in front (Caddy, Traefik, nginx,
        Cloudflare, …). The full production recipe with replicas,
        mutual peering, ACME, witnesses, backups, and key rotation
        lives in{" "}
        <span style={`color:${C.acc};font-family:${FONT_MONO};`}>docs/HOSTING.md</span>{" "}
        — that's how fd0.sh itself runs.
      </p>
    </section>

    {/* ─── yubikey ───────────────────────────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-16 border-y"
      style={`border-color:${C.border};background:${C.bgRaised}99;`}
    >
      <div class="max-w-6xl mx-auto">
        <SectionHead
          id="yubikey"
          kicker="04 · YubiKey"
          title="Hardware-backed unlock via PIV slot 9d."
          body="On-card X25519 ECDH; the slot private key never leaves the device. Requires firmware 5.7 or later. Build the client with -tags=yubikey."
        />
        <div
          class="p-4 text-[13px] leading-[1.6] max-w-3xl"
          style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
        >
          <Shell>{`$ fd0 auth add --yubikey --touch=never
✓ YubiKey detected: Yubico YubiKey OTP+FIDO+CCID
Set a PIN? [y/N]: y
Enter PIN (6-8 ASCII): ……
✓ added YubiKey auth method am_01KR… (policy: PIN+touch(none))

$ fd0 lock
$ fd0 unlock --method=yubikey
YubiKey PIN (empty for touch-only): ……
Touch your YubiKey if it blinks…
✓ vault unlocked (yubikey)`}</Shell>
        </div>
        <p class="text-sm mt-5 leading-relaxed max-w-3xl" style={`color:${C.dim};`}>
          On multi-reader hosts,{" "}
          <span style={`color:${C.acc};font-family:${FONT_MONO};`}>
            FD0_YUBIKEY_CARD=&lt;substring&gt;
          </span>{" "}
          picks the right reader by name. Without the env var, fd0
          refuses to act when more than one YubiKey-shaped reader is
          present — to avoid acting on the wrong card.
        </p>
      </div>
    </section>

    {/* ─── sync ──────────────────────────────────────────────────────── */}
    <section class="px-6 md:px-10 py-16 max-w-6xl mx-auto">
      <SectionHead
        id="sync"
        kicker="05 · Sync"
        title="One command. Multi-device, concurrent-write safe."
        body="Sync is the only command that talks to the server. Everything else is local."
      />

      <div class="grid md:grid-cols-2 gap-8 mt-4">
        <div>
          <div class="text-xs mb-2" style={`color:${C.dim};`}>
            Manual
          </div>
          <div
            class="p-4 text-[13px] leading-[1.6]"
            style={`background:${C.bgRaised};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <Shell>{`$ fd0 sync`}</Shell>
          </div>
        </div>
        <div>
          <div class="text-xs mb-2" style={`color:${C.dim};`}>
            Automatic — ~/.fd0/config.toml
          </div>
          <div
            class="p-4 text-[13px] leading-[1.6]"
            style={`background:${C.bgRaised};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <Shell>{`[sync]
server    = "https://fd0.example.com"
interval  = "1h"
on_unlock = true`}</Shell>
          </div>
        </div>
      </div>

      <p class="text-sm mt-7 leading-relaxed max-w-3xl" style={`color:${C.dim};`}>
        Concurrent writes from multiple devices auto-retry against the
        current chain tip. The server returns{" "}
        <span style={`color:${C.acc};`}>409 divergence</span> for stale
        pushes; the client refreshes, re-signs, and retries up to three
        times by default. Linear log with optimistic concurrency — not
        CRDT commutativity.
      </p>
    </section>

    {/* ─── recovery ──────────────────────────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-16 border-y"
      style={`border-color:${C.border};background:${C.bgRaised}99;`}
    >
      <div class="max-w-6xl mx-auto">
        <SectionHead
          id="recovery"
          kicker="06 · Recovery"
          title="Restore identity on a fresh device."
          body="Recovery is a separate offline file sealed under its own passphrase. Treat both the file and the passphrase as full credentials."
        />
        <div
          class="p-4 text-[13px] leading-[1.6] max-w-3xl"
          style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
        >
          <Shell>{`# export — do this once, store offline
$ fd0 recovery export ~/recovery.cbor
Recovery passphrase: …
Confirm recovery passphrase: …
✓ recovery file written to ~/recovery.cbor

# on a fresh device — restore + sync
$ fd0 recovery import ~/recovery.cbor
Recovery passphrase: …
Choose new device passphrase: …
✓ identity restored
$ fd0 unlock && fd0 sync   # auto-discovers scope memberships`}</Shell>
        </div>
      </div>
    </section>

    <Footer />
  </div>
);

export default ssr(async (c) => {
  c.get("page").title = "fd0 — Documentation";
  return () => <Docs />;
});
