/**
 * /spec — Protocol-level specification, in depth.
 *
 * Companion to /docs. While /docs covers what fd0 the binary does for
 * an operator, this page covers what fd0 the protocol guarantees at
 * the wire level: which CBOR objects flow, what each domain separator
 * binds, what the AEAD/sealed-box constructions are, what the
 * transparency-log invariant looks like, and what the threat model
 * actually says.
 *
 * Each section is the readable companion to one of the canonical
 * specs in docs/*.md on GitHub — those remain the normative text.
 */

import { ssr } from "../../config";
import { Shell } from "../lib/shell";
import { C, FONT_SANS, FONT_MONO, Nav, Footer } from "../lib/chrome";

const SectionHead = (p: { id: string; kicker: string; title: string; body?: string; specLink?: string }) => (
  <div id={p.id} class="mb-10">
    <div class="flex flex-wrap items-baseline justify-between gap-3 mb-3">
      <div
        class="text-[11px] tracking-[0.18em] uppercase"
        style={`color:${C.acc};`}
      >
        {p.kicker}
      </div>
      {p.specLink ? (
        <a
          href={p.specLink}
          class="text-[11px] tracking-widest uppercase"
          style={`color:${C.dim};`}
        >
          → normative spec on GitHub
        </a>
      ) : null}
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

const SubHead = (p: { children: any }) => (
  <h3
    class="text-base tracking-widest uppercase mt-12 mb-3 font-medium"
    style={`color:${C.fg};`}
  >
    {p.children}
  </h3>
);

const Para = (p: { children: any }) => (
  <p class="text-[15px] leading-[1.72] my-4 max-w-3xl" style={`color:${C.dim};`}>
    {p.children}
  </p>
);

const Code = (p: { children: string; title?: string }) => (
  <div
    class="my-5"
    style={`background:${C.bgRaised};border:1px solid ${C.border};`}
  >
    {p.title ? (
      <div
        class="px-4 py-2 text-[11px] tracking-widest uppercase border-b"
        style={`color:${C.dim};border-color:${C.border};`}
      >
        {p.title}
      </div>
    ) : null}
    <div
      class="p-4 text-[12.5px] leading-[1.6]"
      style={`font-family:${FONT_MONO};`}
    >
      <Shell>{p.children}</Shell>
    </div>
  </div>
);

const Term = (p: { children: any }) => (
  <span style={`color:${C.acc};font-family:${FONT_MONO};`}>{p.children}</span>
);

const DomainRow = (p: { domain: string; binds: string }) => (
  <div
    class="grid grid-cols-[16rem_1fr] gap-x-6 py-2.5 text-[13px]"
    style={`border-top:1px solid ${C.border};`}
  >
    <span style={`color:${C.acc};font-family:${FONT_MONO};`}>{p.domain}</span>
    <span style={`color:${C.dim};`}>{p.binds}</span>
  </div>
);

const ThreatRow = (p: { id: string; name: string; status: string; mitigation: string }) => (
  <div
    class="grid grid-cols-[4rem_1fr_8rem] gap-x-4 gap-y-1 py-3 items-start text-[13px]"
    style={`border-top:1px solid ${C.border};`}
  >
    <span style={`color:${C.acc};font-family:${FONT_MONO};`}>{p.id}</span>
    <div>
      <div style={`color:${C.fg};`} class="font-medium mb-0.5">
        {p.name}
      </div>
      <div style={`color:${C.dim};`}>{p.mitigation}</div>
    </div>
    <span
      class="text-[10px] tracking-widest uppercase justify-self-end mt-1"
      style={
        p.status === "mitigated"
          ? `color:${C.sage};`
          : p.status === "accepted"
          ? `color:${C.dim};`
          : `color:${C.acc};`
      }
    >
      {p.status}
    </span>
  </div>
);

const Spec = () => (
  <div
    class="min-h-screen"
    style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;`}
  >
    <Nav current="spec" />

    {/* ─── header ────────────────────────────────────────────────────── */}
    <header class="px-6 md:px-10 pt-16 md:pt-24 pb-12 max-w-6xl mx-auto">
      <div
        class="text-[11px] tracking-[0.18em] uppercase mb-4"
        style={`color:${C.acc};`}
      >
        Specification · v1.0 (frozen)
      </div>
      <h1 class="text-[2.4rem] md:text-[3rem] leading-[1.05] tracking-tight font-medium">
        Protocol.
      </h1>
      <p class="mt-5 text-lg leading-relaxed max-w-2xl" style={`color:${C.dim};`}>
        Readable walk through the wire format, cryptographic
        constructions, on-disk layout, sync protocol, transparency log,
        and threat model. The canonical text lives in{" "}
        <a
          href="https://github.com/ValentinKolb/fd0.sh/tree/main/docs"
          style={`color:${C.acc};`}
        >
          docs/*.md
        </a>{" "}
        in the repository.
      </p>

      {/* jump nav */}
      <nav
        class="mt-10 flex flex-wrap gap-x-5 gap-y-2 text-sm pt-6"
        style={`border-top:1px solid ${C.border};color:${C.dim};`}
      >
        {[
          ["#wire", "Wire format"],
          ["#crypto", "Cryptography"],
          ["#storage", "Storage"],
          ["#sync", "Sync protocol"],
          ["#translog", "Transparency log"],
          ["#threats", "Threat model"],
        ].map(([href, label]) => (
          <a href={href} class="hover:text-white">
            {label}
          </a>
        ))}
      </nav>
    </header>

    {/* ─── wire format ───────────────────────────────────────────────── */}
    <section class="px-6 md:px-10 py-16 max-w-6xl mx-auto">
      <SectionHead
        id="wire"
        kicker="01 · Wire format"
        title="Deterministic CBOR + domain-separated signatures."
        body="Every byte that moves between client and server (and every byte that's signed) is deterministic CBOR per RFC 8949 §4.2.1. No ambiguity, no canonicalisation surprises, no JSON-style whitespace games."
        specLink="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/PROTOCOL.md"
      />

      <SubHead>Determinism rules</SubHead>
      <Para>
        Maps are sorted by key length first, then lexicographically.
        Integers use the shortest encoding (no length-padded majors).
        Strings are UTF-8 NFC. There is exactly one valid CBOR encoding
        for every fd0 object — encode and re-encode produces byte-identical
        output, and that's what gets signed.
      </Para>

      <SubHead>Domain separation</SubHead>
      <Para>
        Every signature is computed over{" "}
        <Term>domain || cbor(object)</Term>; every AEAD AAD carries a
        domain string. A ciphertext or signature valid under one domain
        is invalid under any other. Disjointness (no prefix-equal pair)
        is enforced by{" "}
        <Term>TestDomainSeparatorsDisjoint</Term> in{" "}
        <Term>internal/proto/proto_test.go</Term>.
      </Para>

      <div
        class="my-7"
        style={`background:${C.bgRaised};border:1px solid ${C.border};padding:1.25rem 1.5rem;`}
      >
        <div
          class="text-xs tracking-widest uppercase mb-3"
          style={`color:${C.dim};`}
        >
          Domains in use
        </div>
        <DomainRow domain="fd0-event-v1" binds="ScopeEvent signatures" />
        <DomainRow domain="fd0-user-event-v1" binds="auth.set signatures (user chain)" />
        <DomainRow domain="fd0-card-v1" binds="Identity card signatures" />
        <DomainRow domain="fd0-http-request-v1" binds="Per-request HTTP auth" />
        <DomainRow domain="fd0-encrypted-super-priv-v1" binds="Auth-method AEAD (passphrase/yubikey wrap)" />
        <DomainRow domain="fd0-vault-body-v1" binds="Vault body AAD" />
        <DomainRow domain="fd0-vault-wrap-v1" binds="Vault wrap header AAD" />
        <DomainRow domain="fd0-recovery-key-v1" binds="Recovery file AEAD" />
        <DomainRow domain="fd0-translog-sth-v1" binds="STH signature input" />
        <DomainRow domain="fd0-witness-cosign-v1" binds="Witness cosign input" />
      </div>

      <SubHead>Event chains</SubHead>
      <Para>
        Both the per-user chain (auth methods) and the per-scope chain
        (members + secrets) are linear append-only signed logs. Each
        event commits to its predecessor by{" "}
        <Term>prev_hash = SHA-256(cbor(prev.SignedPrefix))</Term>. The
        first event has <Term>prev_hash = nil</Term>; the server checks
        the chain on every push.
      </Para>

      <Code title="ScopeEvent — internal/proto/types.go">{`ScopeEvent = {
  signed_prefix : SignedPrefix,
  signature     : Signature,
}

SignedPrefix = {
  kind           : "member.change" / "secret.set",
  scope          : tstr / nil,                ; nil iff genesis
  prev_hash      : bstr .size 32 / nil,
  author         : bstr .size 32,             ; signer super_pub
  seq            : uint,
  oek_version    : uint,
  key_deliveries : [* KeyDelivery],           ; non-empty for member.change
  payload        : <kind-specific>,
}

event_id       = "e_" || base32(truncate_128(SHA-256(cbor(SignedPrefix))))
prev_hash[N+1] = SHA-256(cbor(SignedPrefix[N]))`}</Code>
    </section>

    {/* ─── cryptography ──────────────────────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-16 border-t"
      style={`border-color:${C.border};background:${C.bgRaised}99;`}
    >
      <div class="max-w-6xl mx-auto">
        <SectionHead
          id="crypto"
          kicker="02 · Cryptography"
          title="Three primitives, one curve family."
          body="Identity is Ed25519, encryption is X25519 sealed-box, symmetric AEAD is XChaCha20-Poly1305. All libsodium-compatible. No bespoke constructions, no in-house crypto."
          specLink="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/PROTOCOL.md#cryptography"
        />

        <SubHead>Identity — Ed25519</SubHead>
        <Para>
          Every device has a single{" "}
          <Term>super_priv / super_pub</Term> Ed25519 keypair generated
          at <Term>fd0 init</Term>. <Term>super_pub</Term> is the account
          identifier (32 bytes, displayed as{" "}
          <Term>upIamMlsgn…</Term> in base32). <Term>super_priv</Term> never
          leaves the device unencrypted; the vault file holds it sealed
          under each enrolled auth method.
        </Para>

        <SubHead>Encryption — X25519 + XChaCha20-Poly1305</SubHead>
        <Para>
          For asymmetric flows (sealing the per-scope key to a
          teammate's card, recovery exports), fd0 derives an X25519
          public key from the Ed25519 identity via the standard
          birational map and uses libsodium-compatible sealed-box.
          Symmetric encryption (vault body, AEAD-sealed secrets) uses
          XChaCha20-Poly1305 with 24-byte random nonces and the domain
          string as the associated data.
        </Para>

        <SubHead>YubiKey-PIV X25519</SubHead>
        <Para>
          On firmware ≥ 5.7, slot 9d holds an on-card X25519 keypair
          generated and bound to the card. fd0 wraps the symmetric vault
          key to that public key via ECDH; unwrap requires the card to
          perform the ECDH op on-chip. The slot private key never
          leaves the device. Optional touch + PIN policies apply per
          unwrap.
        </Para>

        <SubHead>Determinism vs. malleability</SubHead>
        <Para>
          Ed25519 signatures are deterministic. AEAD nonces are random
          per encryption, so the same plaintext under the same key
          produces a fresh ciphertext every time — but the determinism
          of the signature input means two clients signing the same
          event over the same prev_hash produce byte-identical
          signatures, simplifying replay detection.
        </Para>
      </div>
    </section>

    {/* ─── storage ───────────────────────────────────────────────────── */}
    <section class="px-6 md:px-10 py-16 max-w-6xl mx-auto">
      <SectionHead
        id="storage"
        kicker="03 · Storage"
        title="One vault file, one chain file per scope."
        body="The client uses plain append-only CBOR files; the server uses SQLite. Both stores hold byte-identical events — there is no client/server format divergence."
        specLink="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/STORAGE.md"
      />

      <SubHead>Client layout — ~/.fd0/</SubHead>
      <Code>{`~/.fd0/
├── vault.enc             # sealed super_priv + per-scope OEKs + chain tips
├── config.toml           # client config (server URL, sync interval)
├── chains/
│   ├── user.cbor         # per-user event chain (auth.set events)
│   └── scope_<id>.cbor   # one per scope, append-only
└── recovery/             # optional, user-managed exports`}</Code>

      <SubHead>vault.enc layout</SubHead>
      <Para>
        The header is unauthenticated metadata; the body is
        AEAD-sealed under a payload key that is itself wrapped under
        each active auth method. Auth methods are independent — adding
        a YubiKey to an existing passphrase-only vault doesn't
        re-encrypt the body, only adds a new wrap.
      </Para>

      <Code title="$ xxd ~/.fd0/vault.enc | head">{`00000000  46 44 30 56 01 01 ba 92  1a 98 c9 6c 82 74 52 f6   |FD0V......l.tR.|
00000010  1a e4 75 dd bb e4 e5 93  8b d4 b5 60 fa a0 b1 41   |..u........\`...A|
00000020  ad b8 73 0a 8b 20 a1 04  20 50 41 53 53 50 48 52   |..s.. .. PASSPHR|
00000030  41 53 45 18 4b 2f 1c d8  3a e9 17 c0 5b 99 9d 4e   |ASE.K/..:...[..N|

  [00..03]  magic "FD0V"
  [04]      version 0x01
  [05..24]  super_pub  32B Ed25519
  [25..27]  wraps.count uvarint
  [28..]    wraps[]: method_id (ULID) · method_type · public_params
                  · wrap_nonce(12) · AEAD-ct`}</Code>

      <SubHead>Atomic writes</SubHead>
      <Para>
        Vault re-seal goes through{" "}
        <Term>vault.enc.tmp → fsync → rename → fsync(parent)</Term>.
        Chain appends go through the same pattern at file granularity.
        An advisory exclusive lock at <Term>~/.fd0/.lock</Term> serialises
        appends, compaction, tail-truncation, vault re-seal, scope
        unlink, and config writes within a single client.
      </Para>

      <SubHead>Server layout — SQLite</SubHead>
      <Para>
        One database file with tables for users (super_pub →
        short_id), user events, scope events, and STHs. The server
        stores byte-identical CBOR blobs and per-event metadata
        (seq, prev_hash). No plaintext, no derived keys, no decryption
        capability anywhere in the server's code path.
      </Para>
    </section>

    {/* ─── sync protocol ─────────────────────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-16 border-t"
      style={`border-color:${C.border};background:${C.bgRaised}99;`}
    >
      <div class="max-w-6xl mx-auto">
        <SectionHead
          id="sync"
          kicker="04 · Sync protocol"
          title="One stateful endpoint. Optimistic concurrency."
          body="POST /v1/sync pushes new events, pulls anything newer than the cursor, and returns the current signed tree head. Per-request HTTP auth via Ed25519 over canonical request bytes."
          specLink="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/API.md"
        />

        <SubHead>Request shape</SubHead>
        <Code>{`POST /v1/sync
Authorization: fd0-http-request-v1 pk=<base64> nonce=<base64> ts=<unix> sig=<base64>
Content-Type: application/cbor

{
  scope        : tstr,
  cursor       : uint,         ; last seq the client has
  push         : [* ScopeEvent],
  pull         : bool,          ; default true
  discover_memberships : bool,  ; optional
}`}</Code>

        <SubHead>Response shape</SubHead>
        <Code>{`200 OK
Content-Type: application/cbor

{
  accepted     : [* event_id],
  pulled       : [* ScopeEvent],
  sth          : SignedTreeHead,
  witness      : Cosign,         ; if witness configured
}`}</Code>

        <SubHead>Optimistic concurrency</SubHead>
        <Para>
          A scope-event push is rejected with{" "}
          <Term>409 divergence</Term> if{" "}
          <Term>prev_hash ≠ scope.tip_hash</Term>. The response includes
          the current tip. The client pulls, applies, re-signs against
          the new tip, and retries. Auto-retry up to N (default 3)
          before surfacing the conflict.
        </Para>

        <SubHead>Idempotency</SubHead>
        <Para>
          <Term>event_id</Term> is content-derived. The server enforces{" "}
          <Term>UNIQUE(event_id)</Term>; replays are accepted as no-ops
          rather than rejected. This makes <Term>fd0 sync</Term> safe to
          run as often as you like — at intervals, on unlock, on
          network reconnect.
        </Para>
      </div>
    </section>

    {/* ─── transparency log ──────────────────────────────────────────── */}
    <section class="px-6 md:px-10 py-16 max-w-6xl mx-auto">
      <SectionHead
        id="translog"
        kicker="05 · Transparency log"
        title="RFC 6962 Merkle tree, signed by the server, cosigned by a witness."
        body="The transparency log lifts the existing tamper-detection guarantee from 'any client pulling from cursor=0 can detect modification' to 'any pair of clients (or a third-party observer) can detect equivocation between divergent server views'."
        specLink="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/TRANSLOG.md"
      />

      <SubHead>One tree per chain</SubHead>
      <Para>
        Leaves are added in the order events are appended; the leaf
        index equals the event's <Term>seq</Term>. Leaf hash is{" "}
        <Term>SHA-256(0x00 || cbor(SignedPrefix))</Term>; internal nodes
        follow RFC 6962 §2.1. The server publishes a fresh{" "}
        <Term>SignedTreeHead</Term> on every accepted append, signed
        with its long-term Ed25519 cosign key.
      </Para>

      <Code title="SignedTreeHead">{`SignedTreeHead = {
  chain_id     : tstr,
  tree_size    : uint,
  root_hash    : bstr .size 32,
  timestamp_ms : uint,
  signature    : Signature,  ; over fd0-translog-sth-v1 || cbor(prefix)
}`}</Code>

      <SubHead>Witness cosign</SubHead>
      <Para>
        The witness binary{" "}
        <Term>fd0-witness</Term> runs on a host independent of the
        server. It polls the server's STH, verifies tree consistency
        against the previous head, and emits a{" "}
        <Term>Cosign</Term> if the head is honest — i.e. a strict
        extension of every prior head it has signed. Divergent heads
        are archived rather than cosigned, surfacing equivocation.
      </Para>

      <Code title="Cosign">{`Cosign = {
  witness_pub  : bstr .size 32,
  chain_id     : tstr,
  tree_size    : uint,
  root_hash    : bstr .size 32,
  observed_ms  : uint,
  signature    : Signature,  ; over fd0-witness-cosign-v1 || cbor(prefix)
}`}</Code>

      <SubHead>First-contact pinning</SubHead>
      <Para>
        On first sync, the client pins the server's cosign public key.
        Subsequent STHs are rejected if signed under a different key.
        The witness pubkey is similarly pinned. Clients can verify each
        other's pins out of band via safety numbers, the same primitive
        used for identity-card verification.
      </Para>
    </section>

    {/* ─── threat model ──────────────────────────────────────────────── */}
    <section
      class="px-6 md:px-10 py-16 border-t"
      style={`border-color:${C.border};background:${C.bgRaised}99;`}
    >
      <div class="max-w-6xl mx-auto">
        <SectionHead
          id="threats"
          kicker="06 · Threat model"
          title="What fd0 defends against, what it leaves to you."
          body="Each threat T## is catalogued with status, mitigation, and a code reference. A representative slice below; the full catalogue lives in docs/THREATS.md."
          specLink="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/THREATS.md"
        />

        <div
          class="my-7"
          style={`background:${C.bgRaised};border:1px solid ${C.border};padding:1.25rem 1.5rem;`}
        >
          <ThreatRow
            id="T03"
            name="Server reads secret plaintext"
            status="mitigated"
            mitigation="Every secret AEAD-sealed under the per-scope OEK before reaching the server. Server-side decryption is impossible: there is no decryption code path."
          />
          <ThreatRow
            id="T07"
            name="Removed member decrypts post-removal writes"
            status="mitigated"
            mitigation="OEK rotates atomically on scope.remove-member. Subsequent secret.set events are sealed under the new OEK, which the removed card cannot unwrap."
          />
          <ThreatRow
            id="T12"
            name="Server forges a chain event"
            status="mitigated"
            mitigation="Every event signed by author's super_priv over fd0-event-v1. Server has no signing capability for member identities."
          />
          <ThreatRow
            id="T15"
            name="YubiKey slot 9d compromise"
            status="mitigated"
            mitigation="X25519 ECDH happens on-card; slot private key never exposed. Touch and PIN policies enforced per unwrap. Loss of physical card requires firmware-level extraction, not in scope."
          />
          <ThreatRow
            id="T22"
            name="Vault file stolen at rest"
            status="mitigated"
            mitigation="Vault body AEAD-sealed under a payload key wrapped to each auth method's key. Offline brute-force resistance depends on the strongest enrolled method (passphrase entropy or YubiKey PIN+touch)."
          />
          <ThreatRow
            id="T35"
            name="Server equivocates (forks the log)"
            status="mitigated"
            mitigation="Independent witness cosign + first-contact pinning. Detection by any client that compares STHs with peers or the witness archive."
          />
          <ThreatRow
            id="T41"
            name="Witness host compromised"
            status="accepted"
            mitigation="Single-witness deployment provides single-point detection. Group-managed witness consortium on the roadmap. A silently-compromised witness reduces detection but does not enable decryption."
          />
          <ThreatRow
            id="T46"
            name="Vault and chain files rolled back together"
            status="accepted"
            mitigation="Coordinated client-side rollback of both vault.enc and ~/.fd0/chains/ is explicitly out of scope. Documented in docs/PROTOCOL.md §6.4."
          />
          <ThreatRow
            id="T52"
            name="Operator coerces a client to publish"
            status="accepted"
            mitigation="Outside the cryptographic threat model. Use of physical security, jurisdictions, and operational controls is left to the deploying organisation."
          />
        </div>

        <p class="text-xs mt-4 leading-relaxed max-w-3xl" style={`color:${C.dim};`}>
          The threat-coverage tool (
          <Term>go run ./tools/threat-coverage</Term>) cross-references
          every T## with a code annotation; CI fails if a mitigated
          threat loses its code reference.
        </p>
      </div>
    </section>

    {/* ─── spec footer ───────────────────────────────────────────────── */}
    <section class="px-6 md:px-10 py-20 max-w-6xl mx-auto">
      <div
        class="p-7 md:p-10"
        style={`background:${C.bgRaised};border:1px solid ${C.border};`}
      >
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-3"
          style={`color:${C.acc};`}
        >
          Normative texts
        </div>
        <h2 class="text-2xl md:text-3xl font-medium tracking-tight mb-3">
          Five Markdown specs. Versioned with the binaries.
        </h2>
        <p class="text-sm leading-relaxed mb-6 max-w-2xl" style={`color:${C.dim};`}>
          This page summarises. The texts below are the authoritative
          specs — when an implementation differs from a spec, the spec
          wins.
        </p>
        <div class="flex flex-wrap gap-3">
          {[
            ["PROTOCOL", "Wire format · signatures · derivation"],
            ["API", "HTTP endpoints · status codes · rate limits"],
            ["STORAGE", "Vault layout · chain files · atomic writes"],
            ["TRANSLOG", "Tree heads · witness · equivocation"],
            ["THREATS", "Catalogue · mitigations · residual risks"],
          ].map(([k, sub]) => (
            <a
              href={`https://github.com/ValentinKolb/fd0.sh/blob/main/docs/${k}.md`}
              class="p-4 transition-colors hover:bg-stone-900 min-w-[14rem]"
              style={`background:${C.bg};border:1px solid ${C.border};`}
            >
              <div
                class="text-sm font-medium mb-1"
                style={`color:${C.acc};font-family:${FONT_MONO};`}
              >
                {k}.md
              </div>
              <div class="text-xs" style={`color:${C.dim};`}>
                {sub}
              </div>
            </a>
          ))}
        </div>
      </div>
    </section>

    <Footer />
  </div>
);

export default ssr(async (c) => {
  c.get("page").title = "fd0 — Specification";
  return () => <Spec />;
});
