/**
 * /spec/* — Protocol-level specification, split per topic with the
 * playful "spec" sidebar (hex-numbered sections, glyphs, live dot).
 *
 * The page split lets each spec subsection deep-link cleanly. The
 * canonical text remains in docs/*.md on GitHub; each subpage carries
 * a "→ normative spec on GitHub" link to the matching markdown source.
 */

import { setPageSeo, ssr } from "../../config";
import { Shell } from "../lib/shell";
import { C, FONT_MONO, SpecLayout, SPEC_NAV } from "../lib/chrome";

/* ─── shared spec primitives ───────────────────────────────────── */

const SubHead = (p: { children: any }) => (
  <h2
    class="text-base tracking-widest uppercase mt-12 mb-3 font-medium"
    style={`color:${C.fg};`}
  >
    {p.children}
  </h2>
);

const Para = (p: { children: any }) => (
  <p class="text-[15px] leading-[1.72] my-4" style={`color:${C.dim};`}>
    {p.children}
  </p>
);

const Term = (p: { children: any }) => (
  <span class="fd0-mono" style={`color:${C.acc};font-family:${FONT_MONO};`}>
    {p.children}
  </span>
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

/* ─── overview ─────────────────────────────────────────────────── */

const OverviewBody = () => (
  <>
    <Para>
      Readable walk through the wire format, cryptographic
      constructions, on-disk layout, sync protocol, transparency log,
      and threat model. The canonical text lives in{" "}
      <a
        href="https://github.com/k2b-dev/fd0.sh/tree/main/docs"
        style={`color:${C.acc};`}
      >
        docs/*.md
      </a>{" "}
      in the repository — when this page and the markdown disagree, the
      markdown wins.
    </Para>

    <div class="grid sm:grid-cols-2 gap-4 mt-8">
      {SPEC_NAV.filter((s) => s.key !== "overview").map((s) => (
        <a
          href={s.href}
          class="block p-4"
          style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.fg};`}
        >
          <div class="flex items-center gap-2 mb-1">
            <span
              class="text-[11px] px-1.5 py-0.5"
              style={`color:${C.acc};font-family:${FONT_MONO};background:${C.acc}14;border:1px solid ${C.acc}33;`}
            >
              {s.hex}
            </span>
            <span style={`color:${C.acc};`}>{s.glyph}</span>
            <span class="font-medium">{s.label}</span>
          </div>
        </a>
      ))}
    </div>

    <SubHead>Normative texts</SubHead>
    <Para>
      Five markdown specs, versioned with the binaries. This page
      summarises; the markdown is authoritative.
    </Para>
    <div class="grid sm:grid-cols-2 gap-3 mt-4">
      {[
        ["PROTOCOL", "Wire format · signatures · derivation"],
        ["API", "HTTP endpoints · status codes · rate limits"],
        ["STORAGE", "Vault layout · chain files · atomic writes"],
        ["TRANSLOG", "Tree heads · witness · equivocation"],
        ["THREATS", "Catalogue · mitigations · residual risks"],
      ].map(([k, sub]) => (
        <a
          href={`https://github.com/k2b-dev/fd0.sh/blob/main/docs/${k}.md`}
          class="p-4"
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

    <SubHead>Engineering references</SubHead>
    <Para>
      Four more documents ship in the same directory. They describe how the
      implementation is hosted, replicated, measured, and reviewed — useful,
      but not normative for the protocol.
    </Para>
    <div class="grid sm:grid-cols-2 gap-3 mt-4">
      {[
        ["HOSTING", "How fd0.sh itself is run · operator reference"],
        ["REPLICATION", "Single-primary design · DR backup"],
        ["BENCH", "Baselines for translog, replay, unlock"],
        ["CRYPTO_AUDIT", "Internal review of the composition"],
      ].map(([k, sub]) => (
        <a
          href={`https://github.com/k2b-dev/fd0.sh/blob/main/docs/${k}.md`}
          class="p-4"
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
  </>
);

/* ─── 0x01 wire format ─────────────────────────────────────────── */

const WireBody = () => (
  <>
    <Para>
      Every byte that moves between client and server (and every byte
      that's signed) is deterministic CBOR per RFC 8949 §4.2.1. No
      ambiguity, no canonicalisation surprises, no JSON-style
      whitespace games.
    </Para>

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
  </>
);

/* ─── 0x02 cryptography ────────────────────────────────────────── */

const CryptoBody = () => (
  <>
    <Para>
      Identity is Ed25519, encryption is X25519 sealed-box, symmetric
      AEAD is AES-256-GCM, and the passphrase KDF is Argon2id. Standard
      constructions throughout — no bespoke primitives, no in-house crypto.
    </Para>

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

    <SubHead>Encryption — X25519 + AES-256-GCM</SubHead>
    <Para>
      For asymmetric flows (sealing the per-scope key to a teammate's
      card, recovery exports), fd0 derives an X25519 public key from
      the Ed25519 identity via the standard birational map and uses
      a libsodium-compatible sealed-box. Symmetric encryption (vault
      body, AEAD-sealed secrets) uses AES-256-GCM with 12-byte random
      nonces and the domain string as the associated data.
    </Para>

    <SubHead>YubiKey-PIV X25519</SubHead>
    <Para>
      On firmware ≥ 5.7, slot 9d holds an on-card X25519 keypair
      generated and bound to the card. fd0 wraps the symmetric vault
      key to that public key via ECDH; unwrap requires the card to
      perform the ECDH op on-chip. The slot private key never leaves
      the device. Optional touch + PIN policies apply per unwrap.
    </Para>

    <SubHead>Determinism vs. malleability</SubHead>
    <Para>
      Ed25519 signatures are deterministic. AEAD nonces are random per
      encryption, so the same plaintext under the same key produces a
      fresh ciphertext every time — but the determinism of the
      signature input means two clients signing the same event over
      the same prev_hash produce byte-identical signatures, simplifying
      replay detection.
    </Para>
  </>
);

/* ─── 0x03 storage ─────────────────────────────────────────────── */

const StorageBody = () => (
  <>
    <Para>
      The client uses plain append-only CBOR files; the server uses
      SQLite. Both stores hold byte-identical events — there is no
      client/server format divergence.
    </Para>

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
      The header is unauthenticated metadata; the body is AEAD-sealed
      under a payload key that is itself wrapped under each active
      auth method. Auth methods are independent — adding a YubiKey to
      an existing passphrase-only vault doesn't re-encrypt the body,
      only adds a new wrap.
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
      appends, verified history repair, tail-truncation, vault re-seal, scope unlink,
      and config writes within a single client.
    </Para>

    <SubHead>Server layout — SQLite</SubHead>
    <Para>
      One database file with tables for users (super_pub → short_id),
      user events, scope events, and STHs. The server stores
      byte-identical CBOR blobs and per-event metadata (seq,
      prev_hash). No plaintext, no derived keys, no decryption
      capability anywhere in the server's code path.
    </Para>
  </>
);

/* ─── 0x04 sync protocol ───────────────────────────────────────── */

const SyncProtoBody = () => (
  <>
    <Para>
      POST /v1/sync pushes new events, pulls anything newer than the
      cursor, and returns the current signed tree head. Per-request
      HTTP auth via Ed25519 over canonical request bytes.
    </Para>

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
      the current tip. The client pulls, applies, re-signs against the
      new tip, and retries. Auto-retry up to N (default 3) before
      surfacing the conflict.
    </Para>

    <SubHead>Idempotency</SubHead>
    <Para>
      <Term>event_id</Term> is content-derived. The server enforces{" "}
      <Term>UNIQUE(event_id)</Term>; replays are accepted as no-ops
      rather than rejected. This makes <Term>fd0 sync</Term> safe to
      run as often as you like — at intervals, on unlock, on network
      reconnect.
    </Para>
  </>
);

/* ─── 0x05 transparency log ────────────────────────────────────── */

const TranslogBody = () => (
  <>
    <Para>
      The transparency log lifts the existing tamper-detection
      guarantee from "any client pulling from cursor=0 can detect
      modification" to "any pair of clients (or a third-party
      observer) can detect equivocation between divergent server
      views."
    </Para>

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
      The witness binary <Term>fd0-witness</Term> runs on a host
      independent of the server. It polls the server's STH, verifies
      tree consistency against the previous head, and emits a{" "}
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
  </>
);

/* ─── 0x06 threat model ────────────────────────────────────────── */

const ThreatsBody = () => (
  <>
    <Para>
      Each threat T## is catalogued with status, mitigation, and a
      code reference. A representative slice below; the full
      catalogue lives in docs/THREATS.md.
    </Para>

    <div
      class="my-7"
      style={`background:${C.bgRaised};border:1px solid ${C.border};padding:1.25rem 1.5rem;`}
    >
      <ThreatRow
        id="T02"
        name="Stolen vault file → offline brute-force"
        status="mitigated"
        mitigation="The vault body is AEAD-sealed under a key wrapped to each enrolled method. Offline resistance is Argon2id at M=64 MiB / T=3, so it rests on the strongest method you enrol — a YubiKey removes the guessing game entirely."
      />
      <ThreatRow
        id="T07"
        name="Same-UID malware reads agent memory"
        status="mitigated"
        mitigation="super_priv lives mlocked inside fd0-agent and is wiped on lock, idle timeout and exit. An attacker already running as you is not fully excluded — this narrows the window rather than closing it."
      />
      <ThreatRow
        id="T26"
        name="Forged member.change (unsigned author)"
        status="mitigated"
        mitigation="Every event is signed by its author over a domain-separated prefix, and the server validates authorship before storing. The server holds no member signing key."
      />
      <ThreatRow
        id="T27"
        name="Foreign-author event splice"
        status="mitigated"
        mitigation="Replay checks each event's author against the member set as of that point in the chain, so a non-member's write is rejected on read even if the server stored it."
      />
      <ThreatRow
        id="T35"
        name="Server equivocation between two clients"
        status="mitigated"
        mitigation="An independent witness cosigns the server's tree head, and clients cross-check it. Two distinct roots at the same tree size are detectable rather than a matter of trust."
      />
      <ThreatRow
        id="T41"
        name="First-fetch checkpoint rollback"
        status="mitigated"
        mitigation="A client with no prior anchor probes for the highest checkpoint before accepting one, so a server cannot quietly seed a new device with an old view."
      />
      <ThreatRow
        id="T06"
        name="Coordinated local rollback (vault + chain)"
        status="accepted"
        mitigation="Replacing vault.enc and ~/.fd0/chains/ together, on your own machine, is outside the model: an attacker with that access already has the device. Single-file rollback is caught (T05)."
      />
      <ThreatRow
        id="T38"
        name="Witness collusion with the server"
        status="accepted"
        mitigation="A witness that colludes stops being an independent check. It still cannot decrypt anything; pinning a second, independently operated witness is what reduces this."
      />
      <ThreatRow
        id="T52"
        name="Metadata side channels"
        status="accepted"
        mitigation="The server learns sizes, timing and access patterns even though it cannot read content. Hiding those needs padding and cover traffic, which fd0 does not currently do."
      />
    </div>

    <p class="text-xs mt-4 leading-relaxed" style={`color:${C.dim};`}>
      The threat-coverage tool (<Term>go run ./tools/threat-coverage</Term>)
      cross-references every T## with a code annotation; CI fails if a
      mitigated threat loses its code reference.
    </p>
  </>
);

/* ─── route exports ────────────────────────────────────────────── */

export const SpecOverview = ssr(async (c) => {
  setPageSeo(c, "spec");
  return () => (
    <SpecLayout current="overview" title="Protocol.">
      <OverviewBody />
    </SpecLayout>
  );
});

export const SpecWire = ssr(async (c) => {
  setPageSeo(c, "specWire");
  return () => (
    <SpecLayout current="wire" title="Deterministic CBOR. Domain-separated signatures.">
      <WireBody />
    </SpecLayout>
  );
});

export const SpecCrypto = ssr(async (c) => {
  setPageSeo(c, "specCrypto");
  return () => (
    <SpecLayout current="crypto" title="Three primitives. One curve family.">
      <CryptoBody />
    </SpecLayout>
  );
});

export const SpecStorage = ssr(async (c) => {
  setPageSeo(c, "specStorage");
  return () => (
    <SpecLayout current="storage" title="One vault. One chain per scope.">
      <StorageBody />
    </SpecLayout>
  );
});

export const SpecSync = ssr(async (c) => {
  setPageSeo(c, "specSync");
  return () => (
    <SpecLayout current="sync" title="One endpoint. Optimistic concurrency.">
      <SyncProtoBody />
    </SpecLayout>
  );
});

export const SpecTranslog = ssr(async (c) => {
  setPageSeo(c, "specTranslog");
  return () => (
    <SpecLayout current="translog" title="RFC 6962 Merkle tree. Witness-cosigned.">
      <TranslogBody />
    </SpecLayout>
  );
});

export const SpecThreats = ssr(async (c) => {
  setPageSeo(c, "specThreats");
  return () => (
    <SpecLayout current="threats" title="What fd0 defends. What it leaves to you.">
      <ThreatsBody />
    </SpecLayout>
  );
});

export default SpecOverview;
