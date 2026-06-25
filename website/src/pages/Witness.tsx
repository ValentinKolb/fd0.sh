/**
 * /witness — public transparency-log dashboard.
 *
 * Server-side fetches the live state of the official fd0-witness:
 *   - /v1/server-info  → pubkey + version
 *   - /v1/observed/{server_b64}  → all chains the witness has archived
 *     for the pinned server, with max tree size, cosign count, and
 *     equivocation flag per chain
 *
 * Configuration via env (defaults sane for the production deploy):
 *   FD0_WITNESS_URL = "https://witness.fd0.sh"
 *   FD0_SERVER_URL  = "https://fd0.sh"      (the server the witness watches)
 *
 * The snapshot is cached in-memory for 30s (see lib/witness-client.ts).
 * If the witness is unreachable we render the last good snapshot tagged
 * as stale, so the page never goes blank.
 */

import { ssr } from "../../config";
import { Shell } from "../lib/shell";
import { C, FONT_SANS, FONT_MONO, Nav, Footer } from "../lib/chrome";
import {
  getWitnessSnapshot,
  bytesToHex,
  type WitnessSnapshot,
  type ObservedChain,
} from "../lib/witness-client";

// Defaults match the deploy/compose.yml service names so the website
// pod resolves the witness via the docker network (no TLS round-trip
// per render). SERVER_URL is what's rendered to users for `fd0 sync`,
// so it must be the PUBLIC hostname — override per deployment.
const WITNESS_URL = process.env.FD0_WITNESS_URL ?? "http://fd0-witness:4049";
const SERVER_URL = process.env.FD0_SERVER_URL ?? "https://api.fd0.sh";

const StatusPill = (p: { state: "healthy" | "stale" | "down" }) => {
  const map = {
    healthy: { color: C.sage, label: "HEALTHY" },
    stale: { color: C.acc, label: "STALE" },
    down: { color: "#d36050", label: "UNREACHABLE" },
  };
  const m = map[p.state];
  return (
    <span
      class="inline-flex items-center gap-2 px-3 py-1 text-[11px] tracking-widest uppercase"
      style={`color:${m.color};border:1px solid ${m.color}55;background:${m.color}11;`}
    >
      <span
        class="inline-block w-1.5 h-1.5 rounded-full"
        style={`background:${m.color};`}
      />
      {m.label}
    </span>
  );
};

const Card = (p: { label: string; aside?: string; children: any }) => (
  <section
    class="p-7"
    style={`background:${C.bgRaised};border:1px solid ${C.border};`}
  >
    <div class="flex items-baseline justify-between mb-4">
      <div
        class="text-[11px] tracking-[0.18em] uppercase"
        style={`color:${C.acc};`}
      >
        {p.label}
      </div>
      {p.aside ? (
        <div class="text-[11px]" style={`color:${C.dim};`}>
          {p.aside}
        </div>
      ) : null}
    </div>
    {p.children}
  </section>
);

const truncHex = (s: string, n = 12) =>
  s.length <= 2 * n + 1 ? s : `${s.slice(0, n)}…${s.slice(-n)}`;

const RelTime = (p: { ms: number }) => {
  const dt = Math.max(0, Date.now() - p.ms);
  const s = Math.floor(dt / 1000);
  if (s < 60) return <>{s}s ago</>;
  const m = Math.floor(s / 60);
  if (m < 60) return <>{m}m ago</>;
  const h = Math.floor(m / 60);
  if (h < 48) return <>{h}h ago</>;
  return <>{Math.floor(h / 24)}d ago</>;
};

const ChainRow = (p: { chain: ObservedChain }) => (
  <div
    class="grid grid-cols-[1fr_8rem_8rem_8rem] gap-x-4 py-3 text-[13px]"
    style={`border-top:1px solid ${C.border};`}
  >
    <span
      class="break-all"
      style={`color:${C.fg};font-family:${FONT_MONO};`}
    >
      {p.chain.chain_id}
    </span>
    <span
      class="text-right tabular-nums"
      style={`color:${C.dim};font-family:${FONT_MONO};`}
    >
      tree_size={p.chain.max_tree_size}
    </span>
    <span
      class="text-right tabular-nums"
      style={`color:${C.dim};`}
    >
      {p.chain.cosign_count} cosigns
    </span>
    <span class="text-right">
      {p.chain.equivocated ? (
        <span style={`color:#d36050;font-weight:500;`}>⚠ EQUIVOCATED</span>
      ) : (
        <span style={`color:${C.sage};`}>✓ no fork</span>
      )}
    </span>
  </div>
);

const WitnessPage = (p: { snap: WitnessSnapshot }) => {
  const snap = p.snap;
  const ageMin = Math.floor((Date.now() - snap.fetchedAt) / 60000);
  const state: "healthy" | "stale" | "down" = !snap.reachable
    ? snap.info
      ? "stale"
      : "down"
    : "healthy";
  const pubHex =
    snap.info?.witness_pub_hex ??
    (snap.info?.witness_pub ? bytesToHex(snap.info.witness_pub) : null);
  const chains = snap.observed?.chains ?? [];
  const anyEquiv = chains.some((c) => c.equivocated);

  return (
    <div
      class="min-h-screen"
      style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;`}
    >
      <Nav current="witness" />

      <header class="px-6 md:px-10 pt-16 md:pt-24 pb-12 max-w-6xl mx-auto">
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-4"
          style={`color:${C.acc};`}
        >
          Public transparency log witness
        </div>
        <h1 class="text-[2.4rem] md:text-[3rem] leading-[1.05] tracking-tight font-medium">
          Witness for{" "}
          <span style={`color:${C.acc};`}>{snap.serverURL}</span>
        </h1>
        <p class="mt-5 text-lg leading-relaxed max-w-2xl" style={`color:${C.dim};`}>
          Independent observer of the fd0.sh server's signed tree
          heads. Consistency-verified observations are cosigned; fork evidence
          is archived and flagged. Pin the witness pubkey below in your client
          to require its cosign on every sync.
        </p>
        <div class="mt-7 flex flex-wrap items-center gap-3 text-sm">
          <StatusPill state={state} />
          <span style={`color:${C.dim};`}>
            {snap.fetchedAt === 0 ? (
              "no successful poll yet"
            ) : (
              <>
                last refresh <RelTime ms={snap.fetchedAt} />
              </>
            )}
          </span>
          {snap.error ? (
            <span style={`color:#d36050;font-family:${FONT_MONO};`}>
              {snap.error}
            </span>
          ) : null}
        </div>
      </header>

      <div class="px-6 md:px-10 max-w-6xl mx-auto flex flex-col gap-5 pb-14">
        {anyEquiv ? (
          <div
            class="p-5 text-sm"
            style={`background:#d3605020;border:1px solid #d36050;color:${C.fg};`}
          >
            <div class="font-medium mb-1" style="color:#d36050;">
              ⚠ Equivocation detected
            </div>
            One or more chains below have divergent STHs archived. The
            server published two distinct roots at the same tree_size.
            Pin a second independent witness if you rely on the
            transparency guarantee.
          </div>
        ) : null}

        <Card label="Witness identity" aside="pin this">
          <div class="flex flex-col gap-3 text-sm">
            <Row k="URL">
              <a href={snap.witnessURL} style={`color:${C.acc};`}>
                {snap.witnessURL}
              </a>
            </Row>
            <Row k="Pubkey (ed25519)">
              <span style={`font-family:${FONT_MONO};`}>
                {pubHex ? truncHex(pubHex, 16) : <em>unavailable</em>}
              </span>
            </Row>
            <Row k="Domain">
              <span style={`font-family:${FONT_MONO};`}>
                fd0-witness-cosign-v1
              </span>
            </Row>
          </div>
          <div class="mt-5 text-xs" style={`color:${C.dim};`}>
            Add to <span style={`color:${C.acc};`}>~/.fd0/config.toml</span>:
          </div>
          <div
            class="mt-2 p-4 text-[13px] leading-[1.55]"
            style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <Shell>{`[witness]
url    = "${snap.witnessURL}"
pubkey = "${pubHex ?? "<pubkey here>"}"
required = true`}</Shell>
          </div>
        </Card>

        <Card
          label={`Observed chains (${chains.length})`}
          aside={`watching ${snap.serverURL}`}
        >
          {chains.length === 0 ? (
            <div class="text-sm" style={`color:${C.dim};`}>
              Witness has not archived any chains yet — the server has
              had no syncs since the witness was deployed, or the
              witness has not finished its first polling cycle.
            </div>
          ) : (
            <div>
              <div
                class="grid grid-cols-[1fr_8rem_8rem_8rem] gap-x-4 pb-2 text-[10px] tracking-widest uppercase"
                style={`color:${C.dim};`}
              >
                <span>Chain ID</span>
                <span class="text-right">Tree size</span>
                <span class="text-right">Cosigns</span>
                <span class="text-right">Status</span>
              </div>
              {chains.map((c) => (
                <ChainRow chain={c} />
              ))}
            </div>
          )}
        </Card>

        <Card label="Verify yourself" aside="curl + jq">
          <p
            class="text-sm leading-relaxed mb-4"
            style={`color:${C.dim};`}
          >
            The witness API is read-only and unauthenticated. Pull any
            STH and compare against what the server gave your client —
            the cosign should match.
          </p>
          <div
            class="p-4 text-[13px] leading-[1.55]"
            style={`background:${C.bg};border:1px solid ${C.border};font-family:${FONT_MONO};`}
          >
            <Shell>{`$ curl -sS ${snap.witnessURL}/v1/server-info | cbor2json
{
  "witness_pub":     "0x${pubHex ? pubHex.slice(0, 16) + "..." : "...."}",
  "witness_pub_hex": "${pubHex ? pubHex.slice(0, 16) + "..." : "...."}"
}

# All chains the witness has archived for ${snap.serverURL}
$ curl -sS ${snap.witnessURL}/v1/observed/$(echo -n "${snap.serverURL}" | basenc --base64url -w0 | tr -d '=')`}</Shell>
          </div>
        </Card>

        <Card label="What this guarantees">
          <p
            class="text-sm leading-relaxed mb-3"
            style={`color:${C.dim};`}
          >
            With the witness pinned in your client and{" "}
            <span style={`color:${C.acc};font-family:${FONT_MONO};`}>
              required = true
            </span>
            , every sync verifies the server's STH against this
            witness's cosign. If the server ever publishes a fork — two
            distinct root hashes at the same tree_size — the witness
            flags equivocation and{" "}
            <span style={`color:${C.acc};`}>
              your client refuses the sync
            </span>
            . That makes server-side equivocation cryptographically
            detectable rather than a matter of trust.
          </p>
          <p class="text-sm leading-relaxed" style={`color:${C.dim};`}>
            Run your own witness:{" "}
            <a
              href="https://github.com/ValentinKolb/fd0.sh/blob/main/docs/TRANSLOG.md#8"
              style={`color:${C.acc};`}
            >
              docs/TRANSLOG.md §8
            </a>
            . The more independent witnesses, the harder undetected
            equivocation becomes.
          </p>
        </Card>
      </div>

      <Footer />
    </div>
  );
};

const Row = (p: { k: string; children: any }) => (
  <div class="grid grid-cols-[10rem_1fr] gap-x-4 items-baseline">
    <span class="text-[11px] tracking-widest uppercase" style={`color:${C.dim};`}>
      {p.k}
    </span>
    <span>{p.children}</span>
  </div>
);

export default ssr(async (c) => {
  const page = c.get("page");
  page.title = "fd0 — Public Witness";
  page.description =
    "Live state of the official fd0 transparency-log witness. Pubkey, observed chains, equivocation status.";
  const snap = await getWitnessSnapshot(WITNESS_URL, SERVER_URL);
  return () => <WitnessPage snap={snap} />;
});
