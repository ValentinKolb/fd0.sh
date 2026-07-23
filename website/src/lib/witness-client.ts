/**
 * Tiny client for the fd0-witness HTTP API.
 *
 * Used by the /witness page to fetch live state from the official
 * witness at FD0_WITNESS_URL (default https://witness.fd0.sh). Bun's
 * fetch + the cbor-x decoder do all the work; the only fd0-specific
 * bit is the base64url encoding of the server URL that lives in the
 * path of /v1/observed/{server_b64} etc.
 *
 * In-memory cache with a TTL keeps the witness from being hit on
 * every page render. Stale-while-error: if a refresh fails, we serve
 * the last successful snapshot with a `staleSince` marker so the
 * page can show "last refreshed N minutes ago".
 */

import { decode as decodeCbor } from "cbor-x";

export type ServerInfo = {
  witness_pub: Uint8Array;
  witness_pub_hex: string;
};

export type ObservedChain = {
  chain_id: string;
  max_tree_size: number;
  cosign_count: number;
  equivocated: boolean;
  consistency_failure_count: number;
};

export type Observed = {
  server_url: string;
  chains: ObservedChain[];
};

export type WitnessSnapshot = {
  fetchedAt: number; // unix ms
  reachable: boolean;
  witnessURL: string;
  serverURL: string;
  info: ServerInfo | null;
  observed: Observed | null;
  error: string | null;
};

const CACHE_TTL_MS = 30_000;
const MAX_WITNESS_RESPONSE_BYTES = 1 << 20;

let cached: WitnessSnapshot | null = null;
let pending: Promise<WitnessSnapshot> | null = null;

/**
 * Returns the current snapshot, refreshing from the witness if the
 * cached one is older than CACHE_TTL_MS. Concurrent callers share the
 * same pending request — no thundering-herd on the witness.
 */
export async function getWitnessSnapshot(
  witnessURL: string,
  serverURL: string,
): Promise<WitnessSnapshot> {
  const now = Date.now();
  if (cached && now - cached.fetchedAt < CACHE_TTL_MS) {
    return cached;
  }
  if (pending) return pending;

  pending = fetchSnapshot(witnessURL, serverURL)
    .then((snap) => {
      cached = snap;
      pending = null;
      return snap;
    })
    .catch((err) => {
      // Refresh failed. Serve the previous snapshot tagged as stale.
      const fallback: WitnessSnapshot = cached ?? {
        fetchedAt: 0,
        reachable: false,
        witnessURL,
        serverURL,
        info: null,
        observed: null,
        error: String(err?.message ?? err),
      };
      pending = null;
      return { ...fallback, reachable: false, error: String(err?.message ?? err) };
    });
  return pending;
}

async function fetchSnapshot(
  witnessURL: string,
  serverURL: string,
): Promise<WitnessSnapshot> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 4000);
  try {
    const [info, observed] = await Promise.all([
      fetchCbor<ServerInfo>(`${witnessURL}/v1/server-info`, ac.signal),
      fetchCbor<Observed>(
        `${witnessURL}/v1/observed/${base64urlEncode(serverURL)}`,
        ac.signal,
      ),
    ]);
    return {
      fetchedAt: Date.now(),
      reachable: true,
      witnessURL,
      serverURL,
      info,
      observed,
      error: null,
    };
  } finally {
    clearTimeout(t);
  }
}

export async function fetchCbor<T>(url: string, signal: AbortSignal): Promise<T> {
  const res = await fetch(url, {
    signal,
    redirect: "manual",
    headers: { Accept: "application/cbor" },
  });
  if (!res.ok) {
    throw new Error(`${url} → ${res.status} ${res.statusText}`);
  }
  const contentLength = Number(res.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_WITNESS_RESPONSE_BYTES) {
    throw new Error(`${url} → response exceeds ${MAX_WITNESS_RESPONSE_BYTES} bytes`);
  }
  if (!res.body) {
    throw new Error(`${url} → empty response body`);
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_WITNESS_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error(`${url} → response exceeds ${MAX_WITNESS_RESPONSE_BYTES} bytes`);
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return decodeCbor(buf) as T;
}

function base64urlEncode(s: string): string {
  // btoa works on bytes; assume URL is ASCII (fd0-witness uses
  // base64.RawURLEncoding on the byte representation).
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/** Bytes → hex (for displaying the witness pubkey if hex isn't pre-encoded). */
export function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
