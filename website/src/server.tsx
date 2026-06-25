import { Hono } from "hono";
import { logger } from "hono/logger";
import { serveStatic } from "hono/bun";
import { timingSafeEqual } from "crypto";
import { config, routes, SITE_URL } from "../config";
import { ErrorPage, errorPresets } from "./lib/error";
import { html as renderHTML } from "../config";
import {
  DocsOverview,
  DocsConcepts,
  DocsInstall,
  DocsCli,
  DocsSsh,
  DocsTalos,
  DocsSync,
  DocsServer,
  DocsYubikey,
  DocsRecovery,
  DocsTroubleshooting,
} from "./pages/Docs";
import Home from "./pages/Home";
import Impressum from "./pages/Impressum";
import {
  SpecOverview,
  SpecWire,
  SpecCrypto,
  SpecStorage,
  SpecSync,
  SpecTranslog,
  SpecThreats,
} from "./pages/Spec";
import Witness from "./pages/Witness";

const VERSION = process.env.FD0_WEBSITE_VERSION ?? "dev";
const METRICS_TOKEN = (process.env.FD0_WEBSITE_METRICS_TOKEN ?? "").trim();

// ─── tiny in-process metrics ───────────────────────────────────────
//
// We intentionally don't pull a prom-client dep — three counters and
// a histogram are easier to keep in sync with the Go binaries by
// hand-rolling the text-format exposition (it's six fields).
const startedAt = Date.now();
const m = {
  requestsTotal: new Map<string, number>(), // key = "method|path_label|status_class"
  responseBytes: 0,
  inFlight: 0,
  uptime: () => (Date.now() - startedAt) / 1000,
};
const opLabel = (path: string): string => {
  const parts = path.replace(/^\//, "").split("/");
  if (parts.length === 0 || parts[0] === "") return "/";
  if (parts.length === 1) return `/${parts[0]}`;
  if (parts.length >= 3) return `/${parts[0]}/${parts[1]}/*`;
  return `/${parts[0]}/${parts[1]}`;
};
const statusClass = (s: number): string => {
  if (s >= 500) return "5xx";
  if (s >= 400) return "4xx";
  if (s >= 300) return "3xx";
  if (s >= 200) return "2xx";
  return "other";
};
const bumpCounter = (k: string) =>
  m.requestsTotal.set(k, (m.requestsTotal.get(k) ?? 0) + 1);

const renderPrometheus = (): string => {
  const lines: string[] = [];
  lines.push(
    "# HELP fd0_http_requests_total HTTP requests processed by the website.",
  );
  lines.push("# TYPE fd0_http_requests_total counter");
  for (const [key, n] of m.requestsTotal) {
    const [method, op, klass] = key.split("|");
    lines.push(
      `fd0_http_requests_total{service="fd0-website",op="${method} ${op}",status_class="${klass}"} ${n}`,
    );
  }
  lines.push("# HELP fd0_http_in_flight In-flight requests.");
  lines.push("# TYPE fd0_http_in_flight gauge");
  lines.push(`fd0_http_in_flight{service="fd0-website"} ${m.inFlight}`);
  lines.push("# HELP fd0_uptime_seconds Process uptime in seconds.");
  lines.push("# TYPE fd0_uptime_seconds gauge");
  lines.push(`fd0_uptime_seconds{service="fd0-website"} ${m.uptime().toFixed(0)}`);
  lines.push("# HELP fd0_build_info Build identifier (constant 1).");
  lines.push("# TYPE fd0_build_info gauge");
  lines.push(
    `fd0_build_info{service="fd0-website",version="${VERSION}"} 1`,
  );
  return lines.join("\n") + "\n";
};

const checkBearer = (auth: string | undefined, expected: string): boolean => {
  if (!expected) return true; // open mode
  const got = (auth ?? "").trim();
  const want = `Bearer ${expected}`;
  if (got.length !== want.length) return false;
  return timingSafeEqual(Buffer.from(got), Buffer.from(want));
};

// ─── Hono app ──────────────────────────────────────────────────────
const app = new Hono()
  .use(logger())
  // Metrics middleware — counts every request, records bytes/status.
  .use(async (c, next) => {
    m.inFlight++;
    try {
      await next();
    } finally {
      m.inFlight--;
      bumpCounter(
        [c.req.method, opLabel(c.req.path), statusClass(c.res.status)].join("|"),
      );
    }
  })
  // Operational endpoints — version-neutral, never under /v1/.
  .get("/health", (c) =>
    c.json({ status: "ok", service: "fd0-website", version: VERSION }),
  )
  .get("/version", (c) =>
    c.json({
      service: "fd0-website",
      server_version: VERSION,
      api_version: "v1",
    }),
  )
  .get("/metrics", (c) => {
    if (!checkBearer(c.req.header("Authorization"), METRICS_TOKEN)) {
      return c.notFound();
    }
    return c.body(renderPrometheus(), 200, {
      "Content-Type": "text/plain; version=0.0.4",
    });
  })
  // Static assets
  .route("/_ssr", routes(config))
  .use(
    "/public/*",
    serveStatic({
      root: "./public",
      rewriteRequestPath: (p) => p.replace(/^\/public/, ""),
    }),
  )
  .get("/files/compose.yml", async (c) => {
    const file = Bun.file("./public/files/compose.yml");
    if (!(await file.exists())) return c.notFound();
    return new Response(file, {
      headers: {
        "Content-Type": "text/yaml; charset=utf-8",
        "Cache-Control": "public, max-age=300",
      },
    });
  })
  // SEO files
  .get("/robots.txt", (c) =>
    c.body(
      [
        "User-agent: *",
        "Allow: /",
        "Disallow: /health",
        "Disallow: /metrics",
        "Disallow: /version",
        "",
        `Sitemap: ${SITE_URL}/sitemap.xml`,
        "",
      ].join("\n"),
      200,
      { "Content-Type": "text/plain; charset=utf-8" },
    ),
  )
  .get("/sitemap.xml", (c) => {
    const urls = [
      "/",
      "/docs",
      "/docs/concepts",
      "/docs/install",
      "/docs/cli",
      "/docs/ssh",
      "/docs/talos",
      "/docs/sync",
      "/docs/server",
      "/docs/yubikey",
      "/docs/recovery",
      "/docs/troubleshooting",
      "/spec",
      "/spec/wire",
      "/spec/crypto",
      "/spec/storage",
      "/spec/sync",
      "/spec/translog",
      "/spec/threats",
      "/witness",
      "/impressum",
    ].map(
      (p) => `${SITE_URL}${p}`,
    );
    const body =
      '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
      urls.map((u) => `  <url><loc>${u}</loc></url>`).join("\n") +
      "\n</urlset>\n";
    return c.body(body, 200, { "Content-Type": "application/xml; charset=utf-8" });
  })
  // Install-script aliases: redirect to the GitHub raw URL so the
  // README + spoken-word command stay short. curl -fsSL follows
  // 302 by default, so `curl -fsSL https://fd0.sh/install | sh`
  // ends up fetching the latest scripts/install.sh from main.
  .get("/install", (c) =>
    c.redirect(
      "https://raw.githubusercontent.com/ValentinKolb/fd0.sh/main/scripts/install.sh",
      302,
    ),
  )
  .get("/install.sh", (c) =>
    c.redirect(
      "https://raw.githubusercontent.com/ValentinKolb/fd0.sh/main/scripts/install.sh",
      302,
    ),
  )
  // Pages
  .get("/", ...Home)
  .get("/docs", ...DocsOverview)
  .get("/docs/concepts", ...DocsConcepts)
  .get("/docs/install", ...DocsInstall)
  .get("/docs/cli", ...DocsCli)
  .get("/docs/ssh", ...DocsSsh)
  .get("/docs/talos", ...DocsTalos)
  .get("/docs/sync", ...DocsSync)
  .get("/docs/server", ...DocsServer)
  .get("/docs/yubikey", ...DocsYubikey)
  .get("/docs/recovery", ...DocsRecovery)
  .get("/docs/troubleshooting", ...DocsTroubleshooting)
  .get("/spec", ...SpecOverview)
  .get("/spec/wire", ...SpecWire)
  .get("/spec/crypto", ...SpecCrypto)
  .get("/spec/storage", ...SpecStorage)
  .get("/spec/sync", ...SpecSync)
  .get("/spec/translog", ...SpecTranslog)
  .get("/spec/threats", ...SpecThreats)
  .get("/witness", ...Witness)
  .get("/impressum", ...Impressum)
  // Error handlers — designed pages instead of plaintext.
  .notFound((c) => {
    const res = renderHTML(() => <ErrorPage content={errorPresets[404]} />);
    return new Response(res.body, { status: 404, headers: res.headers });
  })
  .onError((err, c) => {
    console.error("[fd0-site] handler error:", err);
    const detail =
      process.env.NODE_ENV === "development"
        ? String(err.stack ?? err.message ?? err)
        : undefined;
    const res = renderHTML(() => (
      <ErrorPage content={errorPresets[500]} detail={detail} />
    ));
    return new Response(res.body, { status: 500, headers: res.headers });
  });

const port = Number(process.env.PORT ?? 5173);
export default { port, fetch: app.fetch };
console.log(
  `[fd0-site] listening on http://localhost:${port}`,
  METRICS_TOKEN ? "(metrics: token-protected)" : "(metrics: open)",
);
