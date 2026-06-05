import { Hono } from "hono";
import { logger } from "hono/logger";
import { serveStatic } from "hono/bun";
import { config, routes } from "../config";
import Docs from "./pages/Docs";
import Home from "./pages/Home";
import Impressum from "./pages/Impressum";
import Spec from "./pages/Spec";

// Static assets — Tailwind CSS, favicons, etc. — live under public/.
// In dev, scripts/preload.ts compiles Tailwind into public/styles.css
// on every restart. In prod, scripts/build.ts emits dist/public/styles.css
// and `start` runs from dist/, so the same "./public/*" path resolves
// to the build output.
const app = new Hono()
  .use(logger())
  .route("/_ssr", routes(config))
  .use(
    "/public/*",
    serveStatic({
      root: "./public",
      rewriteRequestPath: (p) => p.replace(/^\/public/, ""),
    }),
  )
  .get("/", ...Home)
  .get("/docs", ...Docs)
  .get("/spec", ...Spec)
  .get("/impressum", ...Impressum);

const port = Number(process.env.PORT ?? 5173);
export default { port, fetch: app.fetch };
console.log(`[fd0-site] listening on http://localhost:${port}`);
