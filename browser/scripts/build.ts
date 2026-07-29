import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const outdir = join(root, "dist");

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

for (const entrypoint of ["src/service-worker.ts", "src/content.ts"]) {
  const result = await Bun.build({
    entrypoints: [join(root, entrypoint)],
    outdir,
    target: "browser",
    format: "iife",
    minify: false,
    sourcemap: "external",
    naming: "[dir]/[name].js",
  });
  if (!result.success) {
    for (const log of result.logs) console.error(log);
    process.exit(1);
  }
}

await cp(join(root, "manifest.json"), join(outdir, "manifest.json"));
console.log(`built Chrome extension at ${outdir}`);
