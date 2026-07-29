import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const storeBuild = Bun.argv.includes("--store");
const outdir = join(root, storeBuild ? "dist-store" : "dist");

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

for (const entrypoint of ["src/service-worker.ts", "src/content.ts"]) {
  const result = await Bun.build({
    entrypoints: [join(root, entrypoint)],
    outdir,
    target: "browser",
    format: "iife",
    minify: false,
    sourcemap: storeBuild ? "none" : "external",
    naming: "[dir]/[name].js",
  });
  if (!result.success) {
    for (const log of result.logs) console.error(log);
    process.exit(1);
  }
}

const baseManifest = JSON.parse(
  await readFile(join(root, "manifest.json"), "utf8"),
) as Record<string, unknown>;
const developmentManifest = storeBuild
  ? {}
  : (JSON.parse(
      await readFile(join(root, "manifest.development.json"), "utf8"),
    ) as Record<string, unknown>);
await writeFile(
  join(outdir, "manifest.json"),
  `${JSON.stringify({ ...baseManifest, ...developmentManifest }, null, 2)}\n`,
);

const iconOut = join(outdir, "icons");
await mkdir(iconOut, { recursive: true });
for (const filename of await readdir(join(root, "icons"))) {
  if (!filename.endsWith(".png")) continue;
  await cp(join(root, "icons", filename), join(iconOut, filename));
}

console.log(
  `built ${storeBuild ? "Chrome Web Store" : "development"} extension at ${outdir}`,
);
