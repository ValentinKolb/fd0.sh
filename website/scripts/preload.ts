/**
 * Dev-mode preload. Run via:
 *   bun --watch --preload=./scripts/preload.ts src/server.tsx
 *
 * Two responsibilities:
 *   1. Register the @valentinkolb/ssr Bun plugin so island/client
 *      component transforms work in the dev process.
 *   2. Compile Tailwind once on boot. `bun --watch` restarts the
 *      process when src/styles.css changes, so the CSS naturally
 *      rebuilds on edit.
 *
 * Production never loads this file — the build script writes the
 * compiled CSS into dist/public/ ahead of time.
 */

import { mkdirSync } from "fs";
import tailwindPlugin from "bun-plugin-tailwind";
import { plugin as ssrPlugin } from "../config";
import { copyFonts } from "./copy-fonts";

Bun.plugin(ssrPlugin());

mkdirSync("public", { recursive: true });

// Copy the variable Geist + Geist Mono woff2 subsets we use so
// dev-mode serves them locally — no Google Fonts, no external HTTP.
{
  const { count, bytes } = await copyFonts("public");
  console.log(`[fd0-site] fonts copied (dev): ${count} file(s), ${(bytes / 1024).toFixed(1)} KB → public/fonts/`);
}
const stylesEntry = new URL("../src/styles.css", import.meta.url).pathname;
const build = await Bun.build({
  entrypoints: [stylesEntry],
  plugins: [tailwindPlugin],
  outdir: "public",
  naming: "styles.[ext]",
});
if (!build.success) {
  console.error("[fd0-site] dev CSS build failed");
  for (const m of build.logs) console.error(m);
} else {
  const css = build.outputs.find((o) => o.path.endsWith(".css"));
  if (css) {
    const kb = (css.size / 1024).toFixed(1);
    console.log(`[fd0-site] tailwind built (dev): ${kb} KB → public/styles.css`);
  }
}
