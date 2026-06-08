/**
 * Copy the variable-weight Geist + Geist Mono woff2 subsets we use into
 * the given `<out>/fonts/` directory.
 *
 * Why we don't @import the fontsource CSS directly: bun-plugin-tailwind
 * doesn't follow @import font URLs into node_modules, so the resolved
 * woff2 paths break in the final bundle. Copying explicitly keeps the
 * font story plain (look at public/fonts/ to see what ships) and avoids
 * any silent zero-byte regression.
 *
 * Subsets: latin + latin-ext, normal weight only. No italic, no
 * cyrillic / vietnamese — keeps the bundle under 90 KB. The site uses
 * a single variable font axis (weight 100..900) so a single file per
 * subset is enough.
 *
 * Updates the family name from fontsource's "Geist Variable" /
 * "Geist Mono Variable" to plain "Geist" / "Geist Mono" via our own
 * @font-face declarations in src/styles.css, so existing page code
 * never has to change.
 */

import { existsSync, mkdirSync, statSync } from "fs";

const FONTS = [
  {
    pkg: "@fontsource-variable/geist",
    files: [
      "geist-latin-wght-normal.woff2",
      "geist-latin-ext-wght-normal.woff2",
    ],
  },
  {
    pkg: "@fontsource-variable/geist-mono",
    files: [
      "geist-mono-latin-wght-normal.woff2",
      "geist-mono-latin-ext-wght-normal.woff2",
    ],
  },
];

export async function copyFonts(outDir: string): Promise<{ count: number; bytes: number }> {
  const fontsDir = `${outDir}/fonts`;
  mkdirSync(fontsDir, { recursive: true });
  let count = 0;
  let bytes = 0;
  for (const { pkg, files } of FONTS) {
    for (const f of files) {
      const src = `node_modules/${pkg}/files/${f}`;
      if (!existsSync(src)) {
        throw new Error(`copy-fonts: missing ${src} — did you bun install?`);
      }
      const dst = `${fontsDir}/${f}`;
      await Bun.write(dst, Bun.file(src));
      count++;
      bytes += statSync(dst).size;
    }
  }
  return { count, bytes };
}

// Allow running as a one-shot: `bun run scripts/copy-fonts.ts public`.
if (import.meta.main) {
  const out = process.argv[2] ?? "public";
  const { count, bytes } = await copyFonts(out);
  console.log(`✓ fonts:  ${count} file(s), ${(bytes / 1024).toFixed(1)} KB → ${out}/fonts/`);
}
