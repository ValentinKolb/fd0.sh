/**
 * Generate PNG + ICO raster fallbacks for the favicon.
 *
 *   bun run scripts/icons.ts
 *
 * Reads public/favicon.svg and writes a standard set into public/:
 *   - favicon-16.png        small browser tabs
 *   - favicon-32.png        standard browser tab
 *   - favicon-48.png        bundled into favicon.ico
 *   - favicon-192.png       Android home screen
 *   - favicon-512.png       PWA splash
 *   - apple-touch-icon.png  iOS home screen (180×180, solid bg)
 *   - favicon.ico           multi-size ICO (16/32/48) for legacy browsers
 *
 * Requirements (Homebrew):
 *   - librsvg     SVG → PNG rasterization. ImageMagick's built-in MSVG
 *                 renderer silently drops `fill="none" stroke=…` on
 *                 rectangles, so a stroked-box favicon comes out as just
 *                 the dot. rsvg-convert renders the spec correctly.
 *   - imagemagick used only to bundle PNGs into the multi-size .ico.
 *
 *   brew install librsvg imagemagick
 *
 * Outputs are committed to git; rerun this script after editing
 * favicon.svg so the rasters stay in sync.
 */

import { $ } from "bun";

const SVG = "public/favicon.svg";
const OUT = "public";
const PALETTE_BG = "#0a0a0a"; // brand near-black for iOS solid bg

const TRANSPARENT_SIZES: Array<{ name: string; size: number }> = [
  { name: "favicon-16.png", size: 16 },
  { name: "favicon-32.png", size: 32 },
  { name: "favicon-48.png", size: 48 },
  { name: "favicon-192.png", size: 192 },
  { name: "favicon-512.png", size: 512 },
];

for (const { name, size } of TRANSPARENT_SIZES) {
  await $`rsvg-convert -w ${size} -h ${size} ${SVG} -o ${OUT}/${name}`;
  console.log(`✓ ${OUT}/${name}`);
}

// Apple touch icon. iOS rounds corners on the home screen and shows the
// icon against the wallpaper, so transparent edges become whatever
// wallpaper the user picked. Solid brand near-black fills the square.
const APPLE = { name: "apple-touch-icon.png", size: 180 };
await $`rsvg-convert -w ${APPLE.size} -h ${APPLE.size} --background-color ${PALETTE_BG} ${SVG} -o ${OUT}/${APPLE.name}`;
console.log(`✓ ${OUT}/${APPLE.name}`);

// Multi-size .ico — browsers that ignore the SVG link pick the best
// embedded PNG. magick's ICO writer takes the inputs as separate frames.
await $`magick ${OUT}/favicon-16.png ${OUT}/favicon-32.png ${OUT}/favicon-48.png ${OUT}/favicon.ico`;
console.log(`✓ ${OUT}/favicon.ico`);

// OpenGraph / Twitter card. 1200×630 is the LinkedIn/Twitter/Slack
// default. Rendered at native size with solid bg so transparent edges
// don't pick up whatever colour the social platform uses to pad.
const OG = "public/og-card.svg";
await $`rsvg-convert -w 1200 -h 630 --background-color ${PALETTE_BG} ${OG} -o ${OUT}/og-card.png`;
console.log(`✓ ${OUT}/og-card.png`);

console.log("\nDone. Commit public/favicon-*.png + apple-touch-icon.png + favicon.ico + og-card.png.");
