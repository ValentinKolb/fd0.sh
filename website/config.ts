import { createConfig } from "@valentinkolb/ssr";
import { createSSRHandler, routes } from "@valentinkolb/ssr/hono";

// Per-page metadata. Beyond the SSR-default title/description, OG/Twitter
// fields support social previews; canonical lets crawlers dedup; structured
// data drives rich results.
type PageOptions = {
  title?: string;
  description?: string;
  canonical?: string;
  ogImage?: string;
  ogType?: "website" | "article";
};

const SITE_NAME = "fd0";
const SITE_URL = process.env.FD0_SITE_URL ?? "https://fd0.sh";
const SITE_DESCRIPTION =
  "fd0 — a zero-knowledge secrets manager you run yourself or use hosted at fd0.sh. " +
  "Ciphertext-only server, hardware-backed identity via YubiKey-PIV, " +
  "end-to-end transparency log with independent witness verification.";

// @font-face declarations live in the HTML head as an inline <style>
// block — keeps bun's CSS bundler from trying to resolve the woff2
// URLs at build time. The files themselves are copied to
// dist/public/fonts/ by scripts/copy-fonts.ts and served by the same
// serveStatic route as everything else under /public/.
const FONT_FACE_CSS = `
@font-face{font-family:"Geist";font-style:normal;font-weight:100 900;font-display:swap;src:url("/public/fonts/geist-latin-wght-normal.woff2") format("woff2-variations");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}
@font-face{font-family:"Geist";font-style:normal;font-weight:100 900;font-display:swap;src:url("/public/fonts/geist-latin-ext-wght-normal.woff2") format("woff2-variations");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF;}
@font-face{font-family:"Geist Mono";font-style:normal;font-weight:100 900;font-display:swap;src:url("/public/fonts/geist-mono-latin-wght-normal.woff2") format("woff2-variations");unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD;}
@font-face{font-family:"Geist Mono";font-style:normal;font-weight:100 900;font-display:swap;src:url("/public/fonts/geist-mono-latin-ext-wght-normal.woff2") format("woff2-variations");unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF;}
`.trim();

const ORG_JSONLD = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": `${SITE_URL}/#org`,
      name: SITE_NAME,
      url: SITE_URL,
      logo: `${SITE_URL}/public/logo.svg`,
      sameAs: ["https://github.com/ValentinKolb/fd0.sh"],
    },
    {
      "@type": "SoftwareApplication",
      name: "fd0",
      applicationCategory: "SecurityApplication",
      operatingSystem: "Linux, macOS",
      offers: {
        "@type": "Offer",
        price: "0",
        priceCurrency: "USD",
      },
      license: "https://www.apache.org/licenses/LICENSE-2.0",
      url: SITE_URL,
    },
  ],
};

export const { config, plugin, html } = createConfig<PageOptions>({
  dev: process.env.NODE_ENV === "development",
  rootDir: import.meta.dir,
  template: ({ body, scripts, title, description, canonical, ogImage, ogType }) => {
    const t = title ?? "fd0 — zero-knowledge secrets manager";
    const d = description ?? SITE_DESCRIPTION;
    const img = ogImage ?? `${SITE_URL}/public/og-card.png`;
    const url = canonical ?? SITE_URL;
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#0b0d0c">
    <meta name="view-transition" content="same-origin">
    <title>${t}</title>
    <meta name="description" content="${d}">

    <link rel="canonical" href="${url}">

    <meta property="og:type" content="${ogType ?? "website"}">
    <meta property="og:site_name" content="${SITE_NAME}">
    <meta property="og:title" content="${t}">
    <meta property="og:description" content="${d}">
    <meta property="og:url" content="${url}">
    <meta property="og:image" content="${img}">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">

    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${t}">
    <meta name="twitter:description" content="${d}">
    <meta name="twitter:image" content="${img}">

    <link rel="icon" type="image/svg+xml" href="/public/favicon.svg">
    <link rel="icon" type="image/png" sizes="32x32" href="/public/favicon-32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/public/favicon-16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/public/apple-touch-icon.png">
    <link rel="shortcut icon" href="/public/favicon.ico">
    <link rel="preload" as="font" type="font/woff2" href="/public/fonts/geist-latin-wght-normal.woff2" crossorigin>
    <link rel="preload" as="font" type="font/woff2" href="/public/fonts/geist-mono-latin-wght-normal.woff2" crossorigin>
    <style>${FONT_FACE_CSS}</style>
    <link rel="stylesheet" href="/public/styles.css">

    <script type="application/ld+json">${JSON.stringify(ORG_JSONLD)}</script>
  </head>
  <body>${body}${scripts}</body>
</html>`;
  },
});

export const ssr = createSSRHandler(html);
export { routes, SITE_URL };
