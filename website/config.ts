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
    <link rel="stylesheet" href="/public/styles.css">

    <script type="application/ld+json">${JSON.stringify(ORG_JSONLD)}</script>
  </head>
  <body>${body}${scripts}</body>
</html>`;
  },
});

export const ssr = createSSRHandler(html);
export { routes, SITE_URL };
