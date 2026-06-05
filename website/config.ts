import { createConfig } from "@valentinkolb/ssr";
import { createSSRHandler, routes } from "@valentinkolb/ssr/hono";

// Per-page metadata. The homepage is currently the only page, but the
// type keeps the door open for future routes without rewriting the
// template.
type PageOptions = {
  title?: string;
  description?: string;
};

const SITE_DESCRIPTION =
  "fd0 — a zero-knowledge secrets manager you run yourself. " +
  "Ciphertext-only server, hardware-backed identity via YubiKey-PIV, " +
  "end-to-end transparency log with independent witness verification.";

export const { config, plugin, html } = createConfig<PageOptions>({
  dev: process.env.NODE_ENV === "development",
  rootDir: import.meta.dir,
  template: ({ body, scripts, title, description }) => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${title ?? "fd0 — zero-knowledge secrets manager"}</title>
    <meta name="description" content="${description ?? SITE_DESCRIPTION}">
    <link rel="icon" type="image/svg+xml" href="/public/favicon.svg">
    <link rel="icon" type="image/png" sizes="32x32" href="/public/favicon-32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/public/favicon-16.png">
    <link rel="apple-touch-icon" sizes="180x180" href="/public/apple-touch-icon.png">
    <link rel="shortcut icon" href="/public/favicon.ico">
    <link rel="stylesheet" href="/public/styles.css">
  </head>
  <body>${body}${scripts}</body>
</html>`,
});

export const ssr = createSSRHandler(html);
export { routes };
