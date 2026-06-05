# website

The fd0.sh homepage. One server-rendered page; no client-side
hydration. Built on Hono + Solid via
[`@valentinkolb/ssr`](https://github.com/ValentinKolb/ssr); Tailwind v4
for styles.

## Run

```sh
bun install
bun run dev      # http://localhost:5173, watch + reload
bun run build    # → dist/server.js + dist/public/styles.css
bun run start    # serves the dist/ build in production mode
```

`PORT=…` overrides the listen port.

## Layout

```
config.ts              @valentinkolb/ssr config (template, dev flag)
scripts/
  preload.ts           dev preload: registers ssr plugin + builds CSS
  build.ts             production bundle script
src/
  server.tsx           Hono app: mounts /_ssr, /public, /
  styles.css           @import tailwindcss + the .term palette
  pages/
    Home.tsx           the page, wrapped in ssr()
public/                dev-mode Tailwind output (gitignored)
dist/                  production build (gitignored)
  server.js
  public/styles.css
```

## How it ships

`scripts/build.ts` does two things:

1. Bundles `src/server.tsx` into `dist/server.js` via `Bun.build` with
   the `@valentinkolb/ssr` plugin (so any future island chunks are
   emitted alongside).
2. Compiles `src/styles.css` into `dist/public/styles.css` via
   `bun-plugin-tailwind`, minified.

`bun run start` chdirs into `dist/` and runs `server.js`, so the
relative `./public/*` path the Hono `serveStatic` middleware uses
resolves to the build output.

## JSX runtime

`bunfig.toml` and `tsconfig.json` both set `importSource = "solid-js"`.
There are no `.island.tsx` or `.client.tsx` files yet — every component
is server-only, but the framework is wired so adding hydrated bits
later is a matter of renaming a file.
