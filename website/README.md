# website

Source for fd0.sh and the user-facing fd0 documentation.

The site is server-rendered with Hono, Solid JSX, and
`@valentinkolb/ssr`. It does not use client-side routing. Most product
documentation belongs here; protocol and operator references stay in the
repository `docs/` directory.

## Run

```sh
bun install
bun run dev      # http://localhost:5173
bun run build    # dist/server.js + dist/public/styles.css
bun run start    # serve dist/
```

`PORT=...` overrides the listen port.

## Pages

| Path | Source |
| --- | --- |
| `/` | `src/pages/Home.tsx` |
| `/docs/*` | `src/pages/Docs.tsx` |
| `/spec/*` | `src/pages/Spec.tsx` |
| `/witness` | `src/pages/Witness.tsx` |
| `/impressum` | `src/pages/Impressum.tsx` |

Navigation, shared shell layout, docs sidebar, and spec sidebar live in
`src/lib/chrome.tsx`. Routes and sitemap entries live in `src/server.tsx`.

## Build

`scripts/build.ts` performs the production build:

1. Bundles `src/server.tsx` into `dist/server.js` through `Bun.build`.
2. Compiles `src/styles.css` into `dist/public/styles.css` through
   `bun-plugin-tailwind`.
3. Copies committed `public/` assets and local fonts into `dist/public/`.
4. Embeds the repository's `scripts/install.sh` and
   `scripts/install-desktop.sh`; `/install*` serves these immutable build
   inputs instead of redirecting to a mutable branch.
5. Fails if `public/files/compose.yml` is missing, because the self-host docs
   link to it directly.

`bun run start` changes into `dist/` before running `server.js`, so
static paths resolve against the production build output.

## Style rules

- Keep user docs direct and task-oriented.
- Put setup and common workflows before edge cases.
- Link to repository specs instead of duplicating protocol detail.
- Avoid vague claims such as "secure", "simple", or "easy" unless the
  paragraph states the concrete mechanism.
