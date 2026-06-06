/**
 * Shared error page. Used by Hono's app.notFound() and app.onError()
 * to render a designed 404/500 in the V1 amber-on-dark palette rather
 * than the framework's default plaintext.
 */

import { C, FONT_SANS, FONT_MONO, Nav, Footer } from "./chrome";

export type ErrorContent = {
  status: number;
  kicker: string;
  title: string;
  body: string;
};

export const errorPresets: Record<number, ErrorContent> = {
  404: {
    status: 404,
    kicker: "404 · not found",
    title: "That route doesn't exist.",
    body: "The URL is wrong, the link is stale, or the page was removed. The four real pages are linked below.",
  },
  500: {
    status: 500,
    kicker: "500 · internal error",
    title: "Something on our side broke.",
    body: "An unexpected error reached the server's last line. The exception is logged on the host; a refresh sometimes works.",
  },
};

export const ErrorPage = (p: { content: ErrorContent; detail?: string }) => (
  <div
    class="min-h-screen flex flex-col"
    style={`background:${C.bg};color:${C.fg};font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;`}
  >
    <Nav />
    <main class="flex-1 flex items-center justify-center px-6 md:px-10 py-20">
      <div class="max-w-2xl text-center">
        <div
          class="text-[11px] tracking-[0.22em] uppercase mb-5"
          style={`color:${C.acc};`}
        >
          {p.content.kicker}
        </div>
        <h1 class="text-[2.4rem] md:text-[3.2rem] leading-[1.05] tracking-tight font-medium mb-6">
          {p.content.title}
        </h1>
        <p class="text-lg leading-relaxed mb-9" style={`color:${C.dim};`}>
          {p.content.body}
        </p>
        {p.detail ? (
          <pre
            class="shell mx-auto p-4 mb-9 text-[12.5px] text-left max-w-xl"
            style={`background:${C.bgRaised};border:1px solid ${C.border};color:${C.dim};font-family:${FONT_MONO};`}
          >
            {p.detail}
          </pre>
        ) : null}
        <div class="flex flex-wrap justify-center gap-3 text-sm">
          {[
            ["/", "Home"],
            ["/docs", "Docs"],
            ["/spec", "Spec"],
            ["/witness", "Witness"],
          ].map(([href, label]) => (
            <a
              href={href}
              class="px-4 py-2 transition-colors"
              style={`color:${C.fg};border:1px solid ${C.border};`}
            >
              {label} →
            </a>
          ))}
        </div>
      </div>
    </main>
    <Footer />
  </div>
);
