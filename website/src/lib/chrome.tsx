/**
 * Shared chrome — Nav + Footer for the three top-level pages.
 *
 * The visual identity (dark surface, amber accent, Geist sans + Geist
 * Mono code) is repeated everywhere instead of pushed into CSS so the
 * three pages remain self-contained and individually editable.
 */

export const C = {
  bg: "#0b0d0c",
  bgRaised: "#13161544",
  fg: "#e8e6e0",
  dim: "#7c7e7a",
  border: "#23262521",
  acc: "#ffb000",
  sage: "#a3c97a",
};

export const FONT_SANS = "Geist,Inter,system-ui,sans-serif";
export const FONT_MONO = "'Geist Mono',ui-monospace,monospace";

export const LogoMark = (p: { size?: number }) => {
  const s = p.size ?? 20;
  const dot = s * 0.18;
  return (
    <span
      class="inline-block"
      style={`width:${s}px;height:${s}px;border:1.5px solid ${C.acc};position:relative;`}
    >
      <span
        class="absolute inset-0 m-auto block rounded-full"
        style={`background:${C.acc};width:${dot}px;height:${dot}px;top:50%;left:50%;transform:translate(-50%,-50%);`}
      />
    </span>
  );
};

export const Nav = (p: { current?: "home" | "docs" | "spec" }) => {
  const link = (key: "home" | "docs" | "spec", href: string, label: string) => (
    <a
      href={href}
      class="transition-colors"
      style={`color:${p.current === key ? C.fg : C.dim};`}
    >
      {label}
    </a>
  );
  return (
    <nav
      class="px-6 md:px-10 py-5 flex items-center justify-between border-b text-sm"
      style={`border-color:${C.border};`}
    >
      <a
        href="/"
        class="flex items-center gap-2.5 font-medium"
        style={`color:${C.fg};`}
      >
        <LogoMark />
        <span>fd0</span>
        <span class="hidden sm:inline" style={`color:${C.dim};`}>
          / secrets you keep
        </span>
      </a>
      <div class="flex items-center gap-5 md:gap-7">
        {link("home", "/", "Home")}
        {link("docs", "/docs", "Docs")}
        {link("spec", "/spec", "Spec")}
        <a
          href="https://github.com/ValentinKolb/fd0.sh"
          class="hidden md:inline transition-colors"
          style={`color:${C.dim};`}
        >
          GitHub
        </a>
      </div>
    </nav>
  );
};

export const Footer = () => (
  <footer
    class="px-6 md:px-10 py-12 border-t text-sm"
    style={`border-color:${C.border};color:${C.dim};`}
  >
    <div class="max-w-6xl mx-auto grid md:grid-cols-[1.4fr_1fr_1fr_1fr] gap-8">
      <div>
        <div class="flex items-center gap-2.5 mb-3" style={`color:${C.fg};`}>
          <LogoMark size={18} />
          <span class="font-medium">fd0</span>
        </div>
        <p class="text-xs leading-relaxed max-w-xs">
          Self-hosted secrets manager. Server stores ciphertext only;
          membership rotates the per-scope key cryptographically.
        </p>
      </div>
      <div>
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-2.5 font-medium"
          style={`color:${C.fg};`}
        >
          Product
        </div>
        <div class="flex flex-col gap-1.5 text-xs">
          <a href="/" class="hover:text-white">Home</a>
          <a href="/#install" class="hover:text-white">Install</a>
          <a href="/#quickstart" class="hover:text-white">Quickstart</a>
          <a href="/#compare" class="hover:text-white">Compare</a>
        </div>
      </div>
      <div>
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-2.5 font-medium"
          style={`color:${C.fg};`}
        >
          Reference
        </div>
        <div class="flex flex-col gap-1.5 text-xs">
          <a href="/docs" class="hover:text-white">Docs</a>
          <a href="/docs#cli" class="hover:text-white">CLI reference</a>
          <a href="/docs#server" class="hover:text-white">Server reference</a>
          <a href="/spec" class="hover:text-white">Specification</a>
          <a href="/spec#threats" class="hover:text-white">Threat model</a>
        </div>
      </div>
      <div>
        <div
          class="text-[11px] tracking-[0.18em] uppercase mb-2.5 font-medium"
          style={`color:${C.fg};`}
        >
          Project
        </div>
        <div class="flex flex-col gap-1.5 text-xs">
          <a href="https://github.com/ValentinKolb/fd0.sh" class="hover:text-white">
            GitHub
          </a>
          <a href="https://github.com/ValentinKolb/fd0.sh/blob/main/LICENSE" class="hover:text-white">
            Apache-2.0 licence
          </a>
          <a href="https://github.com/ValentinKolb/fd0.sh/releases" class="hover:text-white">
            Releases
          </a>
          <a href="/impressum" class="hover:text-white">Impressum</a>
        </div>
      </div>
    </div>
    <div
      class="max-w-6xl mx-auto mt-10 pt-6 flex flex-wrap justify-between items-center gap-3 text-xs"
      style={`border-top:1px solid ${C.border};`}
    >
      <div>fd0.sh — v1.0 — Apache-2.0</div>
      <div>self-hosted · no telemetry · no cloud</div>
    </div>
  </footer>
);
