/**
 * Shared fd0 shell highlighter + <Shell> component.
 *
 * Same DSL as src/pages/Home.tsx (kept inline there because Home is the
 * locked production page). New homepage drafts under /v1–/v5 import from
 * here so the rule set stays in one place and the regex only compiles
 * once at module load.
 *
 * Tokens emitted: hl-comment, hl-string, hl-url, hl-prompt, hl-flag,
 * hl-arrow, hl-cmd. Styling lives in src/styles.css under .term — the
 * draft pages either reuse those rules by attaching the .term class or
 * scope new rules to their own root container.
 */

import { highlight } from "@valentinkolb/stdlib";

export const fd0Shell = highlight.compile([
  { kind: "comment", match: /#[^\n]*/ },
  { kind: "string", match: /"[^"]*"/ },
  { kind: "url", match: /(?:https?|fd0):\/\/[^\s"<>()]+/ },
  { kind: "prompt", match: /\$(?=\s|$)/ },
  { kind: "flag", match: /(?<![\w-])--?[a-zA-Z][\w-]*/ },
  { kind: "arrow", match: /[→←]/ },
  {
    kind: "cmd",
    match: /(?<![./\w])(?:fd0(?:-[a-z]+)?|curl|sudo|sh|systemctl|tar|xxd|grep|cat|sed|awk|cosign)(?![./\w])/,
  },
]);

// Always emits `.shell` (root-scope ligature kill + horizontal overflow)
// plus any caller-provided classes. Do NOT pass `.term` — that legacy
// class carries min-height:100vh and used to stretch hero terminals.
export const Shell = (p: { children: string; class?: string }) => (
  <pre class={`shell${p.class ? " " + p.class : ""}`} innerHTML={fd0Shell(p.children)} />
);
