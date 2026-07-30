import type { TerminalTheme } from "../../../shared/contracts";

export const terminalCursorOptions = {
  cursorBlink: false,
  cursorInactiveStyle: "block",
  cursorStyle: "bar",
  cursorWidth: 2,
} as const;

export function cleanTerminalTitle(value: string): string {
  return [...value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()]
    .slice(0, 120)
    .join("");
}

export function resolveTerminalTheme(
  theme: TerminalTheme,
  systemDark: boolean,
): "light" | "dark" {
  return theme === "system" ? (systemDark ? "dark" : "light") : theme;
}

export function applyTerminalTheme(
  theme: TerminalTheme,
  systemDark: boolean,
  root: Pick<HTMLElement, "dataset" | "style"> = document.documentElement,
): "light" | "dark" {
  const resolved = resolveTerminalTheme(theme, systemDark);
  root.dataset.theme = resolved;
  root.style.colorScheme = resolved;
  return resolved;
}
