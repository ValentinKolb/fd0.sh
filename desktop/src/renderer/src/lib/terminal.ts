import type { TerminalTheme } from "../../../shared/contracts";

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
