import type { DesktopTheme } from "../../../shared/contracts";

const THEME_STORAGE_KEY = "fd0.theme";
const SYSTEM_DARK_QUERY = "(prefers-color-scheme: dark)";
export type ResolvedDesktopTheme = Exclude<DesktopTheme, "system">;

let removeActiveSystemListener: (() => void) | undefined;

export function readTheme(storage: Pick<Storage, "getItem">, development: boolean): DesktopTheme {
  const stored = storage.getItem(THEME_STORAGE_KEY);
  if (stored === "system" || stored === "light" || stored === "dark") return stored;
  return development ? "light" : "system";
}

export function resolveTheme(theme: DesktopTheme, systemDark: boolean): ResolvedDesktopTheme {
  if (theme === "system") return systemDark ? "dark" : "light";
  return theme;
}

export function applyTheme(
  theme: DesktopTheme,
  root: HTMLElement = document.documentElement,
  systemDark = window.matchMedia(SYSTEM_DARK_QUERY).matches,
): ResolvedDesktopTheme {
  const resolved = resolveTheme(theme, systemDark);
  root.dataset.theme = resolved;
  root.style.colorScheme = resolved;
  return resolved;
}

export function activateTheme(
  theme: DesktopTheme,
  root: HTMLElement = document.documentElement,
  media: MediaQueryList = window.matchMedia(SYSTEM_DARK_QUERY),
): () => void {
  removeActiveSystemListener?.();
  removeActiveSystemListener = undefined;

  const update = (): void => {
    applyTheme(theme, root, media.matches);
  };
  update();

  if (theme !== "system") return () => undefined;
  media.addEventListener("change", update);
  const stop = (): void => {
    media.removeEventListener("change", update);
    if (removeActiveSystemListener === stop) removeActiveSystemListener = undefined;
  };
  removeActiveSystemListener = stop;
  return stop;
}

export function storeTheme(storage: Pick<Storage, "setItem">, theme: DesktopTheme): void {
  storage.setItem(THEME_STORAGE_KEY, theme);
}
