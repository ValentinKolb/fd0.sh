import type { DesktopTheme, ResolvedDesktopTheme } from "../../../shared/contracts";

const THEME_STORAGE_KEY = "fd0.theme";

let removeActiveSystemListener: (() => void) | undefined;
let systemTheme: ResolvedDesktopTheme = "light";
const systemThemeListeners = new Set<() => void>();

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
  systemDark = systemTheme === "dark",
): ResolvedDesktopTheme {
  const resolved = resolveTheme(theme, systemDark);
  root.dataset.theme = resolved;
  root.style.colorScheme = resolved;
  return resolved;
}

export function activateTheme(
  theme: DesktopTheme,
  root: HTMLElement = document.documentElement,
): () => void {
  removeActiveSystemListener?.();
  removeActiveSystemListener = undefined;

  const update = (): void => {
    applyTheme(theme, root);
  };
  update();

  if (theme !== "system") return () => undefined;
  systemThemeListeners.add(update);
  const stop = (): void => {
    systemThemeListeners.delete(update);
    if (removeActiveSystemListener === stop) removeActiveSystemListener = undefined;
  };
  removeActiveSystemListener = stop;
  return stop;
}

export function setSystemTheme(theme: ResolvedDesktopTheme): void {
  if (systemTheme === theme) return;
  systemTheme = theme;
  for (const listener of systemThemeListeners) listener();
}

export function systemThemeIsDark(): boolean {
  return systemTheme === "dark";
}

export function observeSystemTheme(listener: () => void): () => void {
  systemThemeListeners.add(listener);
  return () => systemThemeListeners.delete(listener);
}

export function storeTheme(storage: Pick<Storage, "setItem">, theme: DesktopTheme): void {
  storage.setItem(THEME_STORAGE_KEY, theme);
}
