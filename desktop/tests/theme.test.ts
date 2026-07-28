import { describe, expect, test } from "bun:test";
import { activateTheme, readTheme, resolveTheme } from "../src/renderer/src/lib/theme";

function storage(value: string | null): Pick<Storage, "getItem"> {
  return { getItem: () => value };
}

function root(): HTMLElement {
  return {
    dataset: {},
    style: { colorScheme: "" },
  } as unknown as HTMLElement;
}

function media(initial: boolean): MediaQueryList & { emit(matches: boolean): void } {
  let matches = initial;
  const listeners = new Set<() => void>();
  return {
    get matches() {
      return matches;
    },
    media: "(prefers-color-scheme: dark)",
    onchange: null,
    addEventListener: (_type, listener) => listeners.add(listener as () => void),
    removeEventListener: (_type, listener) => listeners.delete(listener as () => void),
    addListener: (listener) => listeners.add(listener),
    removeListener: (listener) => listeners.delete(listener),
    dispatchEvent: () => true,
    emit(next) {
      matches = next;
      for (const listener of listeners) listener();
    },
  };
}

describe("desktop theme", () => {
  test("preserves stored choices and defaults new production profiles to System", () => {
    expect(readTheme(storage("system"), false)).toBe("system");
    expect(readTheme(storage("light"), false)).toBe("light");
    expect(readTheme(storage("dark"), false)).toBe("dark");
    expect(readTheme(storage(null), false)).toBe("system");
    expect(readTheme(storage(null), true)).toBe("light");
  });

  test("resolves only System through the operating-system preference", () => {
    expect(resolveTheme("system", false)).toBe("light");
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
  });

  test("updates a System renderer live and stops observing when disposed", () => {
    const target = root();
    const preference = media(false);
    const stop = activateTheme("system", target, preference);
    expect(target.dataset.theme).toBe("light");
    expect(target.style.colorScheme).toBe("light");

    preference.emit(true);
    expect(target.dataset.theme).toBe("dark");
    expect(target.style.colorScheme).toBe("dark");

    stop();
    preference.emit(false);
    expect(target.dataset.theme).toBe("dark");
  });
});
