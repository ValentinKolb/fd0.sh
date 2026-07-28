import { describe, expect, test } from "bun:test";
import { activateTheme, readTheme, resolveTheme, setSystemTheme } from "../src/renderer/src/lib/theme";

function storage(value: string | null): Pick<Storage, "getItem"> {
  return { getItem: () => value };
}

function root(): HTMLElement {
  return {
    dataset: {},
    style: { colorScheme: "" },
  } as unknown as HTMLElement;
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
    setSystemTheme("light");
    const stop = activateTheme("system", target);
    expect(target.dataset.theme).toBe("light");
    expect(target.style.colorScheme).toBe("light");

    setSystemTheme("dark");
    expect(target.dataset.theme).toBe("dark");
    expect(target.style.colorScheme).toBe("dark");

    stop();
    setSystemTheme("light");
    expect(target.dataset.theme).toBe("dark");
  });
});
