import { describe, expect, test } from "bun:test";
import {
  applyTerminalTheme,
  cleanTerminalTitle,
  resolveTerminalTheme,
  terminalCursorOptions,
} from "../src/renderer/src/lib/terminal";

describe("terminal presentation", () => {
  test("keeps the terminal theme independent and resolves only System", () => {
    expect(resolveTerminalTheme("system", false)).toBe("light");
    expect(resolveTerminalTheme("system", true)).toBe("dark");
    expect(resolveTerminalTheme("light", true)).toBe("light");
    expect(resolveTerminalTheme("dark", false)).toBe("dark");
  });

  test("applies the terminal theme to standalone window roots", () => {
    const root = {
      dataset: {} as DOMStringMap,
      style: {} as CSSStyleDeclaration,
    };
    expect(applyTerminalTheme("system", true, root)).toBe("dark");
    expect(root.dataset.theme).toBe("dark");
    expect(root.style.colorScheme).toBe("dark");
    expect(applyTerminalTheme("light", true, root)).toBe("light");
    expect(root.dataset.theme).toBe("light");
  });

  test("keeps a high-contrast cursor visible without blink gaps", () => {
    expect(terminalCursorOptions).toEqual({
      cursorBlink: false,
      cursorInactiveStyle: "block",
      cursorStyle: "bar",
      cursorWidth: 2,
    });
  });

  test("neutralizes remote control characters in the secondary title", () => {
    expect(cleanTerminalTitle("  vim\u001b]0;spoof\u0007  ")).toBe("vim ]0;spoof");
    expect(cleanTerminalTitle("a".repeat(140))).toHaveLength(120);
  });
});
