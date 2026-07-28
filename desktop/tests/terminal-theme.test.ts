import { describe, expect, test } from "bun:test";
import {
  cleanTerminalTitle,
  resolveTerminalTheme,
} from "../src/renderer/src/lib/terminal";

describe("terminal presentation", () => {
  test("keeps the terminal theme independent and resolves only System", () => {
    expect(resolveTerminalTheme("system", false)).toBe("light");
    expect(resolveTerminalTheme("system", true)).toBe("dark");
    expect(resolveTerminalTheme("light", true)).toBe("light");
    expect(resolveTerminalTheme("dark", false)).toBe("dark");
  });

  test("neutralizes remote control characters in the secondary title", () => {
    expect(cleanTerminalTitle("  vim\u001b]0;spoof\u0007  ")).toBe("vim ]0;spoof");
    expect(cleanTerminalTitle("a".repeat(140))).toHaveLength(120);
  });
});
