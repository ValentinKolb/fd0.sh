import { afterEach, describe, expect, test } from "bun:test";
import { ManagedClipboard } from "../src/main/managed-clipboard";

const managers: ManagedClipboard[] = [];

afterEach(() => {
  for (const manager of managers.splice(0)) manager.clear();
});

function fixture() {
  let value = "original";
  let clears = 0;
  const clipboard = {
    writeText(next: string) { value = next; },
    readText() { return value; },
    clear() { value = ""; clears += 1; },
  };
  const manager = new ManagedClipboard(clipboard);
  managers.push(manager);
  return {
    manager,
    value: () => value,
    replace: (next: string) => { value = next; },
    clears: () => clears,
  };
}

describe("ManagedClipboard", () => {
  test("clears the value written by fd0 when the vault locks", () => {
    const state = fixture();
    state.manager.write("secret");
    state.manager.clear();
    expect(state.value()).toBe("");
    expect(state.clears()).toBe(1);
  });

  test("preserves a newer clipboard value written by another application", () => {
    const state = fixture();
    state.manager.write("secret");
    state.replace("new clipboard value");
    state.manager.clear();
    expect(state.value()).toBe("new clipboard value");
    expect(state.clears()).toBe(0);
  });

  test("tracks only the latest value written by fd0", () => {
    const state = fixture();
    state.manager.write("first secret");
    state.manager.write("second secret");
    state.manager.clear();
    expect(state.value()).toBe("");
    expect(state.clears()).toBe(1);
  });
});
