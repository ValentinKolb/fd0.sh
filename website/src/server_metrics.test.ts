import { describe, expect, test } from "bun:test";
import { metricMethod, metricPathLabel } from "./server";

describe("website metric labels", () => {
  test("bounds attacker-controlled paths", () => {
    expect(metricPathLabel("/docs")).toBe("/docs");
    expect(metricPathLabel("/public/chunk-123.js")).toBe("/public/*");
    expect(metricPathLabel("/attacker/controlled/value")).toBe("/*");
  });

  test("bounds attacker-controlled methods", () => {
    expect(metricMethod("GET")).toBe("GET");
    expect(metricMethod("ARBITRARY")).toBe("OTHER");
  });
});
