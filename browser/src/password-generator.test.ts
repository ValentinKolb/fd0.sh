import { describe, expect, test } from "bun:test";

import {
  defaultGeneratorSettings,
  generatePassword,
  passwordStrength,
} from "./password-generator";

describe("browser password generator", () => {
  test("uses the same random password contract as Desktop", () => {
    const value = generatePassword({
      ...defaultGeneratorSettings,
      length: 32,
    });

    expect(value).toHaveLength(32);
    expect(value).toMatch(/[a-z]/);
    expect(value).toMatch(/[A-Z]/);
    expect(value).toMatch(/[0-9]/);
    expect(value).toMatch(/[^a-zA-Z0-9]/);
    expect(passwordStrength(value).score).toBeGreaterThanOrEqual(3);
  });

  test("generates readable phrases and digit-only PINs", () => {
    const phrase = generatePassword({
      ...defaultGeneratorSettings,
      mode: "memorable",
      words: 4,
      separator: "_",
      addNumber: false,
    });
    const pin = generatePassword({
      ...defaultGeneratorSettings,
      mode: "pin",
      pinLength: 8,
    });

    expect(phrase.split("_")).toHaveLength(4);
    expect(pin).toMatch(/^\d{8}$/);
  });
});
