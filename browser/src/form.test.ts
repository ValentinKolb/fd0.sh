import { describe, expect, test } from "bun:test";

import { passwordScore, usernameScore } from "./form";

describe("login field scoring", () => {
  test("prefers explicit username metadata", () => {
    expect(
      usernameScore({
        type: "text",
        autocomplete: "username",
        name: "",
        id: "",
      }),
    ).toBeGreaterThan(
      usernameScore({
        type: "email",
        autocomplete: "",
        name: "",
        id: "",
      }),
    );
  });

  test("rejects new-password fields for login fill", () => {
    expect(
      passwordScore({
        type: "password",
        autocomplete: "new-password",
        name: "password",
        id: "",
      }),
    ).toBe(-1);
  });

  test("does not treat unrelated fields as credentials", () => {
    expect(
      usernameScore({
        type: "search",
        autocomplete: "",
        name: "query",
        id: "site-search",
      }),
    ).toBe(0);
    expect(
      passwordScore({
        type: "text",
        autocomplete: "",
        name: "password",
        id: "",
      }),
    ).toBe(0);
  });
});
