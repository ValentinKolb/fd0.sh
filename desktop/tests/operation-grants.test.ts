import { describe, expect, test } from "bun:test";
import { OperationGrants } from "../src/main/operation-grants";

describe("OperationGrants", () => {
  test("binds a single use grant to operation and record", () => {
    let now = 1_000;
    let id = 0;
    const grants = new OperationGrants(500, () => now, () => `grant-${++id}`);
    const token = grants.issue("pass.edit", "scope-a", "pass:github");

    expect(grants.consume(token, "pass.edit", "scope-a", "pass:other")).toBe(false);
    expect(grants.consume(token, "pass.edit", "scope-a", "pass:github")).toBe(false);

    const valid = grants.issue("pass.edit", "scope-a", "pass:github");
    expect(grants.consume(valid, "pass.edit", "scope-a", "pass:github")).toBe(true);
    expect(grants.consume(valid, "pass.edit", "scope-a", "pass:github")).toBe(false);
  });

  test("expires and clears grants", () => {
    let now = 1_000;
    const grants = new OperationGrants(500, () => now, () => "grant");
    const expired = grants.issue("secret.edit", "scope-a", "token");
    now = 1_501;
    expect(grants.consume(expired, "secret.edit", "scope-a", "token")).toBe(false);

    const cleared = grants.issue("ssh.edit", "scope-a", "host:prod");
    grants.clear();
    expect(grants.consume(cleared, "ssh.edit", "scope-a", "host:prod")).toBe(false);
  });
});
