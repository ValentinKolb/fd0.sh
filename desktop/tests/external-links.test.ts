import { describe, expect, test } from "bun:test";
import { supportLink, trustedItemURL } from "../src/main/external-links";

describe("trustedItemURL", () => {
  test("accepts normalized HTTPS URLs", () => {
    expect(trustedItemURL("https://example.com/login")).toBe("https://example.com/login");
  });

  test("rejects non-HTTPS, credentials, and oversized values", () => {
    expect(() => trustedItemURL("http://example.com")).toThrow();
    expect(() => trustedItemURL("https://user:secret@example.com")).toThrow();
    expect(() => trustedItemURL(`https://example.com/${"x".repeat(2_048)}`)).toThrow();
  });
});

describe("supportLink", () => {
  test("maps only fixed support destinations", () => {
    expect(supportLink("docs")).toBe("https://fd0.sh/docs");
    expect(supportLink("issues")).toBe("https://github.com/ValentinKolb/fd0.sh/issues");
    expect(() => supportLink("other" as "docs")).toThrow();
  });
});
