import { describe, expect, test } from "bun:test";
import { sftpSessionExitError } from "../src/main/sftp-bridge";

describe("SFTP bridge process errors", () => {
  test("maps expected SSH failures without exposing diagnostics", () => {
    const error = sftpSessionExitError(
      "Permission denied for alice@example.test using /Users/alice/.ssh/key",
      255,
    );
    expect(error.code).toBe("authentication_failed");
    expect(error.message).not.toContain("alice");
    expect(error.action).not.toContain("/Users/");
  });

  test("turns an unexpected exit into a calm reconnectable error", () => {
    const error = sftpSessionExitError("private helper output", "SIGTERM");
    expect(error.code).toBe("disconnected");
    expect(error.retryable).toBe(true);
    expect(error.message).not.toContain("private helper output");
  });

  test("explains host verification and locked-vault recovery", () => {
    expect(sftpSessionExitError("Host key verification failed", 255).code).toBe("host_unverified");
    expect(sftpSessionExitError("vault not unlocked", 1).code).toBe("vault_locked");
  });
});
