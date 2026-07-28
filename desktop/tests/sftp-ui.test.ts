import { describe, expect, test } from "bun:test";
import {
  decodeSFTPPreview,
  remoteBreadcrumbs,
  remoteJoin,
  remoteParent,
  sftpErrorNeedsReconnect,
} from "../src/renderer/src/lib/sftp";

describe("SFTP file window helpers", () => {
  test("normalizes remote paths and breadcrumbs", () => {
    expect(remoteJoin("/home/sandbox/", "files")).toBe("/home/sandbox/files");
    expect(remoteParent("/home/sandbox/files/")).toBe("/home/sandbox");
    expect(remoteBreadcrumbs("/home/sandbox")).toEqual([
      { label: "/", path: "/" },
      { label: "home", path: "/home" },
      { label: "sandbox", path: "/home/sandbox" },
    ]);
  });

  test("only reconnects for session-level failures", () => {
    expect(sftpErrorNeedsReconnect({ code: "disconnected" })).toBe(true);
    expect(sftpErrorNeedsReconnect({ code: "connection_failed" })).toBe(true);
    expect(sftpErrorNeedsReconnect({ code: "permission_denied" })).toBe(false);
    expect(sftpErrorNeedsReconnect(new Error("server refused"))).toBe(false);
  });

  test("renders UTF-8 as text and binary as a hex dump", () => {
    const text = decodeSFTPPreview({
      contentBase64: btoa("hello\n"),
      size: 6,
      truncated: false,
    });
    expect(text).toEqual({ kind: "text", value: "hello\n" });

    const binary = decodeSFTPPreview({
      contentBase64: btoa("\u0000A\u00ff"),
      size: 3,
      truncated: false,
    });
    expect(binary.kind).toBe("hex");
    expect(binary.value).toContain("00 41 ff");
    expect(binary.value).toContain("|.A.|");
  });
});
