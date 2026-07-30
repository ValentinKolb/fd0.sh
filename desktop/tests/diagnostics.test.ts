import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DiagnosticsLog, persistedSyncState, redactDiagnosticText } from "../src/main/diagnostics";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("desktop diagnostics", () => {
  test("redacts credentials and user home paths", () => {
    expect(redactDiagnosticText("password=hunter2 Bearer abc.def /Users/alice/.fd0"))
      .toBe("password=[redacted] Bearer [redacted] ~/.fd0");
  });

  test("restores the latest persisted sync from Unix seconds", () => {
    const sync = persistedSyncState(
      { state: "never" },
      { firstSyncAt: 1_700_000_000, lastSyncAt: 1_800_000_000 },
    );
    expect(sync).toEqual({
      state: "ok",
      lastAttemptAt: new Date(1_800_000_000 * 1_000).toISOString(),
    });
  });

  test("uses first sync for state written by older desktop versions", () => {
    const sync = persistedSyncState({ state: "never" }, { firstSyncAt: 1_700_000_000 });
    expect(sync.lastAttemptAt).toBe(new Date(1_700_000_000 * 1_000).toISOString());
  });

  test("keeps the current session sync state", () => {
    const sync = { state: "error" as const, lastAttemptAt: "2026-07-30T12:00:00.000Z" };
    expect(persistedSyncState(sync, { lastSyncAt: 1_800_000_000 })).toBe(sync);
  });

  test("rotates bounded logs", async () => {
    const root = await mkdtemp(join(tmpdir(), "fd0-diagnostics-"));
    roots.push(root);
    const path = join(root, "desktop.log");
    const log = new DiagnosticsLog(path, { maxBytes: 80, backups: 2 });
    for (let index = 0; index < 10; index++) log.record("app", `event-${index}`, "safe");
    await log.flush();
    expect((await readFile(path, "utf8")).length).toBeGreaterThan(0);
    expect((await readFile(`${path}.1`, "utf8")).length).toBeGreaterThan(0);
  });
});
