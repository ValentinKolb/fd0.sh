import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DiagnosticsLog, redactDiagnosticText } from "../src/main/diagnostics";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("desktop diagnostics", () => {
  test("redacts credentials and user home paths", () => {
    expect(redactDiagnosticText("password=hunter2 Bearer abc.def /Users/alice/.fd0"))
      .toBe("password=[redacted] Bearer [redacted] ~/.fd0");
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
