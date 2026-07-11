import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BridgeSupervisor, DesktopBridgeError } from "../src/main/bridge";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fakeBridge(): { binary: string; counter: string; crash: string } {
  const root = mkdtempSync(join(tmpdir(), "fd0-bridge-test-"));
  roots.push(root);
  const binary = join(root, "bridge.ts");
  const counter = join(root, "launches");
  const crash = join(root, "crashed");
  writeFileSync(binary, `#!/usr/bin/env bun
import { appendFileSync, existsSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
appendFileSync(process.env.TEST_LAUNCH_COUNTER!, "1");
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  const request = JSON.parse(line);
  if (request.method === "crash.once" && !existsSync(process.env.TEST_CRASH_MARKER!)) {
    writeFileSync(process.env.TEST_CRASH_MARKER!, "1");
    process.exit(1);
  }
  const response = request.method === "domain.error"
    ? { version: 1, id: request.id, error: { code: "expected", message: "Expected failure", retryable: false } }
    : { version: 1, id: request.id, result: request.method === "bridge.handshake" ? { protocol: 1 } : { ok: true } };
  process.stdout.write(JSON.stringify(response) + "\\n");
}
`, { mode: 0o700 });
  chmodSync(binary, 0o700);
  return { binary, counter, crash };
}

describe("BridgeSupervisor", () => {
  test("restarts a crashed bridge without replaying the failed operation", async () => {
    const fixture = fakeBridge();
    const supervisor = new BridgeSupervisor(fixture.binary, {
      ...process.env,
      TEST_LAUNCH_COUNTER: fixture.counter,
      TEST_CRASH_MARKER: fixture.crash,
    });
    await supervisor.start();
    await expect(supervisor.request("crash.once", {})).rejects.toThrow("Try the action again");
    await expect(supervisor.request<{ ok: boolean }>("crash.once", {})).resolves.toEqual({ ok: true });
    expect(readFileSync(fixture.counter, "utf8")).toBe("11");
    supervisor.dispose();
  });

  test("does not restart for a structured domain error", async () => {
    const fixture = fakeBridge();
    const supervisor = new BridgeSupervisor(fixture.binary, {
      ...process.env,
      TEST_LAUNCH_COUNTER: fixture.counter,
      TEST_CRASH_MARKER: fixture.crash,
    });
    await supervisor.start();
    await expect(supervisor.request("domain.error", {})).rejects.toBeInstanceOf(DesktopBridgeError);
    await expect(supervisor.request<{ ok: boolean }>("status", {})).resolves.toEqual({ ok: true });
    expect(readFileSync(fixture.counter, "utf8")).toBe("1");
    supervisor.dispose();
  });
});
