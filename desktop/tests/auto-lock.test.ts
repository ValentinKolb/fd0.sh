import { describe, expect, test } from "bun:test";
import { DEFAULT_IDLE_TIMEOUT_MS, DesktopAutoLock, type SecurityLockReason } from "../src/main/auto-lock";

function status(unlocked: boolean, idleTimeoutMillis?: number) {
  return {
    vaultExists: true,
    agentRunning: true,
    unlocked,
    yubikey: false,
    idleTimeoutMillis,
  };
}

describe("DesktopAutoLock", () => {
  test("locks when the operating system reports idle or locked", async () => {
    let state: "active" | "idle" | "locked" = "active";
    const reasons: SecurityLockReason[] = [];
    const thresholds: number[] = [];
    const autoLock = new DesktopAutoLock({
      getSystemIdleState: (threshold) => {
        thresholds.push(threshold);
        return state;
      },
      lock: async (reason) => { reasons.push(reason); },
      onError: () => {},
    });
    autoLock.observe(status(true, 90_000));

    await autoLock.checkNow();
    expect(reasons).toEqual([]);
    state = "idle";
    await autoLock.checkNow();
    expect(reasons).toEqual(["system-idle"]);
    expect(thresholds).toEqual([90, 90]);

    autoLock.observe(status(true, 90_000));
    state = "locked";
    await autoLock.checkNow();
    expect(reasons).toEqual(["system-idle", "system-lock"]);
  });

  test("uses the safe default for agents without lifecycle metadata", async () => {
    let threshold = 0;
    const autoLock = new DesktopAutoLock({
      getSystemIdleState: (value) => {
        threshold = value;
        return "active";
      },
      lock: async () => {},
      onError: () => {},
    });
    autoLock.observe(status(true));
    await autoLock.checkNow();
    expect(threshold).toBe(DEFAULT_IDLE_TIMEOUT_MS / 1_000);
  });

  test("deduplicates concurrent security lock requests", async () => {
    let calls = 0;
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    const autoLock = new DesktopAutoLock({
      getSystemIdleState: () => "active",
      lock: async () => {
        calls += 1;
        await pending;
      },
      onError: () => {},
    });
    autoLock.observe(status(true));

    const first = autoLock.lockNow("suspend", true);
    const second = autoLock.lockNow("resume", true);
    expect(second).toBe(first);
    expect(calls).toBe(1);
    finish();
    await first;
  });

  test("retries transient bridge failures", async () => {
    let calls = 0;
    const autoLock = new DesktopAutoLock({
      getSystemIdleState: () => "active",
      lock: async () => {
        calls += 1;
        if (calls < 3) throw new Error("bridge restarted");
      },
      onError: () => {},
      retryDelaysMs: [0, 0],
      sleep: async () => {},
    });

    await autoLock.lockNow("system-lock", true);
    expect(calls).toBe(3);
  });

  test("does nothing while the vault is known to be locked", async () => {
    let calls = 0;
    const autoLock = new DesktopAutoLock({
      getSystemIdleState: () => "idle",
      lock: async () => { calls += 1; },
      onError: () => {},
    });
    autoLock.observe(status(false, 1_000));
    await autoLock.checkNow();
    await autoLock.lockNow("system-idle");
    expect(calls).toBe(0);
  });
});
