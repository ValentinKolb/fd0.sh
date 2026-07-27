import { describe, expect, test } from "bun:test";
import type { VaultStatus } from "../src/shared/contracts";
import {
  READINESS_SNOOZE_MS,
  isReadinessWarningSnoozed,
  readinessWarningReason,
  snoozeReadinessWarning,
} from "../src/renderer/src/lib/readiness-snooze";

function status(firstSyncAt?: number, recoveryVerifiedAt?: number): VaultStatus {
  return {
    vaultExists: true,
    agentRunning: true,
    unlocked: true,
    yubikey: false,
    readiness: { firstSyncAt, recoveryVerifiedAt },
  };
}

function memoryStorage(): Pick<Storage, "getItem" | "setItem" | "removeItem"> {
  const values = new Map<string, string>();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => { values.delete(key); },
  };
}

describe("readiness warning snooze", () => {
  test("sequences first sync before recovery", () => {
    expect(readinessWarningReason(status())).toBe("first-sync");
    expect(readinessWarningReason(status(1))).toBe("recovery");
    expect(readinessWarningReason(status(1, 2))).toBeNull();
  });

  test("snoozes each warning independently for seven days", () => {
    const storage = memoryStorage();
    const now = 1_000;
    snoozeReadinessWarning(storage, "first-sync", now);

    expect(isReadinessWarningSnoozed(storage, "first-sync", now + READINESS_SNOOZE_MS - 1)).toBe(true);
    expect(isReadinessWarningSnoozed(storage, "recovery", now + 1)).toBe(false);
    expect(isReadinessWarningSnoozed(storage, "first-sync", now + READINESS_SNOOZE_MS)).toBe(false);
  });
});
