import type { VaultStatus } from "../../../shared/contracts";

export type ReadinessWarningReason = "first-sync" | "recovery";

export const READINESS_SNOOZE_MS = 7 * 24 * 60 * 60 * 1_000;

type ReadinessStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function storageKey(reason: ReadinessWarningReason): string {
  return `fd0.readinessSnooze.${reason}`;
}

export function readinessWarningReason(status: VaultStatus | null): ReadinessWarningReason | null {
  if (!status?.vaultExists) return null;
  if (!status.readiness?.firstSyncAt) return "first-sync";
  if (!status.readiness.recoveryVerifiedAt) return "recovery";
  return null;
}

export function snoozeReadinessWarning(
  storage: ReadinessStorage,
  reason: ReadinessWarningReason,
  now = Date.now(),
): void {
  storage.setItem(storageKey(reason), String(now + READINESS_SNOOZE_MS));
}

export function isReadinessWarningSnoozed(
  storage: ReadinessStorage,
  reason: ReadinessWarningReason,
  now = Date.now(),
): boolean {
  const raw = storage.getItem(storageKey(reason));
  if (raw === null) return false;
  const until = Number(raw);
  if (Number.isFinite(until) && until > now) return true;
  storage.removeItem(storageKey(reason));
  return false;
}
