import type { VaultStatus } from "../shared/contracts";

export const DEFAULT_IDLE_TIMEOUT_MS = 5 * 60_000;

export type SecurityLockReason = "system-idle" | "system-lock" | "suspend" | "resume" | "session-inactive";
type SystemIdleState = "active" | "idle" | "locked" | "unknown";

type DesktopAutoLockDependencies = {
  getSystemIdleState(thresholdSeconds: number): SystemIdleState;
  lock(reason: SecurityLockReason): Promise<void>;
  onError(error: unknown): void;
  pollIntervalMs?: number;
  retryDelaysMs?: readonly number[];
  sleep?: (delayMs: number) => Promise<void>;
};

export class DesktopAutoLock {
  readonly #deps: DesktopAutoLockDependencies;
  #idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;
  #unlocked = false;
  #timer: ReturnType<typeof setInterval> | undefined;
  #lockPromise: Promise<void> | undefined;

  constructor(deps: DesktopAutoLockDependencies) {
    this.#deps = deps;
  }

  observe(status: VaultStatus): void {
    this.#unlocked = Boolean(status.unlocked);
    const reported = status.idleTimeoutMillis;
    this.#idleTimeoutMs = typeof reported === "number" && Number.isFinite(reported) && reported > 0
      ? Math.max(1_000, Math.floor(reported))
      : DEFAULT_IDLE_TIMEOUT_MS;
  }

  start(): void {
    if (this.#timer) return;
    const interval = this.#deps.pollIntervalMs ?? 5_000;
    this.#timer = setInterval(() => {
      void this.checkNow().catch(this.#deps.onError);
    }, interval);
  }

  stop(): void {
    if (!this.#timer) return;
    clearInterval(this.#timer);
    this.#timer = undefined;
  }

  async checkNow(): Promise<void> {
    if (!this.#unlocked) return;
    const thresholdSeconds = Math.max(1, Math.ceil(this.#idleTimeoutMs / 1_000));
    const state = this.#deps.getSystemIdleState(thresholdSeconds);
    if (state === "locked") {
      await this.lockNow("system-lock");
    } else if (state === "idle") {
      await this.lockNow("system-idle");
    }
  }

  lockNow(reason: SecurityLockReason, force = false): Promise<void> {
    if (!force && !this.#unlocked) return Promise.resolve();
    if (this.#lockPromise) return this.#lockPromise;
    const promise = this.#lockWithRetry(reason).finally(() => {
      if (this.#lockPromise === promise) this.#lockPromise = undefined;
    });
    this.#lockPromise = promise;
    return promise;
  }

  async #lockWithRetry(reason: SecurityLockReason): Promise<void> {
    const retryDelays = this.#deps.retryDelaysMs ?? [250, 750];
    const sleep = this.#deps.sleep ?? ((delayMs) => new Promise((resolve) => setTimeout(resolve, delayMs)));
    for (let attempt = 0; ; attempt += 1) {
      try {
        await this.#deps.lock(reason);
        this.#unlocked = false;
        return;
      } catch (error) {
        if (attempt >= retryDelays.length) throw error;
        await sleep(retryDelays[attempt]!);
      }
    }
  }
}
