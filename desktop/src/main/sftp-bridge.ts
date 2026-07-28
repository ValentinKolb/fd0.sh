import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { DesktopBridgeError } from "./bridge";
import type { BridgeErrorShape, SFTPProgress } from "../shared/contracts";

const protocolVersion = 1;
const maxFrameBytes = 1 << 20;

type SFTPFrame<T> = {
  version: number;
  id: string;
  event?: string;
  data?: unknown;
  result?: T;
  error?: BridgeErrorShape;
};

type Pending = {
  resolve(value: unknown): void;
  reject(error: Error): void;
  timer: NodeJS.Timeout;
  onProgress?: (progress: SFTPProgress) => void;
};

export type SFTPTransfer<T> = {
  id: string;
  result: Promise<T>;
};

export class SFTPBridgeClient {
  readonly #process: ChildProcessWithoutNullStreams;
  readonly #pending = new Map<string, Pending>();
  #closed = false;
  #stderr = "";

  constructor(
    binary: string,
    host: string,
    scopeId: string,
    environment: NodeJS.ProcessEnv,
    onDiagnostic?: (event: string) => void,
  ) {
    this.#process = spawn(binary, ["--host", host, "--scope", scopeId], {
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.#process.stdin.setDefaultEncoding("utf8");
    const lines = createInterface({ input: this.#process.stdout, crlfDelay: Infinity });
    lines.on("line", (line) => this.#handleLine(line));
    this.#process.stderr.on("data", (value: Buffer) => {
      if (this.#stderr.length < 32 * 1024) {
        this.#stderr += value.toString("utf8").slice(0, 32 * 1024 - this.#stderr.length);
      }
      onDiagnostic?.("stderr");
    });
    this.#process.once("error", () => {
      onDiagnostic?.("process-error");
      this.#failAll(new DesktopBridgeError({
        code: "connection_failed",
        message: "fd0 could not start the remote file session.",
        action: "Try again. Open Support if the problem continues.",
        retryable: true,
      }));
    });
    this.#process.once("exit", (code, signal) => {
      this.#closed = true;
      onDiagnostic?.("process-exit");
      this.#failAll(sftpSessionExitError(this.#stderr, signal ?? code));
    });
  }

  request<T>(method: string, params: unknown, timeoutMs = 20_000): Promise<T> {
    const { result } = this.#send<T>(method, params, timeoutMs);
    return result;
  }

  transfer<T>(
    method: "transfer.download" | "transfer.upload",
    params: unknown,
    onProgress: (progress: SFTPProgress) => void,
  ): SFTPTransfer<T> {
    return this.#send<T>(method, params, 24 * 60 * 60_000, onProgress);
  }

  async cancel(transferId: string): Promise<void> {
    await this.request("transfer.cancel", { transferId });
  }

  dispose(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#process.stdin.end();
    this.#process.kill("SIGTERM");
    this.#failAll(new Error("fd0 file session closed"));
  }

  #send<T>(
    method: string,
    params: unknown,
    timeoutMs: number,
    onProgress?: (progress: SFTPProgress) => void,
  ): SFTPTransfer<T> {
    if (this.#closed) {
      return { id: "", result: Promise.reject(new Error("fd0 file session is not running")) };
    }
    if (this.#pending.size >= 32) {
      return {
        id: "",
        result: Promise.reject(new DesktopBridgeError({
          code: "busy",
          message: "Too many remote file operations are active.",
          action: "Wait for an operation to finish and try again.",
          retryable: true,
        })),
      };
    }
    const id = randomUUID();
    const frame = JSON.stringify({ version: protocolVersion, id, method, params });
    if (Buffer.byteLength(frame, "utf8") > maxFrameBytes) {
      return { id, result: Promise.reject(new Error("fd0 file request is too large")) };
    }
    const result = new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error("fd0 file request timed out"));
      }, timeoutMs);
      timer.unref();
      this.#pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timer,
        onProgress,
      });
      this.#process.stdin.write(frame + "\n", (error) => {
        if (!error) return;
        const pending = this.#pending.get(id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.#pending.delete(id);
        pending.reject(error);
      });
    });
    return { id, result };
  }

  #handleLine(line: string): void {
    if (Buffer.byteLength(line, "utf8") > maxFrameBytes) {
      this.#failAll(new Error("fd0 file response is too large"));
      this.dispose();
      return;
    }
    let frame: SFTPFrame<unknown>;
    try {
      frame = JSON.parse(line) as SFTPFrame<unknown>;
    } catch {
      this.#failAll(new Error("fd0 file session returned invalid JSON"));
      return;
    }
    if (frame.version !== protocolVersion || typeof frame.id !== "string") return;
    const pending = this.#pending.get(frame.id);
    if (!pending) return;
    if (frame.event === "progress") {
      const value = frame.data as Partial<SFTPProgress>;
      if (typeof value.transferred === "number" && typeof value.total === "number") {
        pending.onProgress?.({ transferred: value.transferred, total: value.total });
      }
      return;
    }
    clearTimeout(pending.timer);
    this.#pending.delete(frame.id);
    if (frame.error) {
      pending.reject(new DesktopBridgeError(frame.error));
    } else {
      pending.resolve(frame.result);
    }
  }

  #failAll(error: Error): void {
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.#pending.clear();
  }
}

export function sftpSessionExitError(stderr: string, status: string | number | null): DesktopBridgeError {
  const value = stderr.toLowerCase();
  if (value.includes("not unlocked") || value.includes("agent socket unavailable")) {
    return new DesktopBridgeError({
      code: "vault_locked",
      message: "Unlock fd0 before browsing remote files.",
      action: "Return to the main fd0 window and unlock the vault.",
      retryable: true,
    });
  }
  if (value.includes("host key verification failed")) {
    return new DesktopBridgeError({
      code: "host_unverified",
      message: "This server has not been verified on this device.",
      action: "Open the server in Terminal once and verify its host key.",
    });
  }
  if (value.includes("permission denied") || value.includes("authentication was denied")) {
    return new DesktopBridgeError({
      code: "authentication_failed",
      message: "The server did not accept the configured fd0 SSH key.",
      action: "Unlock fd0 and check the key assigned to this server.",
    });
  }
  if (value.includes("subsystem request failed") || value.includes("does not provide the sftp subsystem")) {
    return new DesktopBridgeError({
      code: "sftp_unavailable",
      message: "This server does not provide SFTP file access.",
      action: "Enable the SFTP subsystem on the server or use Terminal.",
    });
  }
  return new DesktopBridgeError({
    code: "disconnected",
    message: "The remote file session closed.",
    action: `Check the network connection and reconnect${status === null ? "." : ` (exit ${status}).`}`,
    retryable: true,
  });
}
