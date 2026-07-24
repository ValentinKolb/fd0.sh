import { randomUUID } from "node:crypto";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import type { BridgeErrorShape } from "../shared/contracts";

const protocolVersion = 1;
const maxFrameBytes = 1 << 20;

type BridgeResponse<T> = {
  version: number;
  id: string;
  result?: T;
  error?: BridgeErrorShape;
};

type Pending = {
  resolve(value: unknown): void;
  reject(error: Error): void;
  timer: NodeJS.Timeout;
};

export class DesktopBridgeError extends Error {
  readonly code: string;
  readonly action?: string;
  readonly retryable: boolean;

  constructor(shape: BridgeErrorShape) {
    super(shape.message);
    this.name = "DesktopBridgeError";
    this.code = shape.code;
    this.action = shape.action;
    this.retryable = shape.retryable ?? false;
  }
}

export class BridgeClient {
  readonly #process: ChildProcessWithoutNullStreams;
  readonly #pending = new Map<string, Pending>();
  #sequence = 0;
  #closed = false;

  get closed(): boolean {
    return this.#closed;
  }

  constructor(
    binary: string,
    environment: NodeJS.ProcessEnv,
    onDiagnostic?: (event: string, detail?: unknown) => void,
  ) {
    this.#process = spawn(binary, [], {
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.#process.stdin.setDefaultEncoding("utf8");
    const lines = createInterface({ input: this.#process.stdout, crlfDelay: Infinity });
    lines.on("line", (line) => this.#handleLine(line));
    this.#process.stderr.on("data", (chunk: Buffer) => {
      onDiagnostic?.("stderr", chunk.toString("utf8").trimEnd());
      if (!process.env.NODE_ENV || process.env.NODE_ENV === "development") {
        console.error(`[fd0 bridge] ${chunk.toString("utf8").trimEnd()}`);
      }
    });
    this.#process.once("error", (error) => {
      onDiagnostic?.("process-error", error);
      this.#failAll(error);
    });
    this.#process.once("exit", (code, signal) => {
      this.#closed = true;
      onDiagnostic?.("process-exit", signal ?? code ?? "unknown");
      this.#failAll(new Error(`fd0 bridge exited (${signal ?? code ?? "unknown"})`));
    });
  }

  async handshake(): Promise<void> {
    const result = await this.request<{ protocol: number }>("bridge.handshake", {});
    if (result.protocol !== protocolVersion) {
      throw new Error(`fd0 bridge protocol mismatch: ${result.protocol}`);
    }
  }

  request<T>(method: string, params: unknown, timeoutMs = 20_000): Promise<T> {
    if (this.#closed) return Promise.reject(new Error("fd0 bridge is not running"));
    const id = `${randomUUID()}-${++this.#sequence}`;
    const frame = JSON.stringify({ version: protocolVersion, id, method, params });
    if (Buffer.byteLength(frame, "utf8") > maxFrameBytes) {
      return Promise.reject(new Error("fd0 bridge request is too large"));
    }
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error("fd0 bridge request timed out"));
      }, timeoutMs);
      this.#pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
        timer,
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
  }

  dispose(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#process.stdin.end();
    this.#process.kill("SIGTERM");
    this.#failAll(new Error("fd0 bridge closed"));
  }

  #handleLine(line: string): void {
    if (Buffer.byteLength(line, "utf8") > maxFrameBytes) {
      this.#failAll(new Error("fd0 bridge response is too large"));
      this.dispose();
      return;
    }
    let response: BridgeResponse<unknown>;
    try {
      response = JSON.parse(line) as BridgeResponse<unknown>;
    } catch {
      this.#failAll(new Error("fd0 bridge returned invalid JSON"));
      return;
    }
    if (response.version !== protocolVersion || typeof response.id !== "string") return;
    const pending = this.#pending.get(response.id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.#pending.delete(response.id);
    if (response.error) {
      pending.reject(new DesktopBridgeError(response.error));
    } else {
      pending.resolve(response.result);
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

export class BridgeSupervisor {
  readonly #binary: string;
  readonly #environment: NodeJS.ProcessEnv;
  readonly #onDiagnostic?: (event: string, detail?: unknown) => void;
  #client: BridgeClient | null = null;
  #starting: Promise<BridgeClient> | null = null;
  #disposed = false;

  constructor(
    binary: string,
    environment: NodeJS.ProcessEnv,
    onDiagnostic?: (event: string, detail?: unknown) => void,
  ) {
    this.#binary = binary;
    this.#environment = environment;
    this.#onDiagnostic = onDiagnostic;
  }

  async start(): Promise<void> {
    await this.#readyClient();
  }

  async request<T>(method: string, params: unknown, timeoutMs = 20_000): Promise<T> {
    const client = await this.#readyClient();
    try {
      return await client.request<T>(method, params, timeoutMs);
    } catch (error) {
      if (error instanceof DesktopBridgeError) throw error;
      this.#invalidate(client);
      void this.#readyClient().catch((restartError) => {
        if (!this.#disposed) console.error("fd0 bridge restart failed", restartError);
      });
      throw new Error("The fd0 local service restarted after an internal error. Try the action again.");
    }
  }

  dispose(): void {
    this.#disposed = true;
    this.#client?.dispose();
    this.#client = null;
  }

  async #readyClient(): Promise<BridgeClient> {
    if (this.#disposed) throw new Error("fd0 bridge supervisor is closed");
    if (this.#client && !this.#client.closed) return this.#client;
    if (this.#starting) return this.#starting;
    this.#starting = (async () => {
      const candidate = new BridgeClient(this.#binary, this.#environment, this.#onDiagnostic);
      try {
        await candidate.handshake();
        if (this.#disposed) {
          candidate.dispose();
          throw new Error("fd0 bridge supervisor is closed");
        }
        this.#client = candidate;
        return candidate;
      } catch (error) {
        candidate.dispose();
        throw error;
      } finally {
        this.#starting = null;
      }
    })();
    return this.#starting;
  }

  #invalidate(client: BridgeClient): void {
    if (this.#client !== client) return;
    client.dispose();
    this.#client = null;
  }
}
