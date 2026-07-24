import { appendFile, mkdir, rename, rm, stat } from "node:fs/promises";
import { dirname } from "node:path";

export type DiagnosticComponent = "app" | "agent" | "bridge" | "sync" | "updater";

export type DiagnosticEvent = {
  at: string;
  component: DiagnosticComponent;
  event: string;
  message?: string;
};

const sensitiveAssignment = /\b(passphrase|password|pin|secret|token|authorization|cookie)\b\s*[:=]\s*([^\s,;]+)/gi;
const bearer = /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi;
const homePath = /\/Users\/[^/\s]+|\/home\/[^/\s]+/g;

export function redactDiagnosticText(value: unknown): string {
  const text = value instanceof Error ? value.message : String(value);
  return text
    .replace(sensitiveAssignment, "$1=[redacted]")
    .replace(bearer, "Bearer [redacted]")
    .replace(homePath, "~")
    .replace(/[\r\n\t]+/g, " ")
    .slice(0, 500);
}

export class DiagnosticsLog {
  readonly path: string;
  readonly #maxBytes: number;
  readonly #backups: number;
  readonly #recent: DiagnosticEvent[] = [];
  #pending = Promise.resolve();

  constructor(path: string, options?: { maxBytes?: number; backups?: number }) {
    this.path = path;
    this.#maxBytes = options?.maxBytes ?? 512 * 1024;
    this.#backups = options?.backups ?? 3;
  }

  record(component: DiagnosticComponent, event: string, detail?: unknown): void {
    const entry: DiagnosticEvent = {
      at: new Date().toISOString(),
      component,
      event: redactDiagnosticText(event),
      ...(detail === undefined ? {} : { message: redactDiagnosticText(detail) }),
    };
    this.#recent.push(entry);
    if (this.#recent.length > 50) this.#recent.shift();
    this.#pending = this.#pending
      .then(async () => {
        await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
        await this.#rotateIfNeeded();
        await appendFile(this.path, JSON.stringify(entry) + "\n", { mode: 0o600 });
      })
      .catch(() => undefined);
  }

  recent(): DiagnosticEvent[] {
    return this.#recent.slice(-20);
  }

  async flush(): Promise<void> {
    await this.#pending;
  }

  async #rotateIfNeeded(): Promise<void> {
    let size = 0;
    try {
      size = (await stat(this.path)).size;
    } catch {
      return;
    }
    if (size < this.#maxBytes) return;
    await rm(`${this.path}.${this.#backups}`, { force: true });
    for (let index = this.#backups - 1; index >= 1; index--) {
      try {
        await rename(`${this.path}.${index}`, `${this.path}.${index + 1}`);
      } catch {
        // A missing older generation is expected.
      }
    }
    try {
      await rename(this.path, `${this.path}.1`);
    } catch {
      // The active file may have been removed by the user.
    }
  }
}
