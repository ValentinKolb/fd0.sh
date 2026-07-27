import { randomUUID } from "node:crypto";
import { basename } from "node:path";
import * as nodePty from "node-pty";
import type { TerminalExit } from "../shared/contracts";

type Disposable = { dispose(): void };

export type PtyProcess = {
  readonly process: string;
  onData(handler: (data: string) => void): Disposable;
  onExit(handler: (result: TerminalExit) => void): Disposable;
  write(data: string): void;
  resize(cols: number, rows: number): void;
  kill(signal?: string): void;
};

export type PtySpawn = (
  file: string,
  args: string[],
  options: {
    name: string;
    cols: number;
    rows: number;
    cwd: string;
    env: NodeJS.ProcessEnv;
  },
) => PtyProcess;

export type TerminalSessionConfig = {
  host: string;
  scopeId: string;
  fd0Binary: string;
  environment: NodeJS.ProcessEnv;
  cwd: string;
};

export type TerminalSessionObserver = {
  data(value: string): void;
  exit(result: TerminalExit): void;
  process(name: string): void;
};

type Session = {
  config: TerminalSessionConfig;
  observer: TerminalSessionObserver;
  pty?: PtyProcess;
  disposables: Disposable[];
  processTimer?: NodeJS.Timeout;
  lastProcess: string;
};

const MAX_INPUT_CHARS = 1024 * 1024;
const TERMINAL_RUNTIME_SMOKE_TEXT = "fd0-terminal-runtime-ok";

function dimension(value: number, minimum: number, maximum: number): number {
  if (!Number.isFinite(value)) throw new Error("Terminal dimensions are invalid");
  return Math.max(minimum, Math.min(maximum, Math.floor(value)));
}

function terminalProcessName(value: string): string {
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  if (!clean) return "ssh";
  return basename(clean).slice(0, 80) || "ssh";
}

function validateConfig(config: TerminalSessionConfig): TerminalSessionConfig {
  for (const [label, value, maximum] of [
    ["SSH host", config.host, 512],
    ["Vault id", config.scopeId, 512],
    ["fd0 executable", config.fd0Binary, 4_096],
    ["Working directory", config.cwd, 4_096],
  ] as const) {
    if (!value || value.includes("\0") || value.length > maximum) {
      throw new Error(`${label} is invalid`);
    }
  }
  return config;
}

export class TerminalSessionManager {
  private readonly sessions = new Map<string, Session>();

  constructor(private readonly spawnPty: PtySpawn = nodePty.spawn as PtySpawn) {}

  create(config: TerminalSessionConfig, observer: TerminalSessionObserver): string {
    const id = randomUUID();
    this.sessions.set(id, {
      config: validateConfig(config),
      observer,
      disposables: [],
      lastProcess: "",
    });
    return id;
  }

  info(id: string): TerminalSessionConfig {
    const session = this.getSession(id);
    return session.config;
  }

  start(id: string, cols: number, rows: number): void {
    const session = this.getSession(id);
    if (session.pty) return;
    const pty = this.spawnPty(
      session.config.fd0Binary,
      ["ssh", "connect", "--scope", session.config.scopeId, session.config.host],
      {
        name: "xterm-256color",
        cols: dimension(cols, 2, 1_000),
        rows: dimension(rows, 1, 1_000),
        cwd: session.config.cwd,
        env: {
          ...session.config.environment,
          TERM: "xterm-256color",
          COLORTERM: "truecolor",
        },
      },
    );
    session.pty = pty;
    session.disposables = [
      pty.onData((data) => {
        if (session.pty === pty) session.observer.data(data);
      }),
      pty.onExit((result) => {
        if (session.pty !== pty) return;
        this.releaseProcess(session);
        session.observer.exit(result);
      }),
    ];
    this.reportProcess(session);
    session.processTimer = setInterval(() => {
      if (session.pty === pty) this.reportProcess(session);
    }, 1_000);
    session.processTimer.unref();
  }

  write(id: string, data: string): void {
    if (typeof data !== "string" || data.length > MAX_INPUT_CHARS) {
      throw new Error("Terminal input is invalid");
    }
    this.getSession(id).pty?.write(data);
  }

  resize(id: string, cols: number, rows: number): void {
    this.getSession(id).pty?.resize(
      dimension(cols, 2, 1_000),
      dimension(rows, 1, 1_000),
    );
  }

  close(id: string): void {
    const session = this.sessions.get(id);
    if (!session) return;
    this.releaseProcess(session, true);
    this.sessions.delete(id);
  }

  closeAll(): void {
    for (const id of [...this.sessions.keys()]) this.close(id);
  }

  private getSession(id: string): Session {
    const session = this.sessions.get(id);
    if (!session) throw new Error("Terminal session is no longer available");
    return session;
  }

  private reportProcess(session: Session): void {
    const name = terminalProcessName(session.pty?.process ?? "");
    if (name === session.lastProcess) return;
    session.lastProcess = name;
    session.observer.process(name);
  }

  private releaseProcess(session: Session, kill = false): void {
    if (session.processTimer) clearInterval(session.processTimer);
    session.processTimer = undefined;
    for (const disposable of session.disposables) disposable.dispose();
    session.disposables = [];
    const pty = session.pty;
    session.pty = undefined;
    session.lastProcess = "";
    if (kill && pty) {
      try {
        pty.kill();
      } catch {
        // The process may already have exited between the close event and here.
      }
    }
  }
}

/** Verifies that the packaged native node-pty binary can create and read a PTY. */
export async function verifyTerminalRuntime(
  spawnPty: PtySpawn = nodePty.spawn as PtySpawn,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const process = spawnPty("/usr/bin/printf", [TERMINAL_RUNTIME_SMOKE_TEXT], {
      name: "xterm-256color",
      cols: 80,
      rows: 24,
      cwd: "/",
      env: { PATH: "/usr/bin:/bin", TERM: "xterm-256color" },
    });
    let output = "";
    const timer = setTimeout(() => {
      try {
        process.kill();
      } catch {
        // The process may have exited while the timeout callback was queued.
      }
      reject(new Error("Terminal runtime smoke test timed out"));
    }, 5_000);
    const data = process.onData((value) => {
      output += value;
    });
    process.onExit(({ exitCode }) => {
      clearTimeout(timer);
      data.dispose();
      if (exitCode === 0 && output.includes(TERMINAL_RUNTIME_SMOKE_TEXT)) {
        resolve();
      } else {
        reject(new Error(`Terminal runtime smoke test failed with exit ${exitCode}`));
      }
    });
  });
}
