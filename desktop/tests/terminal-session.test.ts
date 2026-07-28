import { describe, expect, test } from "bun:test";
import {
  TerminalSessionManager,
  verifyTerminalRuntime,
  type PtyProcess,
  type PtySpawn,
} from "../src/main/terminal-session";
import type { TerminalExit } from "../src/shared/contracts";

class FakePty implements PtyProcess {
  process = "/usr/bin/ssh";
  writes: string[] = [];
  resizes: Array<[number, number]> = [];
  killed = false;
  private dataHandler = (_value: string): void => undefined;
  private exitHandler = (_result: TerminalExit): void => undefined;

  onData(handler: (data: string) => void) {
    this.dataHandler = handler;
    return { dispose: () => { this.dataHandler = () => undefined; } };
  }

  onExit(handler: (result: TerminalExit) => void) {
    this.exitHandler = handler;
    return { dispose: () => { this.exitHandler = () => undefined; } };
  }

  write(data: string): void {
    this.writes.push(data);
  }

  resize(cols: number, rows: number): void {
    this.resizes.push([cols, rows]);
  }

  kill(): void {
    this.killed = true;
  }

  emitData(value: string): void {
    this.dataHandler(value);
  }

  emitExit(result: TerminalExit): void {
    this.exitHandler(result);
  }
}

function fixture() {
  const processes: FakePty[] = [];
  const calls: Parameters<PtySpawn>[] = [];
  const spawn: PtySpawn = (...args) => {
    calls.push(args);
    const process = new FakePty();
    processes.push(process);
    return process;
  };
  const events = {
    data: [] as string[],
    exit: [] as TerminalExit[],
    process: [] as string[],
  };
  const manager = new TerminalSessionManager(spawn);
  const id = manager.create(
    {
      host: "production database",
      scopeId: "s_work",
      fd0Binary: "/Applications/fd0.app/Contents/Resources/bin/fd0",
      cwd: "/Users/fd0",
      environment: { FD0_HOME: "/tmp/fd0 home", PATH: "/usr/bin" },
    },
    {
      data: (value) => events.data.push(value),
      exit: (value) => events.exit.push(value),
      process: (value) => events.process.push(value),
    },
  );
  return { manager, id, calls, processes, events };
}

describe("TerminalSessionManager", () => {
  test("spawns only the trusted fd0 SSH argv", () => {
    const { manager, id, calls, events } = fixture();
    manager.start(id, 120, 38);

    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe("/Applications/fd0.app/Contents/Resources/bin/fd0");
    expect(calls[0][1]).toEqual([
      "ssh",
      "connect",
      "--scope",
      "s_work",
      "production database",
    ]);
    expect(calls[0][2]).toMatchObject({
      name: "xterm-256color",
      cols: 120,
      rows: 38,
      cwd: "/Users/fd0",
      env: {
        FD0_HOME: "/tmp/fd0 home",
        TERM: "xterm-256color",
        COLORTERM: "truecolor",
      },
    });
    expect(events.process).toEqual(["ssh"]);
  });

  test("forwards data, input, resize and exit without a shell", () => {
    const { manager, id, processes, events } = fixture();
    manager.start(id, 80, 24);
    const process = processes[0];

    process.emitData("\\x1b[32mconnected\\x1b[0m");
    manager.write(id, "uptime\r");
    manager.resize(id, 160, 48);
    process.emitExit({ exitCode: 0 });

    expect(events.data).toEqual(["\\x1b[32mconnected\\x1b[0m"]);
    expect(process.writes).toEqual(["uptime\r"]);
    expect(process.resizes).toEqual([[160, 48]]);
    expect(events.exit).toEqual([{ exitCode: 0 }]);
  });

  test("can reconnect after exit and kills a live process on close", () => {
    const { manager, id, processes } = fixture();
    manager.start(id, 80, 24);
    processes[0].emitExit({ exitCode: 255 });
    manager.start(id, 80, 24);
    manager.close(id);

    expect(processes).toHaveLength(2);
    expect(processes[1].killed).toBe(true);
    expect(() => manager.info(id)).toThrow("no longer available");
  });

  test("release smoke verifies the native PTY data path", async () => {
    const spawn: PtySpawn = (file, args) => {
      expect(file).toBe("/usr/bin/printf");
      expect(args).toEqual(["fd0-terminal-runtime-ok"]);
      const process = new FakePty();
      queueMicrotask(() => {
        process.emitData("fd0-terminal-runtime-ok");
        process.emitExit({ exitCode: 0 });
      });
      return process;
    };
    await expect(verifyTerminalRuntime(spawn)).resolves.toBeUndefined();
  });
});
