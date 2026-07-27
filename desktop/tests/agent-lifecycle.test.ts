import { expect, mock, test } from "bun:test";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

mock.module("electron", () => ({
  app: {
    isPackaged: false,
    getLoginItemSettings: () => ({ openAtLogin: false, status: "not-registered" }),
    setLoginItemSettings: () => undefined,
  },
}));

const { AgentLifecycle } = await import("../src/main/agent-lifecycle");

test("macOS agent service keeps interactive crypto responsive", async () => {
  const plist = await readFile(
    join(import.meta.dir, "../resources/sh.fd0.desktop.agent.plist"),
    "utf8",
  );
  expect(plist).toContain("<string>Standard</string>");
  expect(plist).not.toContain("<string>Background</string>");
});

test("AgentLifecycle installs and starts an isolated systemd user service", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-agent-lifecycle-"));
  const calls: string[][] = [];
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/opt/fd0 app/fd0-desktop",
    home,
    run: async (_file, args) => {
      calls.push(args as string[]);
      return { stdout: "", stderr: "" };
    },
  });

  expect(await lifecycle.ensureRunning()).toBe("enabled");
  const unit = await readFile(
    join(home, ".config", "systemd", "user", "fd0-agent.service"),
    "utf8",
  );
  expect(unit).toContain('ExecStart="/opt/fd0 app/fd0-desktop" --fd0-agent-relay');
  expect(unit).toContain("Restart=on-failure");
  expect(calls).toEqual([
    ["--user", "daemon-reload"],
    ["--user", "enable", "--now", "fd0-agent.service"],
  ]);
});

test("AgentLifecycle keeps GUI login separate from the agent service", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-gui-login-"));
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/home/test/fd0%desktop",
    home,
    run: async () => ({ stdout: "", stderr: "" }),
  });

  expect(await lifecycle.guiLaunchesAtLogin()).toBe(false);
  expect(await lifecycle.setGuiLaunchAtLogin(true)).toBe(true);
  const entry = await readFile(
    join(home, ".config", "autostart", "sh.fd0.desktop.desktop"),
    "utf8",
  );
  expect(entry).toContain('Exec="/home/test/fd0%%desktop"');
  expect(await lifecycle.setGuiLaunchAtLogin(false)).toBe(false);
  expect(await lifecycle.guiLaunchesAtLogin()).toBe(false);
});

test("AgentLifecycle refuses to replace a foreign systemd unit", async () => {
  const home = await mkdtemp(join(tmpdir(), "fd0-agent-foreign-"));
  const unitPath = join(home, ".config", "systemd", "user", "fd0-agent.service");
  await mkdir(join(home, ".config", "systemd", "user"), { recursive: true });
  await writeFile(unitPath, "[Service]\nExecStart=/usr/local/bin/fd0-agent\n");
  const calls: string[][] = [];
  const lifecycle = new AgentLifecycle({
    platform: "linux",
    packaged: true,
    appPath: "/opt/fd0",
    home,
    run: async (_file, args) => {
      calls.push(args as string[]);
      return { stdout: "", stderr: "" };
    },
  });

  await expect(lifecycle.ensureRunning()).rejects.toThrow("different fd0 service");
  await lifecycle.stop();
  await lifecycle.uninstall();
  expect(calls).toEqual([]);
  expect(await readFile(unitPath, "utf8")).toContain("/usr/local/bin/fd0-agent");
});
