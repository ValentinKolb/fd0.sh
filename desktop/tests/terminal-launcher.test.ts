import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildTerminalLaunchPlan,
  detectTerminalEnvironment,
  readTerminalLauncherSettings,
  terminalLauncherState,
  validateTerminalLauncherSettings,
  writeTerminalLauncherSettings,
  type TerminalDetection,
} from "../src/main/terminal-launcher";
import type { TerminalLauncherSettings } from "../src/shared/contracts";

const linuxDetection: TerminalDetection = {
  commands: {
    "xdg-terminal-exec": "/usr/bin/xdg-terminal-exec",
    ghostty: "/usr/bin/ghostty",
  },
  macApplications: { terminal: false, iterm2: false },
};

const automatic: TerminalLauncherSettings = {
  profileId: "automatic",
  terminalTheme: "system",
  customExecutable: "",
  customArguments: [],
};

describe("terminal launcher profiles", () => {
  test("detects commands without executing them", async () => {
    const accessible = new Set([
      "/usr/bin/xdg-terminal-exec",
      "/usr/bin/konsole",
    ]);
    const detection = await detectTerminalEnvironment({
      platform: "linux",
      environment: { PATH: "/usr/bin" },
      canAccess: async (path) => accessible.has(path),
    });

    expect(detection.commands["xdg-terminal-exec"]).toBe("/usr/bin/xdg-terminal-exec");
    expect(detection.commands.konsole).toBe("/usr/bin/konsole");
    expect(detection.commands.ghostty).toBeUndefined();
  });

  test("automatic Linux launch preserves every fd0 argument", () => {
    const plan = buildTerminalLaunchPlan({
      platform: "linux",
      settings: automatic,
      detection: linuxDetection,
      fd0Binary: "/opt/fd0/bin/fd0",
      scopeId: "s_work",
      alias: "production database",
      environment: { PATH: "/usr/bin" },
    });

    expect(plan.profileId).toBe("linux-system");
    expect(plan.command).toBe("/usr/bin/xdg-terminal-exec");
    expect(plan.arguments).toEqual([
      "--",
      "/opt/fd0/bin/fd0",
      "ssh",
      "connect",
      "--scope",
      "s_work",
      "production database",
    ]);
  });

  test("macOS adapters pass record data as argv, never AppleScript source", () => {
    const alias = "prod'; touch /tmp/not-run";
    const environment = {
      PATH: "/usr/bin",
      FD0_HOME: "/tmp/fd0 home",
      FD0_SSH_SOCK: "/tmp/fd0.sock",
    };
    const plan = buildTerminalLaunchPlan({
      platform: "darwin",
      settings: { ...automatic, profileId: "macos-terminal" },
      detection: {
        commands: { osascript: "/usr/bin/osascript" },
        macApplications: { terminal: true, iterm2: false },
      },
      fd0Binary: "/Applications/fd0.app/Contents/Resources/bin/fd0",
      scopeId: "s_personal",
      alias,
      environment,
    });

    expect(plan.command).toBe("/usr/bin/osascript");
    expect(plan.arguments.at(-1)).toBe(alias);
    expect(plan.arguments[1]).not.toContain(alias);
    expect(plan.arguments).toContain("FD0_HOME=/tmp/fd0 home");
    expect(plan.arguments).toContain("FD0_SSH_SOCK=/tmp/fd0.sock");
  });

  test("exposes only platform-relevant profiles and resolves Automatic", () => {
    const state = terminalLauncherState("linux", automatic, linuxDetection);
    expect(state.automaticProfileId).toBe("linux-system");
    expect(state.profiles[0]).toMatchObject({ id: "in-app", available: true });
    expect(state.profiles.find((profile) => profile.id === "linux-system")?.available).toBe(true);
    expect(state.profiles.some((profile) => profile.id === "macos-terminal")).toBe(false);
  });
});

describe("terminal launcher settings", () => {
  test("requires an absolute custom executable", () => {
    expect(() =>
      validateTerminalLauncherSettings(
        { profileId: "custom", terminalTheme: "system", customExecutable: "ghostty", customArguments: ["-e"] },
        "linux",
      ),
    ).toThrow("absolute path");
  });

  test("persists a private device-local profile", async () => {
    const directory = await mkdtemp(join(tmpdir(), "fd0-terminal-settings-"));
    const path = join(directory, "terminal-launcher.json");
    const input: TerminalLauncherSettings = {
      profileId: "custom",
      terminalTheme: "dark",
      customExecutable: "/opt/bin/my-terminal-wrapper",
      customArguments: ["--new-window"],
    };
    try {
      await writeTerminalLauncherSettings(path, "linux", input);
      expect(await readTerminalLauncherSettings(path, "linux")).toEqual(input);
      expect((await stat(path)).mode & 0o777).toBe(0o600);
      expect(await readFile(path, "utf8")).not.toContain("undefined");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("defaults new devices to the in-app terminal and a system terminal theme", async () => {
    const path = join(tmpdir(), `fd0-terminal-settings-missing-${process.pid}.json`);
    expect(await readTerminalLauncherSettings(path, "linux")).toEqual({
      profileId: "in-app",
      terminalTheme: "system",
      customExecutable: "",
      customArguments: [],
    });
  });

  test("preserves an existing external choice while adding the terminal theme default", async () => {
    const directory = await mkdtemp(join(tmpdir(), "fd0-terminal-settings-legacy-"));
    const path = join(directory, "terminal-launcher.json");
    try {
      await writeFile(path, JSON.stringify({
        profileId: "ghostty",
        customExecutable: "",
        customArguments: [],
      }));
      expect(await readTerminalLauncherSettings(path, "linux")).toEqual({
        profileId: "ghostty",
        terminalTheme: "system",
        customExecutable: "",
        customArguments: [],
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
