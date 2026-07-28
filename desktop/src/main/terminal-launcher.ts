import { constants } from "node:fs";
import { access, chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { spawn, type SpawnOptions } from "node:child_process";
import { delimiter, dirname, isAbsolute, join } from "node:path";
import type {
  TerminalLauncherSettings,
  TerminalLauncherState,
  TerminalProfileID,
  TerminalProfileSummary,
} from "../shared/contracts";

const defaultSettings: TerminalLauncherSettings = {
  profileId: "in-app",
  terminalTheme: "system",
  customExecutable: "",
  customArguments: [],
};

const commandNames = [
  "osascript",
  "ghostty",
  "xdg-terminal-exec",
  "x-terminal-emulator",
  "ptyxis",
  "gnome-terminal",
  "konsole",
] as const;

type TerminalCommandName = (typeof commandNames)[number];

export type TerminalDetection = {
  commands: Partial<Record<TerminalCommandName, string>>;
  macApplications: {
    terminal: boolean;
    iterm2: boolean;
  };
};

export type TerminalLaunchPlan = {
  profileId: TerminalProfileID;
  command: string;
  arguments: string[];
  environment: NodeJS.ProcessEnv;
};

type DetectOptions = {
  platform: NodeJS.Platform;
  environment: NodeJS.ProcessEnv;
  canAccess?: (path: string, mode: number) => Promise<boolean>;
};

async function defaultCanAccess(path: string, mode: number): Promise<boolean> {
  try {
    await access(path, mode);
    return true;
  } catch {
    return false;
  }
}

async function findExecutable(
  name: TerminalCommandName,
  environment: NodeJS.ProcessEnv,
  canAccess: (path: string, mode: number) => Promise<boolean>,
): Promise<string | undefined> {
  for (const directory of (environment.PATH ?? "").split(delimiter).filter(Boolean)) {
    const candidate = join(directory, name);
    if (await canAccess(candidate, constants.X_OK)) return candidate;
  }
  return undefined;
}

/** Detects launchers without running them or opening a window. */
export async function detectTerminalEnvironment(options: DetectOptions): Promise<TerminalDetection> {
  const canAccess = options.canAccess ?? defaultCanAccess;
  const commandEntries = await Promise.all(
    commandNames.map(async (name) => [name, await findExecutable(name, options.environment, canAccess)] as const),
  );
  const commands = Object.fromEntries(commandEntries.filter((entry) => entry[1])) as Partial<
    Record<TerminalCommandName, string>
  >;

  if (options.platform === "darwin" && !commands.osascript && await canAccess("/usr/bin/osascript", constants.X_OK)) {
    commands.osascript = "/usr/bin/osascript";
  }

  if (options.platform === "darwin" && !commands.ghostty) {
    const home = options.environment.HOME ?? "";
    const candidates = [
      "/Applications/Ghostty.app/Contents/MacOS/ghostty",
      ...(home ? [join(home, "Applications", "Ghostty.app", "Contents", "MacOS", "ghostty")] : []),
    ];
    for (const candidate of candidates) {
      if (await canAccess(candidate, constants.X_OK)) {
        commands.ghostty = candidate;
        break;
      }
    }
  }

  const home = options.environment.HOME ?? "";
  const terminalApplications = [
    "/System/Applications/Utilities/Terminal.app",
    "/Applications/Utilities/Terminal.app",
  ];
  const itermApplications = [
    "/Applications/iTerm.app",
    ...(home ? [join(home, "Applications", "iTerm.app")] : []),
  ];
  return {
    commands,
    macApplications: {
      terminal:
        options.platform === "darwin" &&
        (await anyAccessible(terminalApplications, canAccess)),
      iterm2:
        options.platform === "darwin" &&
        (await anyAccessible(itermApplications, canAccess)),
    },
  };
}

async function anyAccessible(
  candidates: string[],
  canAccess: (path: string, mode: number) => Promise<boolean>,
): Promise<boolean> {
  for (const candidate of candidates) {
    if (await canAccess(candidate, constants.F_OK)) return true;
  }
  return false;
}

function profileMetadata(platform: NodeJS.Platform): Array<Omit<TerminalProfileSummary, "available">> {
  const inApp = {
    id: "in-app" as const,
    label: "In fd0",
    description: "Open SSH sessions in a separate fd0 terminal window.",
  };
  if (platform === "darwin") {
    return [
      inApp,
      {
        id: "automatic",
        label: "Automatic",
        description: "Use the standard macOS terminal.",
      },
      {
        id: "macos-terminal",
        label: "macOS Terminal",
        description: "Open a new Terminal.app session.",
      },
      {
        id: "iterm2",
        label: "iTerm2",
        description: "Open a new iTerm2 window.",
      },
      {
        id: "ghostty",
        label: "Ghostty",
        description: "Run the fd0 command directly in Ghostty.",
      },
      {
        id: "custom",
        label: "Custom launcher",
        description: "Use an executable or wrapper you choose.",
      },
    ];
  }
  if (platform === "linux") {
    return [
      inApp,
      {
        id: "automatic",
        label: "Automatic",
        description: "Use the first supported terminal available on this device.",
      },
      {
        id: "linux-system",
        label: "Linux system default",
        description: "Use xdg-terminal-exec and the desktop's preferred terminal.",
      },
      {
        id: "debian-default",
        label: "Debian / Ubuntu default",
        description: "Use the x-terminal-emulator system alternative.",
      },
      {
        id: "ptyxis",
        label: "RHEL / Fedora default",
        description: "Open the command in Ptyxis.",
      },
      {
        id: "gnome-terminal",
        label: "GNOME Terminal",
        description: "Open the command in GNOME Terminal.",
      },
      {
        id: "konsole",
        label: "Konsole",
        description: "Open the command in KDE Konsole.",
      },
      {
        id: "ghostty",
        label: "Ghostty",
        description: "Run the fd0 command directly in Ghostty.",
      },
      {
        id: "custom",
        label: "Custom launcher",
        description: "Use an executable or wrapper you choose.",
      },
    ];
  }
  return [
    inApp,
    {
      id: "automatic",
      label: "Automatic",
      description: "No supported terminal launcher was detected.",
    },
    {
      id: "custom",
      label: "Custom launcher",
      description: "Use an executable or wrapper you choose.",
    },
  ];
}

function builtinAvailable(
  id: TerminalProfileID,
  platform: NodeJS.Platform,
  detection: TerminalDetection,
): boolean {
  switch (id) {
    case "in-app":
      return true;
    case "macos-terminal":
      return platform === "darwin" && detection.macApplications.terminal && Boolean(detection.commands.osascript);
    case "iterm2":
      return platform === "darwin" && detection.macApplications.iterm2 && Boolean(detection.commands.osascript);
    case "ghostty":
      return Boolean(detection.commands.ghostty);
    case "linux-system":
      return platform === "linux" && Boolean(detection.commands["xdg-terminal-exec"]);
    case "debian-default":
      return platform === "linux" && Boolean(detection.commands["x-terminal-emulator"]);
    case "ptyxis":
      return platform === "linux" && Boolean(detection.commands.ptyxis);
    case "gnome-terminal":
      return platform === "linux" && Boolean(detection.commands["gnome-terminal"]);
    case "konsole":
      return platform === "linux" && Boolean(detection.commands.konsole);
    case "custom":
      return true;
    default:
      return false;
  }
}

function automaticProfile(
  platform: NodeJS.Platform,
  detection: TerminalDetection,
): TerminalProfileID | undefined {
  const candidates: TerminalProfileID[] =
    platform === "darwin"
      ? ["macos-terminal"]
      : [
          "linux-system",
          "debian-default",
          "ptyxis",
          "gnome-terminal",
          "konsole",
          "ghostty",
        ];
  return candidates.find((id) => builtinAvailable(id, platform, detection));
}

export function terminalLauncherState(
  platform: NodeJS.Platform,
  settings: TerminalLauncherSettings,
  detection: TerminalDetection,
): TerminalLauncherState {
  const automaticProfileId = automaticProfile(platform, detection);
  return {
    settings,
    automaticProfileId,
    profiles: profileMetadata(platform).map((profile) => ({
      ...profile,
      available:
        profile.id === "in-app"
          ? true
          : profile.id === "automatic"
          ? Boolean(automaticProfileId)
          : builtinAvailable(profile.id, platform, detection),
    })),
  };
}

function validateString(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string" || value.includes("\0") || value.length > maxLength) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

export function validateTerminalLauncherSettings(
  input: TerminalLauncherSettings,
  platform: NodeJS.Platform,
): TerminalLauncherSettings {
  const availableIDs = new Set(profileMetadata(platform).map((profile) => profile.id));
  if (!input || !availableIDs.has(input.profileId)) throw new Error("Terminal profile is invalid");
  const terminalTheme =
    input.terminalTheme === "system" || input.terminalTheme === "light" || input.terminalTheme === "dark"
      ? input.terminalTheme
      : "system";
  const customExecutable = validateString(input.customExecutable, "Custom terminal executable", 4_096).trim();
  if (customExecutable && !isAbsolute(customExecutable)) {
    throw new Error("Custom terminal executable must be an absolute path");
  }
  if (input.profileId === "custom" && !customExecutable) {
    throw new Error("Choose a custom terminal executable");
  }
  if (!Array.isArray(input.customArguments) || input.customArguments.length > 32) {
    throw new Error("Custom terminal arguments are invalid");
  }
  const customArguments = input.customArguments.map((argument) =>
    validateString(argument, "Custom terminal argument", 512),
  );
  return { profileId: input.profileId, terminalTheme, customExecutable, customArguments };
}

export async function readTerminalLauncherSettings(path: string, platform: NodeJS.Platform): Promise<TerminalLauncherSettings> {
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as TerminalLauncherSettings;
    return validateTerminalLauncherSettings(parsed, platform);
  } catch {
    return { ...defaultSettings };
  }
}

export async function writeTerminalLauncherSettings(
  path: string,
  platform: NodeJS.Platform,
  input: TerminalLauncherSettings,
): Promise<TerminalLauncherSettings> {
  const settings = validateTerminalLauncherSettings(input, platform);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
  await chmod(temporary, 0o600);
  await rename(temporary, path);
  return settings;
}

function directCommand(
  profileId: TerminalProfileID,
  detection: TerminalDetection,
): { command?: string; prefix: string[] } {
  switch (profileId) {
    case "ghostty":
      return { command: detection.commands.ghostty, prefix: ["-e"] };
    case "linux-system":
      return { command: detection.commands["xdg-terminal-exec"], prefix: ["--"] };
    case "debian-default":
      return { command: detection.commands["x-terminal-emulator"], prefix: ["-e"] };
    case "ptyxis":
      return { command: detection.commands.ptyxis, prefix: ["--"] };
    case "gnome-terminal":
      return { command: detection.commands["gnome-terminal"], prefix: ["--"] };
    case "konsole":
      return { command: detection.commands.konsole, prefix: ["-e"] };
    default:
      return { prefix: [] };
  }
}

const terminalAppleScript = `
on run argv
  set commandText to ""
  repeat with argumentValue in argv
    set commandText to commandText & quoted form of (argumentValue as text) & " "
  end repeat
  tell application "Terminal"
    activate
    do script commandText
  end tell
end run
`.trim();

const itermAppleScript = `
on run argv
  set commandText to ""
  repeat with argumentValue in argv
    set commandText to commandText & quoted form of (argumentValue as text) & " "
  end repeat
  tell application "iTerm2"
    activate
    create window with default profile command commandText
  end tell
end run
`.trim();

function fd0EnvironmentArguments(environment: NodeJS.ProcessEnv): string[] {
  return Object.entries(environment)
    .filter(([name, value]) => name.startsWith("FD0_") && typeof value === "string")
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => `${name}=${value}`);
}

export function buildTerminalLaunchPlan(options: {
  platform: NodeJS.Platform;
  settings: TerminalLauncherSettings;
  detection: TerminalDetection;
  fd0Binary: string;
  scopeId: string;
  alias: string;
  environment: NodeJS.ProcessEnv;
}): TerminalLaunchPlan {
  const settings = validateTerminalLauncherSettings(options.settings, options.platform);
  const fd0Binary = validateString(options.fd0Binary, "fd0 executable", 4_096);
  const scopeId = validateString(options.scopeId, "Vault id", 512);
  const alias = validateString(options.alias, "SSH host alias", 512);
  if (!fd0Binary || !scopeId || !alias) throw new Error("SSH terminal command is incomplete");

  const profileId =
    settings.profileId === "automatic"
      ? automaticProfile(options.platform, options.detection)
      : settings.profileId;
  if (!profileId) throw new Error("No supported terminal was detected. Choose a custom launcher in Settings.");
  if (profileId === "in-app") {
    throw new Error("The in-app terminal does not use an external launch plan");
  }

  const fd0Arguments = [fd0Binary, "ssh", "connect", "--scope", scopeId, alias];
  if (profileId === "custom") {
    return {
      profileId,
      command: settings.customExecutable,
      arguments: [...settings.customArguments, ...fd0Arguments],
      environment: options.environment,
    };
  }

  if (profileId === "macos-terminal" || profileId === "iterm2") {
    const osascript = options.detection.commands.osascript;
    if (!builtinAvailable(profileId, options.platform, options.detection) || !osascript) {
      throw new Error("The selected terminal is not installed. Choose another launcher in Settings.");
    }
    const terminalCommand = [
      "/usr/bin/env",
      ...fd0EnvironmentArguments(options.environment),
      ...fd0Arguments,
    ];
    return {
      profileId,
      command: osascript,
      arguments: ["-e", profileId === "macos-terminal" ? terminalAppleScript : itermAppleScript, "--", ...terminalCommand],
      environment: options.environment,
    };
  }

  const direct = directCommand(profileId, options.detection);
  if (!direct.command || !builtinAvailable(profileId, options.platform, options.detection)) {
    throw new Error("The selected terminal is not installed. Choose another launcher in Settings.");
  }
  return {
    profileId,
    command: direct.command,
    arguments: [...direct.prefix, ...fd0Arguments],
    environment: options.environment,
  };
}

export async function spawnTerminal(
  plan: TerminalLaunchPlan,
  spawnProcess: typeof spawn = spawn,
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const options: SpawnOptions = {
      detached: true,
      stdio: "ignore",
      env: plan.environment,
      shell: false,
    };
    const child = spawnProcess(plan.command, plan.arguments, options);
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}
