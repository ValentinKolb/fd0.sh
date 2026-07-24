import { app } from "electron";
import { execFile } from "node:child_process";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const macServiceName = "sh.fd0.desktop.agent.plist";
const linuxServiceName = "fd0-agent.service";

export type AgentServiceStatus =
  | "enabled"
  | "requires-approval"
  | "not-registered"
  | "unsupported";

export class AgentLifecycle {
  readonly #platform: NodeJS.Platform;
  readonly #packaged: boolean;
  readonly #appPath: string;
  readonly #home: string;
  readonly #run: typeof execFileAsync;

  constructor(options?: {
    platform?: NodeJS.Platform;
    packaged?: boolean;
    appPath?: string;
    home?: string;
    run?: typeof execFileAsync;
  }) {
    this.#platform = options?.platform ?? process.platform;
    this.#packaged = options?.packaged ?? app.isPackaged;
    this.#appPath = options?.appPath ?? (process.env.APPIMAGE || process.execPath);
    this.#home = options?.home ?? homedir();
    this.#run = options?.run ?? execFileAsync;
  }

  async ensureRunning(): Promise<AgentServiceStatus> {
    if (!this.#packaged) return "unsupported";
    if (this.#platform === "darwin") {
      const settings = { type: "agentService" as const, serviceName: macServiceName };
      const current = app.getLoginItemSettings(settings);
      if (current.status === "not-registered" || current.status === "not-found") {
        app.setLoginItemSettings({ ...settings, openAtLogin: true });
      }
      const status = app.getLoginItemSettings(settings).status;
      return status === "enabled" ? "enabled"
        : status === "requires-approval" ? "requires-approval"
        : "not-registered";
    }
    if (this.#platform === "linux") {
      await this.#installLinuxUnit();
      await this.#systemctl(["enable", "--now", linuxServiceName]);
      return "enabled";
    }
    return "unsupported";
  }

  async restart(): Promise<void> {
    if (!this.#packaged) throw new Error("Native agent supervision is unavailable in development mode");
    if (this.#platform === "darwin") {
      await this.stop();
      const status = await this.ensureRunning();
      if (status !== "enabled") throw approvalError(status);
      return;
    }
    if (this.#platform === "linux") {
      await this.#installLinuxUnit();
      await this.#systemctl(["restart", linuxServiceName]);
      return;
    }
    throw new Error("Native agent supervision is unavailable on this platform");
  }

  async stop(): Promise<void> {
    if (!this.#packaged) return;
    if (this.#platform === "darwin") {
      const settings = { type: "agentService" as const, serviceName: macServiceName };
      const status = app.getLoginItemSettings(settings).status;
      if (status !== "not-registered" && status !== "not-found") {
        app.setLoginItemSettings({ ...settings, openAtLogin: false });
      }
      return;
    }
    if (this.#platform === "linux") {
      await this.#systemctl(["stop", linuxServiceName], true);
    }
  }

  async uninstall(): Promise<void> {
    await this.stop();
    if (this.#platform === "linux") {
      await this.#systemctl(["disable", linuxServiceName], true);
      await rm(this.#linuxUnitPath(), { force: true });
      await this.#systemctl(["daemon-reload"], true);
    }
  }

  async assertReady(status: AgentServiceStatus): Promise<void> {
    if (status === "enabled" || status === "unsupported") return;
    throw approvalError(status);
  }

  async guiLaunchesAtLogin(): Promise<boolean> {
    if (!this.#packaged) return false;
    if (this.#platform === "darwin") {
      return app.getLoginItemSettings({ type: "mainAppService" }).openAtLogin;
    }
    if (this.#platform === "linux") {
      try {
        await readFile(this.#linuxAutostartPath(), "utf8");
        return true;
      } catch {
        return false;
      }
    }
    return false;
  }

  async setGuiLaunchAtLogin(enabled: boolean): Promise<boolean> {
    if (!this.#packaged) return false;
    if (this.#platform === "darwin") {
      app.setLoginItemSettings({ type: "mainAppService", openAtLogin: enabled });
      return this.guiLaunchesAtLogin();
    }
    if (this.#platform === "linux") {
      const path = this.#linuxAutostartPath();
      if (!enabled) {
        await rm(path, { force: true });
        return false;
      }
      const entry = [
        "[Desktop Entry]",
        "Type=Application",
        "Name=fd0",
        "Comment=Password and infrastructure credential manager",
        `Exec=${desktopExecQuote(this.#appPath)}`,
        "Terminal=false",
        "X-GNOME-Autostart-enabled=true",
        "",
      ].join("\n");
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(path, entry, { mode: 0o600 });
      return true;
    }
    return false;
  }

  async #installLinuxUnit(): Promise<void> {
    const path = this.#linuxUnitPath();
    const unit = [
      "[Unit]",
      "Description=fd0 local vault service",
      "Documentation=https://fd0.sh/docs",
      "",
      "[Service]",
      "Type=simple",
      `ExecStart=${systemdQuote(this.#appPath)} --fd0-agent-relay`,
      "Restart=on-failure",
      "RestartSec=2s",
      "TimeoutStopSec=10s",
      "NoNewPrivileges=true",
      "",
      "[Install]",
      "WantedBy=default.target",
      "",
    ].join("\n");
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    let current = "";
    try {
      current = await readFile(path, "utf8");
    } catch {
      // Missing or unreadable unit is replaced atomically below.
    }
    if (current !== unit) {
      const staged = `${path}.new`;
      await writeFile(staged, unit, { mode: 0o600 });
      await rename(staged, path);
      await this.#systemctl(["daemon-reload"]);
    }
  }

  #linuxUnitPath(): string {
    return join(this.#home, ".config", "systemd", "user", linuxServiceName);
  }

  #linuxAutostartPath(): string {
    return join(this.#home, ".config", "autostart", "sh.fd0.desktop.desktop");
  }

  async #systemctl(args: string[], ignoreMissing = false): Promise<void> {
    try {
      await this.#run("systemctl", ["--user", ...args], { timeout: 15_000 });
    } catch (error) {
      if (ignoreMissing) return;
      const detail = error instanceof Error ? error.message : String(error);
      throw new Error(`Could not manage the fd0 background service: ${detail}`);
    }
  }
}

function approvalError(status: AgentServiceStatus): Error {
  if (status === "requires-approval") {
    return new Error("Allow fd0 in System Settings > General > Login Items, then try again");
  }
  return new Error("The fd0 background service could not be registered");
}

function systemdQuote(value: string): string {
  return `"${value.replaceAll("%", "%%").replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}

function desktopExecQuote(value: string): string {
  return `"${value.replaceAll("%", "%%").replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}
