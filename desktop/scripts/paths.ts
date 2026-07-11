import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

export const repoRoot = resolve(import.meta.dirname, "../..");
export const buildDir = join(repoRoot, ".build", "desktop");
export const bridgeBin = join(buildDir, "fd0-desktop-bridge");
export const agentBin = join(buildDir, "fd0-agent");
export const cliBin = join(buildDir, "fd0");
export const seedBin = join(buildDir, "fd0-desktop-dev-seed");

export const devHome =
  process.platform === "darwin"
    ? join(homedir(), "Library", "Application Support", "fd0 Desktop Dev")
    : join(homedir(), ".local", "share", "fd0-desktop-dev");

export const devUserData =
  process.platform === "darwin"
    ? join(homedir(), "Library", "Application Support", "fd0 Desktop Dev UI")
    : join(homedir(), ".local", "share", "fd0-desktop-dev-ui");

const uid = typeof process.getuid === "function" ? process.getuid() : "user";
export const devSSHSock = join(tmpdir(), `fd0-desktop-dev-ssh-${uid}.sock`);

export const devEnv: NodeJS.ProcessEnv = {
  ...process.env,
  FD0_HOME: devHome,
  FD0_SSH_SOCK: devSSHSock,
  FD0_AGENT_BIN: agentBin,
  FD0_BIN: cliBin,
  FD0_DESKTOP_BRIDGE_BIN: bridgeBin,
  FD0_DESKTOP_MODE: "isolated",
  FD0_DESKTOP_USER_DATA: devUserData,
  FD0_AGENT_SYNC_DISABLED: "1",
  FD0_DESKTOP_DEV_PASSPHRASE: "fd0-desktop-dev",
};
