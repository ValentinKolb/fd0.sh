import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";

export const repoRoot = resolve(import.meta.dirname, "../..");
export const buildDir = join(repoRoot, ".build", "desktop");
export const bridgeBin = join(buildDir, "fd0-desktop-bridge");
export const sftpBridgeBin = join(buildDir, "fd0-sftp-bridge");
export const agentBin = join(buildDir, "fd0-agent");
export const cliBin = join(buildDir, "fd0");
export const seedBin = join(buildDir, "fd0-desktop-dev-seed");
export const releaseVerifierBin = join(buildDir, "fd0-release-verify");
export const browserHostBin = join(buildDir, "fd0-browser-host");
export const runtimeDir = join(buildDir, "runtime");

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
  FD0_SFTP_BRIDGE_BIN: sftpBridgeBin,
  FD0_DESKTOP_MODE: "isolated",
  FD0_DESKTOP_USER_DATA: devUserData,
  FD0_AGENT_SYNC_DISABLED: "1",
  FD0_DESKTOP_DEV_PASSPHRASE: "fd0-desktop-dev",
  // FD0_HOME isolates the vault but not what fd0 renders out of it. Every
  // mutating ssh/kube/talos command rewrites the real dotfiles in $HOME, so a
  // dev run would otherwise clobber the developer's own ssh_config, kubeconfig
  // and talosconfig. Isolating the vault is not the same as isolating output.
  FD0_SSH_CONFIG_PATH: join(devHome, "render", "ssh", "fd0.conf"),
  FD0_KUBE_CONFIG_PATH: join(devHome, "render", "kube", "config.fd0"),
  FD0_KUBE_USER_CONFIG: join(devHome, "render", "kube", "config"),
  FD0_TALOS_CONFIG_PATH: join(devHome, "render", "talos", "config.fd0"),
  FD0_TALOS_USER_CONFIG: join(devHome, "render", "talos", "config"),
};
