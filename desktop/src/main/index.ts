import { basename, extname, join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { createReadStream } from "node:fs";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { homedir, tmpdir } from "node:os";
import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  ipcMain,
  Menu,
  nativeTheme,
  nativeImage,
  protocol,
  powerMonitor,
  session,
  shell,
  net,
  Tray,
  type MessageBoxOptions,
  type MenuItemConstructorOptions,
} from "electron";
import electronUpdater from "electron-updater";
import { BridgeSupervisor, DesktopBridgeError } from "./bridge";
import { AgentLifecycle } from "./agent-lifecycle";
import { DesktopAutoLock, type SecurityLockReason } from "./auto-lock";
import { ManagedClipboard } from "./managed-clipboard";
import { supportLink, trustedItemURL, type SupportLinkTarget } from "./external-links";
import { OperationGrants, type OperationGrantKind } from "./operation-grants";
import {
  checksumForAsset,
  compareSemver,
  desktopReleaseIdentity,
  selectDesktopRelease,
  type DesktopRelease,
} from "./release-verification";
import type {
  DesktopCommand,
  FieldRef,
  FieldView,
  GenerateSSHKeyInput,
  IdentityCardInfo,
  ItemDetail,
  RecordRef,
  SavePassInput,
  SaveSecretInput,
  SaveSSHHostInput,
  ScopeShareInfo,
  SyncPreparation,
  UnlockInput,
  UpdateStatus,
  VaultStatus,
} from "../shared/contracts";

let mainWindow: BrowserWindow | null = null;
let bridge: BridgeSupervisor | null = null;
const agentLifecycle = new AgentLifecycle();
const managedClipboard = new ManagedClipboard(clipboard);
const operationGrants = new OperationGrants();
let tray: Tray | null = null;
let updateTimer: NodeJS.Timeout | null = null;
let installingUpdate = false;
let updateState: UpdateStatus = { state: app.isPackaged ? "idle" : "unsupported" };
let selectedUpdateRelease: DesktopRelease | null = null;
let autoLock: DesktopAutoLock | null = null;
let disposeAutoLockEvents: (() => void) | null = null;
let securityStatusTimer: NodeJS.Timeout | null = null;
let securityStatusRefreshing = false;
let lastObservedUnlocked: boolean | undefined;
const { autoUpdater } = electronUpdater;
const applicationRoot = app.isPackaged ? app.getAppPath() : resolve(import.meta.dirname, "../..");
const nativeAgentManaged = app.isPackaged
  && process.env.FD0_HOME === undefined
  && process.env.FD0_SSH_SOCK === undefined;

app.setName("fd0");
if (!app.isPackaged) app.setPath("userData", requiredEnv("FD0_DESKTOP_USER_DATA"));
nativeTheme.themeSource = "dark";
protocol.registerSchemesAsPrivileged([
  {
    scheme: "fd0-app",
    privileges: {
      standard: true,
      secure: true,
      codeCache: true,
    },
  },
]);

const lifecycleCommand = process.argv.find((value) => [
  "--fd0-agent-service-stop",
  "--fd0-agent-service-restart",
  "--fd0-agent-service-uninstall",
].includes(value));
const relayExitCode = runPackagedRelay();
if (relayExitCode !== null) process.exit(relayExitCode);

if (!lifecycleCommand && !app.requestSingleInstanceLock()) {
  app.quit();
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required for the isolated desktop build`);
  return value;
}

function runtimeEnvironment(): NodeJS.ProcessEnv {
  const inherited = Object.fromEntries(
    ["PATH", "HOME", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL", "SHELL"]
      .map((name) => [name, process.env[name]])
      .filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
  if (app.isPackaged) {
    return {
      ...inherited,
      FD0_HOME: process.env.FD0_HOME?.trim() || join(homedir(), ".fd0"),
      FD0_AGENT_BIN: join(process.resourcesPath, "bin", "fd0-agent"),
      FD0_BIN: join(process.resourcesPath, "bin", "fd0"),
      FD0_DESKTOP_MODE: "system",
      FD0_DESKTOP_VERSION: app.getVersion(),
      ...(nativeAgentManaged ? { FD0_AGENT_MANAGED: "1" } : {}),
      ...(process.env.FD0_SSH_SOCK !== undefined ? { FD0_SSH_SOCK: process.env.FD0_SSH_SOCK } : {}),
    };
  }
  return {
    ...inherited,
    FD0_HOME: requiredEnv("FD0_HOME"),
    FD0_SSH_SOCK: requiredEnv("FD0_SSH_SOCK"),
    FD0_AGENT_BIN: requiredEnv("FD0_AGENT_BIN"),
    FD0_BIN: requiredEnv("FD0_BIN"),
    FD0_DESKTOP_MODE: "isolated",
    FD0_AGENT_SYNC_DISABLED: "1",
  };
}

function bridgeBinary(): string {
  if (!app.isPackaged) return requiredEnv("FD0_DESKTOP_BRIDGE_BIN");
  return join(process.resourcesPath, "bin", "fd0-desktop-bridge");
}

function runPackagedRelay(): number | null {
  if (!app.isPackaged) return null;
  const relays = [
    { marker: "--fd0-cli-relay", binary: "fd0" },
    { marker: "--fd0-agent-relay", binary: "fd0-agent" },
  ];
  const selected = relays
    .map((relay) => ({ ...relay, index: process.argv.indexOf(relay.marker) }))
    .filter((relay) => relay.index >= 0);
  if (selected.length === 0) return null;
  if (selected.length !== 1) {
    console.error("fd0 Desktop: invalid CLI relay request");
    return 2;
  }
  const relay = selected[0]!;
  const executable = join(process.resourcesPath, "bin", relay.binary);
  const result = spawnSync(executable, process.argv.slice(relay.index + 1), {
    env: {
      ...runtimeEnvironment(),
      FD0_DESKTOP_MANAGED: "1",
      FD0_DESKTOP_APP: process.env.APPIMAGE || process.execPath,
    },
    stdio: "inherit",
  });
  if (result.error) {
    console.error(`fd0 Desktop: ${result.error.message}`);
    return 1;
  }
  return result.status ?? 1;
}

function sendCommand(command: DesktopCommand): void {
  mainWindow?.webContents.send("desktop:command", command);
}

function publishUpdate(status: UpdateStatus): void {
  updateState = status;
  mainWindow?.webContents.send("desktop:update", status);
}

function showAppMessageBox(options: MessageBoxOptions) {
  return mainWindow ? dialog.showMessageBox(mainWindow, options) : dialog.showMessageBox(options);
}

async function checkForUpdates(): Promise<UpdateStatus> {
  if (!app.isPackaged) return updateState;
  selectedUpdateRelease = null;
  publishUpdate({ state: "checking" });
  try {
    const release = await resolveDesktopUpdateRelease();
    if (compareSemver(release.version, app.getVersion()) <= 0) {
      selectedUpdateRelease = null;
      publishUpdate({ state: "current", version: app.getVersion() });
      return updateState;
    }
    selectedUpdateRelease = release;
    autoUpdater.setFeedURL({ provider: "generic", url: release.feedURL });
    await autoUpdater.checkForUpdates();
  } catch (error) {
    console.error("fd0 update check failed", error);
    publishUpdate({ state: "error", message: "Could not check for updates." });
  }
  return updateState;
}

async function resolveDesktopUpdateRelease(): Promise<DesktopRelease> {
  const response = await net.fetch("https://api.github.com/repos/ValentinKolb/fd0.sh/releases?per_page=30", {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": `fd0-desktop/${app.getVersion()}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!response.ok) throw new Error(`GitHub release lookup failed with HTTP ${response.status}`);
  const payload = await response.json() as unknown;
  const allowPrerelease = app.getVersion().includes("-");
  const release = selectDesktopRelease(payload, allowPrerelease);
  if (!release) throw new Error("No fd0 Desktop release is available");
  return release;
}

async function fetchReleaseFile(release: DesktopRelease, name: string, maxBytes = 4 << 20): Promise<Uint8Array> {
  const response = await net.fetch(new URL(name, release.feedURL).toString());
  if (!response.ok) throw new Error(`Could not fetch ${name}: HTTP ${response.status}`);
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) throw new Error(`${name} exceeds the update metadata limit`);
  const body = new Uint8Array(await response.arrayBuffer());
  if (body.byteLength > maxBytes) throw new Error(`${name} exceeds the update metadata limit`);
  return body;
}

async function verifyDownloadedDesktopUpdate(version: string, downloadedFile: string): Promise<void> {
  if (process.platform !== "linux") return;
  const release = selectedUpdateRelease;
  if (!release || release.version !== version || compareSemver(version, app.getVersion()) <= 0) {
    throw new Error("Downloaded update does not match the selected newer release");
  }
  const assetArch = process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : "";
  if (!assetArch) throw new Error(`Unsupported update architecture: ${process.arch}`);
  const assetName = `fd0-desktop_${version}_linux_${assetArch}.AppImage`;
  const [manifestBytes, signature, certificate, actual] = await Promise.all([
    fetchReleaseFile(release, "checksums.txt"),
    fetchReleaseFile(release, "checksums.txt.sig"),
    fetchReleaseFile(release, "checksums.txt.pem"),
    sha256Path(downloadedFile),
  ]);
  const manifest = new TextDecoder().decode(manifestBytes);
  const expected = checksumForAsset(manifest, assetName);
  if (actual !== expected) throw new Error("Downloaded update does not match the authenticated release manifest");

  const root = await mkdtemp(join(tmpdir(), "fd0-update-"));
  try {
    const manifestPath = join(root, "checksums.txt");
    const signaturePath = join(root, "checksums.txt.sig");
    const certificatePath = join(root, "checksums.txt.pem");
    await Promise.all([
      writeFile(manifestPath, manifestBytes, { mode: 0o600 }),
      writeFile(signaturePath, signature, { mode: 0o600 }),
      writeFile(certificatePath, certificate, { mode: 0o600 }),
    ]);
    const cosign = process.env.FD0_COSIGN_BIN?.trim() || "cosign";
    const verification = spawnSync(cosign, [
      "verify-blob",
      "--certificate", certificatePath,
      "--signature", signaturePath,
      "--certificate-identity-regexp", desktopReleaseIdentity(release.tag),
      "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
      manifestPath,
    ], {
      env: runtimeEnvironment(),
      encoding: "utf8",
      timeout: 30_000,
    });
    if (verification.error) {
      if ((verification.error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error("Cosign is required to authenticate Linux desktop updates");
      }
      throw verification.error;
    }
    if (verification.status !== 0) throw new Error("Cosign rejected the fd0 Desktop release signature");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function sha256Path(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

function isExpectedUpdateVersion(version: string): boolean {
  try {
    return selectedUpdateRelease?.version === version && compareSemver(version, app.getVersion()) > 0;
  } catch {
    return false;
  }
}

function announceDownloadedUpdate(version: string): void {
  publishUpdate({ state: "ready", version, progress: 100 });
  void showAppMessageBox({
    type: "info",
    buttons: ["Restart fd0", "Later"],
    defaultId: 0,
    cancelId: 1,
    title: "fd0 is ready to update",
    message: `fd0 ${version} has been downloaded.`,
    detail: "Restart now to install it. fd0 will stop the current agent so the app, CLI, and agent stay on one version.",
    noLink: true,
  }).then((answer) => {
    if (answer.response === 0) {
      void installReadyUpdate().catch((error) => {
        console.error("fd0 update install failed", error);
        publishUpdate({ state: "error", message: "Could not prepare fd0 for the update." });
      });
    }
  });
}

function configureUpdater(): void {
  if (!app.isPackaged) return;
  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.allowPrerelease = app.getVersion().includes("-");
  if (process.platform === "darwin") autoUpdater.channel = process.arch;
  autoUpdater.allowDowngrade = false;
  autoUpdater.on("checking-for-update", () => publishUpdate({ state: "checking" }));
  autoUpdater.on("update-not-available", () => publishUpdate({ state: "current", version: app.getVersion() }));
  autoUpdater.on("update-available", (info) => {
    if (!isExpectedUpdateVersion(info.version)) {
      publishUpdate({ state: "error", message: "The update feed returned an unexpected release." });
      return;
    }
    publishUpdate({ state: "available", version: info.version });
    void showAppMessageBox({
      type: "info",
      buttons: ["Download", "Later"],
      defaultId: 0,
      cancelId: 1,
      title: "fd0 update available",
      message: `fd0 ${info.version} is available.`,
      detail: "Download the signed update now? You can keep using fd0 while it downloads.",
      noLink: true,
    }).then((answer) => {
      if (answer.response !== 0) return;
      publishUpdate({ state: "downloading", version: info.version, progress: 0 });
      void autoUpdater.downloadUpdate().catch((error) => {
        console.error("fd0 update download failed", error);
        publishUpdate({ state: "error", message: "Could not download the update." });
      });
    });
  });
  autoUpdater.on("download-progress", (progress) => {
    publishUpdate({ state: "downloading", version: updateState.version, progress: Math.max(0, Math.min(100, progress.percent)) });
  });
  autoUpdater.on("update-downloaded", (info) => {
    void verifyDownloadedDesktopUpdate(info.version, info.downloadedFile)
      .then(() => announceDownloadedUpdate(info.version))
      .catch((error) => {
        console.error("fd0 update authentication failed", error);
        publishUpdate({
          state: "error",
          message: error instanceof Error ? error.message : "Could not authenticate the downloaded update.",
        });
      });
  });
  autoUpdater.on("error", (error) => {
    console.error("fd0 updater error", error);
    publishUpdate({ state: "error", message: "The updater encountered an error." });
  });
  updateTimer = setTimeout(() => {
    void checkForUpdates();
    updateTimer = setInterval(() => void checkForUpdates(), 6 * 60 * 60_000);
  }, 15_000);
}

async function installReadyUpdate(): Promise<void> {
  if (updateState.state !== "ready") throw new Error("No downloaded fd0 update is ready to install");
  if (installingUpdate) return;
  installingUpdate = true;
  try {
    if (nativeAgentManaged) {
      await agentLifecycle.stop();
    } else if (bridge) {
      await bridge.request("agent.prepareUpdate", {}, 10_000);
    }
    setTimeout(() => autoUpdater.quitAndInstall(false, true), 100);
  } catch (error) {
    installingUpdate = false;
    throw error;
  }
}

function observeVaultStatus(status: VaultStatus): VaultStatus {
  const lockedTransition = lastObservedUnlocked === true && !status.unlocked;
  lastObservedUnlocked = status.unlocked;
  autoLock?.observe(status);
  if (lockedTransition) {
    managedClipboard.clear();
    operationGrants.clear();
    sendCommand("refresh");
  }
  return status;
}

async function refreshSecurityStatus(): Promise<void> {
  if (!bridge || securityStatusRefreshing) return;
  securityStatusRefreshing = true;
  try {
    observeVaultStatus(await bridge.request<VaultStatus>("vault.status", {}));
  } catch (error) {
    console.error("fd0 security status refresh failed", error);
  } finally {
    securityStatusRefreshing = false;
  }
}

async function requestVaultLock(): Promise<void> {
  if (!bridge) throw new Error("fd0 bridge is unavailable");
  const status = await bridge.request<VaultStatus>("vault.lock", {});
  observeVaultStatus(status);
  managedClipboard.clear();
  operationGrants.clear();
  sendCommand("refresh");
}

function writeManagedClipboard(value: string): { clearAfterSeconds: number } {
  managedClipboard.write(value);
  return { clearAfterSeconds: 30 };
}

function reportAutomaticLockFailure(error: unknown): void {
  console.error("fd0 automatic lock failed", error);
}

function configureAutoLock(): () => void {
  autoLock = new DesktopAutoLock({
    getSystemIdleState: (thresholdSeconds) => powerMonitor.getSystemIdleState(thresholdSeconds),
    lock: async (_reason: SecurityLockReason) => requestVaultLock(),
    onError: reportAutomaticLockFailure,
  });
  autoLock.start();

  const lockFor = (reason: SecurityLockReason) => {
    void autoLock?.lockNow(reason, true).catch(reportAutomaticLockFailure);
  };
  const onSuspend = () => lockFor("suspend");
  const onResume = () => lockFor("resume");
  const onLockScreen = () => lockFor("system-lock");
  const onSessionInactive = () => lockFor("session-inactive");
  powerMonitor.on("suspend", onSuspend);
  powerMonitor.on("resume", onResume);
  if (process.platform === "darwin" || process.platform === "win32") {
    powerMonitor.on("lock-screen", onLockScreen);
  }
  if (process.platform === "darwin") {
    powerMonitor.on("user-did-resign-active", onSessionInactive);
  }

  return () => {
    autoLock?.stop();
    powerMonitor.removeListener("suspend", onSuspend);
    powerMonitor.removeListener("resume", onResume);
    if (process.platform === "darwin" || process.platform === "win32") {
      powerMonitor.removeListener("lock-screen", onLockScreen);
    }
    if (process.platform === "darwin") {
      powerMonitor.removeListener("user-did-resign-active", onSessionInactive);
    }
    autoLock = null;
  };
}

async function lockVaultFromMain(): Promise<void> {
  try {
    await requestVaultLock();
  } catch (error) {
    dialog.showErrorBox("fd0 could not lock", error instanceof Error ? error.message : String(error));
  }
}

function showMainWindow(): void {
  if (!mainWindow) mainWindow = createWindow();
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
}

function createTray(): void {
  const source = join(applicationRoot, "resources", "tray.png");
  const image = nativeImage.createFromPath(source).resize({ width: 18, height: 18 });
  if (process.platform === "darwin") image.setTemplateImage(true);
  tray = new Tray(image);
  tray.setToolTip("fd0");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "Open fd0", click: showMainWindow },
    { type: "separator" },
    { label: "Lock Vault", click: () => void lockVaultFromMain() },
    { type: "separator" },
    { label: "Quit fd0", click: () => app.quit() },
  ]));
  tray.on("click", showMainWindow);
}

function buildMenu(): void {
  const isMac = process.platform === "darwin";
  const template: MenuItemConstructorOptions[] = [
    ...(isMac
      ? [
          {
            label: "fd0",
            submenu: [
              { role: "about" as const },
              { type: "separator" as const },
              {
                label: "Settings…",
                accelerator: "CmdOrCtrl+,",
                click: () => sendCommand("open-settings"),
              },
              { type: "separator" as const },
              { role: "services" as const },
              { type: "separator" as const },
              { role: "hide" as const },
              { role: "hideOthers" as const },
              { role: "unhide" as const },
              { type: "separator" as const },
              { role: "quit" as const },
            ],
          },
        ]
      : []),
    {
      label: "File",
      submenu: [
        { label: "New Item", accelerator: "CmdOrCtrl+N", click: () => sendCommand("new-item") },
        { type: "separator" },
        isMac ? { role: "close" } : { role: "quit" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
        { type: "separator" },
        { label: "Find", accelerator: "CmdOrCtrl+F", click: () => sendCommand("focus-search") },
      ],
    },
    {
      label: "Vault",
      submenu: [
        { label: "Refresh", accelerator: "CmdOrCtrl+R", click: () => sendCommand("refresh") },
        {
          label: "Lock",
          accelerator: "CmdOrCtrl+Shift+L",
          click: () => void lockVaultFromMain(),
        },
      ],
    },
    {
      label: "View",
      submenu: [
        ...(process.env.NODE_ENV === "development"
          ? [{ role: "reload" as const }, { role: "toggleDevTools" as const }, { type: "separator" as const }]
          : []),
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },
    {
      label: "Window",
      submenu: [{ role: "minimize" }, { role: "zoom" }, ...(isMac ? [{ type: "separator" as const }, { role: "front" as const }] : [])],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function assertTrustedSender(event: Electron.IpcMainInvokeEvent): void {
  if (!mainWindow || event.sender.id !== mainWindow.webContents.id) {
    throw new Error("Untrusted IPC sender");
  }
}

type IPCResult<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string; action?: string; retryable: boolean } };

function flattenFields(fields: FieldView[]): FieldView[] {
  return fields.flatMap((field) => [field, ...flattenFields(field.children ?? [])]);
}

function dialogText(value: string, fallback: string): string {
  const clean = value.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return [...clean].slice(0, 160).join("") || fallback;
}

async function loadTrustedItem(client: BridgeSupervisor, ref: RecordRef): Promise<ItemDetail> {
  return client.request<ItemDetail>("item.detail", {
    scopeId: ref.scopeId,
    name: ref.name,
    ...(ref.raw ? { raw: true } : {}),
  });
}

async function confirmItemAction(
  client: BridgeSupervisor,
  ref: RecordRef,
  options: {
    title: string;
    action: string;
    message(detail: ItemDetail): string;
    detail: string;
    type?: "question" | "warning";
  },
): Promise<ItemDetail | null> {
  if (!mainWindow) throw new Error("fd0 window is unavailable");
  const item = await loadTrustedItem(client, ref);
  const confirmation = await dialog.showMessageBox(mainWindow, {
    type: options.type ?? "question",
    buttons: ["Cancel", options.action],
    defaultId: 0,
    cancelId: 0,
    title: options.title,
    message: options.message(item),
    detail: options.detail,
    noLink: true,
  });
  return confirmation.response === 1 ? item : null;
}

async function issueEditGrant(
  client: BridgeSupervisor,
  ref: RecordRef,
  kind: OperationGrantKind,
): Promise<string | null> {
  const detail = await confirmItemAction(client, ref, {
    title: "Edit protected item?",
    action: "Edit",
    message: ({ item }) => `Edit ${dialogText(item.title, "this item")} from ${dialogText(item.vault, "this vault")}?`,
    detail: "The editor will receive this item's decrypted fields until you save or close it.",
  });
  return detail ? operationGrants.issue(kind, ref.scopeId, ref.name) : null;
}

function requireEditGrant(
  authorization: string | undefined,
  kind: OperationGrantKind,
  scopeId: string,
  name: string,
): void {
  if (!operationGrants.consume(authorization, kind, scopeId, name)) {
    throw new Error("Edit authorization expired. Close the editor and open the item again.");
  }
}

async function respond<T>(operation: () => Promise<T>): Promise<IPCResult<T>> {
  try {
    return { ok: true, value: await operation() };
  } catch (error) {
    if (error instanceof DesktopBridgeError) {
      return {
        ok: false,
        error: {
          code: error.code,
          message: error.message,
          action: error.action,
          retryable: error.retryable,
        },
      };
    }
    return {
      ok: false,
      error: {
        code: "desktop_error",
        message: error instanceof Error ? error.message : "fd0 could not complete that action.",
        retryable: true,
      },
    };
  }
}

function registerIPC(client: BridgeSupervisor): void {
  const handle = <TArgs extends unknown[], TResult>(
    channel: string,
    operation: (...args: TArgs) => Promise<TResult>,
  ): void => {
    ipcMain.handle(channel, (event, ...args: TArgs) => {
      assertTrustedSender(event);
      return respond(() => operation(...args));
    });
  };

  handle("fd0:status", async () => observeVaultStatus(await client.request<VaultStatus>("vault.status", {})));
  handle("fd0:create-vault", async (passphrase: string, label: string) => {
    await ensureManagedAgent(client);
    const buffer = Buffer.from(passphrase, "utf8");
    const encoded = buffer.toString("base64");
    buffer.fill(0);
    return observeVaultStatus(await client.request<VaultStatus>("vault.create", { passphrase: encoded, label }));
  });
  handle("fd0:unlock", async (input: UnlockInput) => {
    await ensureManagedAgent(client);
    const passphrase = Buffer.from(input?.passphrase ?? "", "utf8");
    const pin = Buffer.from(input?.pin ?? "", "utf8");
    const params = {
      method: input?.method ?? "",
      passphrase: passphrase.toString("base64"),
      pin: pin.toString("base64"),
    };
    passphrase.fill(0);
    pin.fill(0);
    return observeVaultStatus(await client.request<VaultStatus>("vault.unlock", params, 60_000));
  });
  handle("fd0:lock", async () => {
    const status = observeVaultStatus(await client.request<VaultStatus>("vault.lock", {}));
    managedClipboard.clear();
    operationGrants.clear();
    sendCommand("refresh");
    return status;
  });
  handle("fd0:restart-agent", async () => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Restart local service"],
      defaultId: 0,
      cancelId: 0,
      title: "Restart the fd0 local service?",
      message: "Restart the fd0 local service?",
      detail: "The vault will lock. Unlock it again after the restart.",
      noLink: true,
    });
    if (confirmation.response !== 1) return observeVaultStatus(await client.request<VaultStatus>("vault.status", {}));
    if (nativeAgentManaged) {
      await agentLifecycle.restart();
      return observeVaultStatus(await client.request<VaultStatus>("vault.status", {}));
    }
    return observeVaultStatus(await client.request<VaultStatus>("agent.restart", {}, 15_000));
  });
  handle("fd0:restore-vault", async (recoveryPassphrase: string, newPassphrase: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const selection = await dialog.showOpenDialog(mainWindow, {
      title: "Restore an fd0 vault",
      properties: ["openFile"],
      filters: [{ name: "fd0 recovery file", extensions: ["cbor", "fd0-recovery"] }, { name: "All files", extensions: ["*"] }],
    });
    const path = selection.filePaths[0];
    if (selection.canceled || !path) return null;
    const info = await stat(path);
    if (!info.isFile() || info.size > 128 * 1024) throw new Error("Recovery files must be smaller than 128 KB");
    const data = await readFile(path);
    const recovery = Buffer.from(recoveryPassphrase, "utf8");
    const local = Buffer.from(newPassphrase, "utf8");
    const params = {
      data: data.toString("base64"),
      recoveryPassphrase: recovery.toString("base64"),
      newPassphrase: local.toString("base64"),
    };
    data.fill(0);
    recovery.fill(0);
    local.fill(0);
    const status = await client.request<VaultStatus | null>("recovery.import", params, 2 * 60_000);
    return status ? observeVaultStatus(status) : null;
  });
  handle("fd0:export-recovery", async (passphrase: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const destination = await dialog.showSaveDialog(mainWindow, {
      title: "Save fd0 recovery file",
      defaultPath: join(app.getPath("documents"), "fd0-recovery.cbor"),
      filters: [{ name: "fd0 recovery file", extensions: ["cbor"] }],
    });
    if (destination.canceled || !destination.filePath) return { saved: false };
    const secret = Buffer.from(passphrase, "utf8");
    const encoded = secret.toString("base64");
    secret.fill(0);
    return client.request<{ saved: boolean; verified: boolean }>(
      "recovery.exportFile",
      { path: destination.filePath, passphrase: encoded },
      2 * 60_000,
    );
  });
  handle("fd0:set-default-auth", async (method: string) => observeVaultStatus(await client.request<VaultStatus>("auth.default", { method })));
  handle("fd0:inventory", () => client.request("inventory.list", {}));
  handle("fd0:item-detail", (ref: RecordRef) => client.request("item.detail", ref));
  handle("fd0:reveal", async (ref: FieldRef) => {
    const detail = await loadTrustedItem(client, ref);
    const field = flattenFields(detail.fields).find((candidate) => candidate.path === ref.path);
    if (!field) throw new Error("That field is no longer available");
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Reveal"],
      defaultId: 0,
      cancelId: 0,
      title: "Reveal protected value?",
      message: `Reveal ${dialogText(field.name, "this field")} from ${dialogText(detail.item.title, "this item")}?`,
      detail: `Vault: ${dialogText(detail.item.vault, "this vault")}\n\nThe value will be visible on screen for 15 seconds.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return null;
    return client.request("field.value", ref);
  });
  handle("fd0:copy", async (ref: FieldRef) => {
    const result = await client.request<{ value: string }>("field.value", ref);
    return writeManagedClipboard(result.value);
  });
  handle("fd0:copy-text", async (value: string) => {
    if (typeof value !== "string" || value.length > 64 * 1024) throw new Error("Clipboard value is invalid");
    return writeManagedClipboard(value);
  });
  handle("fd0:save-pass", async (input: SavePassInput) => {
    const { authorization, ...params } = input;
    if (input.create !== true) {
      requireEditGrant(authorization, "pass.edit", input.scopeId, `pass:${input.recordName.trim()}`);
    }
    return client.request("pass.save", params);
  });
  handle("fd0:edit-pass", async (ref: RecordRef) => {
    const authorization = await issueEditGrant(client, ref, "pass.edit");
    if (!authorization) return null;
    const input = await client.request<SavePassInput>("pass.editData", ref);
    return { ...input, authorization };
  });
  handle("fd0:set-favorite", (ref: RecordRef, favorite: boolean) => client.request("pass.favorite", { ...ref, favorite: Boolean(favorite) }));
  handle("fd0:pick-attachment", async () => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const selection = await dialog.showOpenDialog(mainWindow, {
      title: "Attach a small file",
      properties: ["openFile"],
    });
    const path = selection.filePaths[0];
    if (selection.canceled || !path) return null;
    const info = await stat(path);
    if (!info.isFile() || info.size > 32 * 1024) throw new Error("Attachments must be smaller than 32 KB");
    const data = await readFile(path);
    const result = {
      name: basename(path),
      mime: mimeForExtension(extname(path)),
      size: data.length,
      sha256: createHash("sha256").update(data).digest("hex"),
      data_b64: data.toString("base64"),
    };
    data.fill(0);
    return result;
  });
  handle("fd0:save-secret", async (input: SaveSecretInput) => {
    const { authorization, ...params } = input;
    if (input.create !== true) {
      requireEditGrant(authorization, "secret.edit", input.scopeId, input.oldName?.trim() ?? "");
    }
    return client.request("secret.save", params);
  });
  handle("fd0:edit-secret", async (ref: RecordRef) => {
    const authorization = await issueEditGrant(client, ref, "secret.edit");
    if (!authorization) return null;
    const input = await client.request<SaveSecretInput>("secret.editData", ref);
    return { ...input, authorization };
  });
  handle("fd0:save-ssh-host", async (input: SaveSSHHostInput) => {
    const { authorization, ...params } = input;
    if (input.oldName) {
      requireEditGrant(authorization, "ssh.edit", input.scopeId, input.oldName);
    }
    return client.request("sshHost.save", params);
  });
  handle("fd0:edit-ssh-host", async (ref: RecordRef) => {
    const authorization = await issueEditGrant(client, ref, "ssh.edit");
    if (!authorization) return null;
    const input = await client.request<SaveSSHHostInput>("sshHost.editData", ref);
    return { ...input, authorization };
  });
  handle("fd0:generate-ssh-key", (input: GenerateSSHKeyInput) => client.request("sshKey.generate", input));
  handle("fd0:import-config", async (kind: "kubernetes" | "talos", scopeId: string) => {
    if (!mainWindow || (kind !== "kubernetes" && kind !== "talos")) throw new Error("Invalid config import");
    const selection = await dialog.showOpenDialog(mainWindow, {
      title: kind === "kubernetes" ? "Import kubeconfig" : "Import talosconfig",
      properties: ["openFile"],
      filters: [{ name: "YAML config", extensions: ["yaml", "yml", "config"] }, { name: "All files", extensions: ["*"] }],
    });
    const path = selection.filePaths[0];
    if (selection.canceled || !path) return null;
    const info = await stat(path);
    if (!info.isFile() || info.size > 512 * 1024) throw new Error("Config must be a file smaller than 512 KB");
    const data = await readFile(path);
    const encoded = data.toString("base64");
    data.fill(0);
    return client.request("config.import", { kind, scopeId, data: encoded });
  });
  handle("fd0:save-attachment", async (ref: FieldRef) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const result = await client.request<{ name: string; mime?: string; data: string }>("file.value", ref);
    const name = basename(result.name || "fd0-attachment");
    const destination = await dialog.showSaveDialog(mainWindow, {
      title: "Save attachment",
      defaultPath: join(app.getPath("downloads"), name),
    });
    if (destination.canceled || !destination.filePath) return { saved: false };
    const data = Buffer.from(result.data, "base64");
    if (data.length > 32 * 1024) {
      data.fill(0);
      throw new Error("Attachment is larger than 32 KB");
    }
    try {
      await writeFile(destination.filePath, data, { mode: 0o600 });
      await chmod(destination.filePath, 0o600);
    } finally {
      data.fill(0);
    }
    return { saved: true };
  });
  handle("fd0:remove", async (ref: RecordRef) => {
    const item = await confirmItemAction(client, ref, {
      title: "Remove item?",
      action: "Remove",
      message: ({ item }) => `Remove ${dialogText(item.title, "this item")} from ${dialogText(item.vault, "this vault")}?`,
      detail: "This creates a deletion that will sync to other devices and vault members.",
      type: "warning",
    });
    if (!item) return { ok: false };
    return client.request("item.remove", ref);
  });
  handle("fd0:create-scope", (label: string) => client.request("scope.create", { label }));
  handle("fd0:scope-share-info", (scopeId: string) => client.request("scope.shareInfo", { scopeId }));
  handle("fd0:scope-add-member", async (scopeId: string, label: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const info = await client.request<ScopeShareInfo>("scope.shareInfo", { scopeId });
    const contact = info.contacts.find((candidate) => candidate.label === label && !candidate.shared);
    if (!contact) throw new Error("That trusted contact is no longer available");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Share vault"],
      defaultId: 0,
      cancelId: 0,
      title: `Share ${dialogText(info.scopeLabel, "this vault")}?`,
      message: `Give ${dialogText(contact.label, "this contact")} access to ${dialogText(info.scopeLabel, "this vault")}?`,
      detail: `Safety fingerprint: ${contact.fingerprint}…\n\nThey will be able to decrypt every current and future item in this vault.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("scope.addMember", { scopeId, label: contact.label });
  });
  handle("fd0:scope-remove-member", async (scopeId: string, memberId: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const info = await client.request<ScopeShareInfo>("scope.shareInfo", { scopeId });
    const member = info.members.find((candidate) => candidate.id === memberId && !candidate.self);
    if (!member) throw new Error("That vault member is no longer available");
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "warning",
      buttons: ["Cancel", "Remove access"],
      defaultId: 0,
      cancelId: 0,
      title: `Remove ${dialogText(member.label, "this member")}?`,
      message: `Remove ${dialogText(member.label, "this member")} from ${dialogText(info.scopeLabel, "this vault")}?`,
      detail: `Safety fingerprint: ${member.fingerprint}…\n\nfd0 will rotate the vault key. They keep anything already downloaded, but cannot decrypt future changes.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("scope.removeMember", { scopeId, memberId });
  });
  handle("fd0:card-export", () => client.request("card.export", {}));
  handle("fd0:card-inspect", (url: string) => client.request("card.inspect", { url }));
  handle("fd0:card-import", async (url: string, label: string) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const preview = await client.request<IdentityCardInfo>("card.inspect", { url });
    const displayLabel = typeof label === "string" && label.trim() ? label.trim().slice(0, 80) : preview.shortId;
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "question",
      buttons: ["Cancel", "Trust contact"],
      defaultId: 0,
      cancelId: 0,
      title: "Verify identity card",
      message: `Did you verify ${displayLabel}'s safety number out of band?`,
      detail: `${preview.safetyNumber}\n\nOnly continue if the other person read the same number to you through a trusted channel.`,
      noLink: true,
    });
    if (confirmation.response !== 1) return { ok: false };
    return client.request("card.import", { url, label });
  });
  handle("fd0:sync", async () => {
    const preparation = await client.request<SyncPreparation>("sync.prepare", {}, 30_000);
    if (preparation.requiresConfirmation) {
      if (!mainWindow) throw new Error("fd0 window is unavailable");
      const name = dialogText(preparation.label ?? "", preparation.serverUrl);
      const confirmation = await dialog.showMessageBox(mainWindow, {
        type: "warning",
        buttons: ["Cancel", "Trust and sync"],
        defaultId: 0,
        cancelId: 0,
        title: "Trust this fd0 service?",
        message: `Trust ${name}?`,
        detail: `${preparation.serverUrl}\n\nSafety fingerprint:\n${preparation.fingerprint}\n\nVerify this fingerprint through an independent trusted channel before continuing.`,
        noLink: true,
      });
      if (confirmation.response !== 1) return { ok: false, cancelled: true };
    }
    if (!preparation.alreadyPinned) {
      await client.request("sync.pin", {
        serverUrl: preparation.serverUrl,
        serverPub: preparation.serverPub,
      }, 30_000);
    }
    return client.request<{ ok: boolean }>("sync.run", {
      serverUrl: preparation.serverUrl,
    }, 5 * 60_000);
  });
  handle("fd0:launch-at-login", async () => agentLifecycle.guiLaunchesAtLogin());
  handle("fd0:set-launch-at-login", async (value: boolean) => {
    return agentLifecycle.setGuiLaunchAtLogin(Boolean(value));
  });
  handle("fd0:open-item-url", async (ref: RecordRef) => {
    if (!mainWindow) throw new Error("fd0 window is unavailable");
    const detail = await loadTrustedItem(client, ref);
    const website = flattenFields(detail.fields).find((field) => field.type === "url" && field.path === "$url");
    const url = trustedItemURL(website?.value ?? "");
    const host = new URL(url).host;
    const confirmation = await dialog.showMessageBox(mainWindow, {
      type: "question",
      buttons: ["Cancel", "Open website"],
      defaultId: 0,
      cancelId: 0,
      title: "Open website?",
      message: `Open ${host} for ${dialogText(detail.item.title, "this item")}?`,
      detail: url,
      noLink: true,
    });
    if (confirmation.response !== 1) return;
    await shell.openExternal(url);
  });
  handle("fd0:open-support-link", async (target: SupportLinkTarget) => {
    await shell.openExternal(supportLink(target));
  });
  handle("fd0:update-status", async () => updateState);
  handle("fd0:check-updates", () => checkForUpdates());
  handle("fd0:install-update", async () => {
    await installReadyUpdate();
  });
}

async function ensureManagedAgent(client: BridgeSupervisor): Promise<void> {
  if (!nativeAgentManaged) return;
  await agentLifecycle.assertReady(await agentLifecycle.ensureRunning());
  let status = await client.request<VaultStatus>("vault.status", {});
  if (status.agentRunning && status.agentMismatch) {
    await agentLifecycle.restart();
  }
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    status = await client.request<VaultStatus>("vault.status", {});
    if (status.agentRunning && !status.agentMismatch) return;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  throw new Error("The fd0 background service did not become ready");
}

function mimeForExtension(extension: string): string {
  switch (extension.toLowerCase()) {
    case ".txt": return "text/plain";
    case ".json": return "application/json";
    case ".pem":
    case ".crt": return "application/x-pem-file";
    case ".key": return "application/octet-stream";
    default: return "application/octet-stream";
  }
}

function createWindow(): BrowserWindow {
  const mac = process.platform === "darwin";
  const window = new BrowserWindow({
    width: 1180,
    height: 780,
    minWidth: 860,
    minHeight: 600,
    show: false,
    backgroundColor: "#0b0e0c",
    ...(mac
      ? {
          titleBarStyle: "hiddenInset" as const,
          trafficLightPosition: { x: 18, y: 18 },
        }
      : {}),
    webPreferences: {
      preload: join(applicationRoot, "out", "preload", "index.cjs"),
      additionalArguments: [app.isPackaged ? "--fd0-system" : "--fd0-isolated"],
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event, url) => {
    const current = window.webContents.getURL();
    if (url !== current) event.preventDefault();
  });
  window.on("closed", () => {
    if (mainWindow === window) mainWindow = null;
  });
  window.once("ready-to-show", () => window.show());
  if (!app.isPackaged && process.env.ELECTRON_RENDERER_URL) {
    void window.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    void window.loadURL("fd0-app://app/index.html");
  }
  return window;
}

function registerAppProtocol(): void {
  const rendererRoot = resolve(applicationRoot, "out", "renderer");
  protocol.handle("fd0-app", (request) => {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return new Response("Not found", { status: 404 });
    }
    if (url.hostname !== "app" || url.username !== "" || url.password !== "" || url.port !== "") {
      return new Response("Not found", { status: 404 });
    }
    let pathname: string;
    try {
      pathname = decodeURIComponent(url.pathname);
    } catch {
      return new Response("Not found", { status: 404 });
    }
    const target = resolve(rendererRoot, pathname.replace(/^\/+/, "") || "index.html");
    if (target !== rendererRoot && !target.startsWith(rendererRoot + sep)) {
      return new Response("Not found", { status: 404 });
    }
    return net.fetch(pathToFileURL(target).toString());
  });
}

async function start(): Promise<void> {
  await app.whenReady();
  if (lifecycleCommand) {
    if (lifecycleCommand === "--fd0-agent-service-restart") {
      await agentLifecycle.restart();
    } else if (lifecycleCommand === "--fd0-agent-service-stop") {
      await agentLifecycle.stop();
    } else {
      await agentLifecycle.uninstall();
    }
    app.exit(0);
    return;
  }
  if (!app.isPackaged && process.platform === "darwin") {
    app.dock?.setIcon(join(applicationRoot, "resources", "icon.png"));
  }
  registerAppProtocol();
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  const client = new BridgeSupervisor(bridgeBinary(), runtimeEnvironment());
  await client.start();
  bridge = client;
  if (nativeAgentManaged) {
    const serviceStatus = await agentLifecycle.ensureRunning();
    if (serviceStatus === "requires-approval") {
      void showAppMessageBox({
        type: "warning",
        buttons: ["Open Login Items", "Later"],
        defaultId: 0,
        cancelId: 1,
        title: "Allow the fd0 background service",
        message: "fd0 needs permission to run its local vault service.",
        detail: "The service starts locked and keeps your CLI and desktop app available after restarts.",
        noLink: true,
      }).then((answer) => {
        if (answer.response === 0) {
          void shell.openExternal("x-apple.systempreferences:com.apple.LoginItems-Settings.extension");
        }
      });
    }
  }
  disposeAutoLockEvents = configureAutoLock();
  await refreshSecurityStatus();
  securityStatusTimer = setInterval(() => void refreshSecurityStatus(), 10_000);
  registerIPC(client);
  buildMenu();
  mainWindow = createWindow();
  createTray();
  configureUpdater();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) mainWindow = createWindow();
  });
}

app.on("second-instance", () => {
  showMainWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

let quitPrepared = false;
app.on("before-quit", (event) => {
  if (!quitPrepared && bridge && !installingUpdate) {
    event.preventDefault();
    quitPrepared = true;
    void bridge.request("vault.lock", {}, 5_000)
      .catch(() => undefined)
      .finally(() => app.quit());
    return;
  }
  managedClipboard.clear();
  operationGrants.clear();
  if (updateTimer) clearTimeout(updateTimer);
  if (securityStatusTimer) clearInterval(securityStatusTimer);
  securityStatusTimer = null;
  disposeAutoLockEvents?.();
  disposeAutoLockEvents = null;
  bridge?.dispose();
  tray?.destroy();
});

void start().catch((error) => {
  dialog.showErrorBox("fd0 could not start", error instanceof Error ? error.message : String(error));
  app.quit();
});
