import { contextBridge, ipcRenderer } from "electron";
import type {
  BridgeErrorShape,
  DesktopAPI,
  DesktopCommand,
  FieldRef,
  GenerateSSHKeyInput,
  RecordRef,
  SavePassInput,
  SaveSecretInput,
  SaveSSHHostInput,
  UpdateStatus,
} from "../shared/contracts";

type IPCResult<T> = { ok: true; value: T } | { ok: false; error: BridgeErrorShape };

class DesktopError extends Error {
  readonly code: string;
  readonly action?: string;
  readonly retryable: boolean;

  constructor(shape: BridgeErrorShape) {
    super(shape.message);
    this.name = "DesktopError";
    this.code = shape.code;
    this.action = shape.action;
    this.retryable = shape.retryable ?? false;
  }
}

async function invoke<T>(channel: string, ...args: unknown[]): Promise<T> {
  const result = (await ipcRenderer.invoke(channel, ...args)) as IPCResult<T>;
  if (!result.ok) throw new DesktopError(result.error);
  return result.value;
}

const api: DesktopAPI = {
  platform: process.platform,
  development: process.argv.includes("--fd0-isolated"),
  status: () => invoke("fd0:status"),
  createVault: (passphrase: string, label: string) => invoke("fd0:create-vault", passphrase, label),
  unlock: (input) => invoke("fd0:unlock", input),
  lock: () => invoke("fd0:lock"),
  restartAgent: () => invoke("fd0:restart-agent"),
  restoreVault: (recoveryPassphrase: string, newPassphrase: string) => invoke("fd0:restore-vault", recoveryPassphrase, newPassphrase),
  exportRecovery: (passphrase: string) => invoke("fd0:export-recovery", passphrase),
  setDefaultAuthMethod: (method: string) => invoke("fd0:set-default-auth", method),
  inventory: () => invoke("fd0:inventory"),
  itemDetail: (ref: RecordRef) => invoke("fd0:item-detail", ref),
  reveal: (ref: FieldRef) => invoke("fd0:reveal", ref),
  copy: (ref: FieldRef) => invoke("fd0:copy", ref),
  copyText: (value: string) => invoke("fd0:copy-text", value),
  savePass: (input: SavePassInput) => invoke("fd0:save-pass", input),
  editPass: (ref: RecordRef) => invoke("fd0:edit-pass", ref),
  setFavorite: (ref: RecordRef, favorite: boolean) => invoke("fd0:set-favorite", ref, favorite),
  pickAttachment: () => invoke("fd0:pick-attachment"),
  saveSecret: (input: SaveSecretInput) => invoke("fd0:save-secret", input),
  editSecret: (ref: RecordRef) => invoke("fd0:edit-secret", ref),
  saveSSHHost: (input: SaveSSHHostInput) => invoke("fd0:save-ssh-host", input),
  editSSHHost: (ref: RecordRef) => invoke("fd0:edit-ssh-host", ref),
  generateSSHKey: (input: GenerateSSHKeyInput) => invoke("fd0:generate-ssh-key", input),
  importConfig: (kind: "kubernetes" | "talos", scopeId: string) => invoke("fd0:import-config", kind, scopeId),
  saveAttachment: (ref: FieldRef) => invoke("fd0:save-attachment", ref),
  remove: (ref: RecordRef) => invoke("fd0:remove", ref),
  createScope: (label: string) => invoke("fd0:create-scope", label),
  scopeShareInfo: (scopeId: string) => invoke("fd0:scope-share-info", scopeId),
  addScopeMember: (scopeId: string, label: string) => invoke("fd0:scope-add-member", scopeId, label),
  removeScopeMember: (scopeId: string, memberId: string) => invoke("fd0:scope-remove-member", scopeId, memberId),
  exportIdentityCard: () => invoke("fd0:card-export"),
  inspectIdentityCard: (url: string) => invoke("fd0:card-inspect", url),
  importIdentityCard: (url: string, label: string) => invoke("fd0:card-import", url, label),
  sync: () => invoke("fd0:sync"),
  launchAtLogin: () => invoke("fd0:launch-at-login"),
  setLaunchAtLogin: (value: boolean) => invoke("fd0:set-launch-at-login", value),
  openItemURL: (ref: RecordRef) => invoke("fd0:open-item-url", ref),
  openSupportLink: (target: "docs" | "issues") => invoke("fd0:open-support-link", target),
  updateStatus: () => invoke("fd0:update-status"),
  checkForUpdates: () => invoke("fd0:check-updates"),
  installUpdate: () => invoke("fd0:install-update"),
  onUpdate: (handler: (status: UpdateStatus) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, status: UpdateStatus) => handler(status);
    ipcRenderer.on("desktop:update", listener);
    return () => ipcRenderer.removeListener("desktop:update", listener);
  },
  onCommand: (handler: (command: DesktopCommand) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, command: DesktopCommand) => handler(command);
    ipcRenderer.on("desktop:command", listener);
    return () => ipcRenderer.removeListener("desktop:command", listener);
  },
};

contextBridge.exposeInMainWorld("fd0", Object.freeze(api));
