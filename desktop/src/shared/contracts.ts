export type ItemKind = "password" | "ssh" | "kubernetes" | "talos" | "secret";

export type BridgeErrorShape = {
  code: string;
  message: string;
  action?: string;
  retryable?: boolean;
};

export type VaultStatus = {
  vaultExists: boolean;
  agentRunning: boolean;
  agentMismatch?: boolean;
  unlocked: boolean;
  unlockedSince?: number;
  version?: string;
  flavor?: string;
  expectedVersion?: string;
  expectedFlavor?: string;
  yubikey: boolean;
  idleTimeoutMillis?: number;
  maxLifetimeMillis?: number;
  authMethods?: AuthMethodSummary[];
};

export type AuthMethodSummary = {
  id: string;
  type: string;
  label: string;
  pinMode?: "none" | "required" | "optional";
  touchPolicy?: string;
  default?: boolean;
};

export type UnlockInput = {
  method?: string;
  passphrase?: string;
  pin?: string;
};

export type ScopeSummary = {
  id: string;
  label: string;
};

export type TrustedContact = {
  label: string;
  fingerprint: string;
  shared?: boolean;
};

export type ScopeMember = {
  id: string;
  label: string;
  fingerprint: string;
  self?: boolean;
  trusted?: boolean;
};

export type ScopeShareInfo = {
  scopeLabel: string;
  contacts: TrustedContact[];
  members: ScopeMember[];
};

export type IdentityCardInfo = {
  url?: string;
  shortId: string;
  fingerprint: string;
  safetyNumber: string;
  expiresAt: string;
};

export type ItemSummary = {
  id: string;
  scopeId: string;
  recordName: string;
  kind: ItemKind;
  title: string;
  subtitle?: string;
  vault: string;
  badge: string;
  updatedAt?: string;
  favorite?: boolean;
};

export type FileView = {
  name: string;
  mime?: string;
  size: number;
};

export type FieldView = {
  name: string;
  path: string;
  type: string;
  section?: string;
  value?: string;
  sensitive?: boolean;
  copyable?: boolean;
  remaining?: number;
  file?: FileView;
  children?: FieldView[];
};

export type ItemDetail = {
  item: ItemSummary;
  fields: FieldView[];
};

export type Inventory = {
  scopes: ScopeSummary[];
  items: ItemSummary[];
  counts: Record<string, number>;
  truncated?: boolean;
};

export type RecordRef = {
  scopeId: string;
  name: string;
  raw?: boolean;
};

export type FieldRef = RecordRef & {
  path: string;
};

export type PassField = {
  type: "text" | "secret" | "totp" | "passkey" | "file" | "section";
  name: string;
  value?: unknown;
  fields?: PassField[];
  meta?: Record<string, unknown>;
};

export type PassItemData = {
  title: string;
  urls?: string[];
  fields: PassField[];
  meta?: Record<string, unknown>;
};

export type SavePassInput = {
  scopeId: string;
  recordName: string;
  item: PassItemData;
  create?: boolean;
  authorization?: string;
};

export type AttachmentValue = {
  name: string;
  mime?: string;
  size: number;
  sha256: string;
  data_b64: string;
};

export type SaveSecretInput = {
  scopeId: string;
  name: string;
  value: string;
  oldName?: string;
  create?: boolean;
  authorization?: string;
};

export type SaveSSHHostInput = {
  scopeId: string;
  oldName?: string;
  authorization?: string;
  host: {
    Alias: string;
    Hostname: string;
    User?: string;
    Port?: number;
    KeyName?: string;
    ProxyJump?: string;
    Tags?: string[];
    Description?: string;
    Options?: Record<string, string>;
  };
};

export type GenerateSSHKeyInput = {
  scopeId: string;
  name: string;
  comment?: string;
};

export type ImportConfigResult = {
  imported: string[];
  skipped?: string[];
};

export type UpdateStatus = {
  state: "unsupported" | "idle" | "checking" | "available" | "downloading" | "ready" | "current" | "error";
  version?: string;
  progress?: number;
  message?: string;
};

export type DesktopCommand =
  | "focus-search"
  | "new-item"
  | "open-settings"
  | "lock"
  | "refresh";

export type DesktopAPI = {
  platform: NodeJS.Platform;
  development: boolean;
  status(): Promise<VaultStatus>;
  createVault(passphrase: string, label: string): Promise<VaultStatus>;
  unlock(input: UnlockInput): Promise<VaultStatus>;
  lock(): Promise<VaultStatus>;
  restartAgent(): Promise<VaultStatus>;
  restoreVault(recoveryPassphrase: string, newPassphrase: string): Promise<VaultStatus | null>;
  exportRecovery(passphrase: string): Promise<{ saved: boolean }>;
  setDefaultAuthMethod(method: string): Promise<VaultStatus>;
  inventory(): Promise<Inventory>;
  itemDetail(ref: RecordRef): Promise<ItemDetail>;
  reveal(ref: FieldRef): Promise<{ value: string; remaining?: number } | null>;
  copy(ref: FieldRef): Promise<{ clearAfterSeconds: number }>;
  copyText(value: string): Promise<{ clearAfterSeconds: number }>;
  savePass(input: SavePassInput): Promise<{ ok: boolean }>;
  editPass(ref: RecordRef): Promise<SavePassInput | null>;
  setFavorite(ref: RecordRef, favorite: boolean): Promise<{ ok: boolean }>;
  pickAttachment(): Promise<AttachmentValue | null>;
  saveSecret(input: SaveSecretInput): Promise<{ ok: boolean }>;
  editSecret(ref: RecordRef): Promise<SaveSecretInput | null>;
  saveSSHHost(input: SaveSSHHostInput): Promise<{ ok: boolean }>;
  editSSHHost(ref: RecordRef): Promise<SaveSSHHostInput | null>;
  generateSSHKey(input: GenerateSSHKeyInput): Promise<{ ok: boolean }>;
  importConfig(kind: "kubernetes" | "talos", scopeId: string): Promise<ImportConfigResult | null>;
  saveAttachment(ref: FieldRef): Promise<{ saved: boolean }>;
  remove(ref: RecordRef): Promise<{ ok: boolean }>;
  createScope(label: string): Promise<{ ok: boolean }>;
  scopeShareInfo(scopeId: string): Promise<ScopeShareInfo>;
  addScopeMember(scopeId: string, label: string): Promise<{ ok: boolean }>;
  removeScopeMember(scopeId: string, memberId: string): Promise<{ ok: boolean }>;
  exportIdentityCard(): Promise<IdentityCardInfo>;
  inspectIdentityCard(url: string): Promise<IdentityCardInfo>;
  importIdentityCard(url: string, label: string): Promise<{ ok: boolean }>;
  sync(): Promise<{ ok: boolean }>;
  launchAtLogin(): Promise<boolean>;
  setLaunchAtLogin(value: boolean): Promise<boolean>;
  openItemURL(ref: RecordRef): Promise<void>;
  openSupportLink(target: "docs" | "issues"): Promise<void>;
  updateStatus(): Promise<UpdateStatus>;
  checkForUpdates(): Promise<UpdateStatus>;
  installUpdate(): Promise<void>;
  onUpdate(handler: (status: UpdateStatus) => void): () => void;
  onCommand(handler: (command: DesktopCommand) => void): () => void;
};
