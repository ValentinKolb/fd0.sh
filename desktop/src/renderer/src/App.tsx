import {
  For,
  Show,
  batch,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
  onMount,
  type Component,
  type JSX,
} from "solid-js";
import { Dynamic } from "solid-js/web";
import {
  IconAlertTriangle,
  IconAdjustmentsHorizontal,
  IconBraces,
  IconCheck,
  IconChevronDown,
  IconClock,
  IconCopy,
  IconDeviceUsb,
  IconDice5,
  IconDownload,
  IconDots,
  IconExternalLink,
  IconEye,
  IconEyeOff,
  IconFolder,
  IconHelp,
  IconHexagonLetterK,
  IconHistory,
  IconKey,
  IconLayoutGrid,
  IconLock,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconServer,
  IconSettings,
  IconShieldCheck,
  IconStar,
  IconTerminal2,
  IconTextSize,
  IconTrash,
  IconUserPlus,
  IconX,
} from "@tabler/icons-solidjs";
import type { IconProps } from "@tabler/icons-solidjs";
import { password } from "@valentinkolb/stdlib";
import { hotkeys } from "@valentinkolb/stdlib/solid";
import type {
  FieldView,
  Inventory,
  ItemDetail,
  ItemKind,
  ItemSummary,
  RecordRef,
  SavePassInput,
  SaveSecretInput,
  SaveSSHHostInput,
  ScopeSummary,
  UpdateStatus,
  VaultStatus,
} from "../../shared/contracts";
import { errorText } from "./errors";
import { AddItemModal } from "./components/AddItemModal";
import { IconButton, SelectControl } from "./components/Controls";
import { PassEditorModal } from "./components/PassEditorModal";
import { PasswordGeneratorPanel } from "./components/PasswordGenerator";
import { ShareVaultModal } from "./components/ShareVaultModal";

type MainView = "items" | "favorites" | "recent" | "generator" | "support" | "settings";
type TypeFilter = "all" | ItemKind;
type IconComponent = Component<IconProps>;

const typeOptions: Array<{ id: TypeFilter; label: string; icon: IconComponent }> = [
  { id: "all", label: "All types", icon: IconLayoutGrid },
  { id: "password", label: "Passwords", icon: IconKey },
  { id: "ssh", label: "SSH", icon: IconTerminal2 },
  { id: "kubernetes", label: "Kubernetes", icon: IconHexagonLetterK },
  { id: "talos", label: "Talos", icon: IconServer },
  { id: "secret", label: "Secrets", icon: IconBraces },
];

const kindIcons: Record<ItemKind, IconComponent> = {
  password: IconKey,
  ssh: IconTerminal2,
  kubernetes: IconHexagonLetterK,
  talos: IconServer,
  secret: IconBraces,
};

function App(): JSX.Element {
  const [status, setStatus] = createSignal<VaultStatus | null>(null);
  const [inventory, setInventory] = createSignal<Inventory>({ scopes: [], items: [], counts: {} });
  const [detail, setDetail] = createSignal<ItemDetail | null>(null);
  const [selectedID, setSelectedID] = createSignal("");
  const [typeFilter, setTypeFilter] = createSignal<TypeFilter>("password");
  const [vaultFilter, setVaultFilter] = createSignal("");
  const [mainView, setMainView] = createSignal<MainView>("items");
  const [query, setQuery] = createSignal("");
  const [showAllSecrets, setShowAllSecrets] = createSignal(false);
  const [recentIDs, setRecentIDs] = createSignal<string[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [detailLoading, setDetailLoading] = createSignal(false);
  const [appError, setAppError] = createSignal("");
  const [toast, setToast] = createSignal("");
  const [addOpen, setAddOpen] = createSignal(false);
  const [editPass, setEditPass] = createSignal<SavePassInput | null>(null);
  const [editSecret, setEditSecret] = createSignal<SaveSecretInput | null>(null);
  const [editSSHHost, setEditSSHHost] = createSignal<SaveSSHHostInput | null>(null);
  const [recoveryOpen, setRecoveryOpen] = createSignal(false);
  const [newVaultOpen, setNewVaultOpen] = createSignal(false);
  const [shareScope, setShareScope] = createSignal<ScopeSummary | null>(null);
  const [syncing, setSyncing] = createSignal(false);
  const [compactRows, setCompactRows] = createSignal(localStorage.getItem("fd0.compactRows") === "1");
  let searchInput: HTMLInputElement | undefined;
  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  let detailRequest = 0;

  const selectedItem = createMemo(() => inventory().items.find((item) => item.id === selectedID()));
  const filteredItems = createMemo(() => {
    let items = inventory().items;
    if (mainView() === "favorites") items = items.filter((item) => item.favorite);
    if (mainView() === "recent") {
      const order = new Map(recentIDs().map((id, index) => [id, index]));
      items = items.filter((item) => order.has(item.id)).sort((a, b) => order.get(a.id)! - order.get(b.id)!);
    }
    if (mainView() === "items") {
      const filter = typeFilter();
      if (filter === "secret" && showAllSecrets()) {
        // Every typed record is intentionally projected through the raw detail view.
      } else if (filter !== "all") {
        items = items.filter((item) => item.kind === filter);
      }
    }
    if (vaultFilter()) items = items.filter((item) => item.scopeId === vaultFilter());
    const needle = query().trim().toLocaleLowerCase();
    if (needle) {
      items = items.filter((item) =>
        [item.title, item.subtitle, item.vault, item.badge].some((value) => value?.toLocaleLowerCase().includes(needle)),
      );
    }
    return items;
  });

  const title = createMemo(() => {
    if (mainView() === "favorites") return "Favorites";
    if (mainView() === "recent") return "Recently used";
    return typeOptions.find((option) => option.id === typeFilter())?.label ?? "All items";
  });

  async function refresh(preferred?: RecordRef): Promise<ItemSummary | undefined> {
    try {
      setAppError("");
      const nextStatus = await window.fd0.status();
      setStatus(nextStatus);
      if (!nextStatus.unlocked) {
        setInventory({ scopes: [], items: [], counts: {} });
        setDetail(null);
        return undefined;
      }
      const nextInventory = await window.fd0.inventory();
      const preferredItem = preferred
        ? nextInventory.items.find((item) => item.scopeId === preferred.scopeId && item.recordName === preferred.name)
        : undefined;
      batch(() => {
        if (preferredItem) setSelectedID(preferredItem.id);
        setInventory(nextInventory);
      });
      return preferredItem;
    } catch (error) {
      setAppError(errorText(error));
      return undefined;
    } finally {
      setLoading(false);
    }
  }

  async function checkLockState(): Promise<void> {
    try {
      const next = await window.fd0.status();
      setStatus(next);
      if (!next.unlocked) {
        setInventory({ scopes: [], items: [], counts: {} });
        setDetail(null);
        setSelectedID("");
      }
    } catch (error) {
      setAppError(errorText(error));
    }
  }

  async function loadDetail(item: ItemSummary | undefined): Promise<void> {
    const request = ++detailRequest;
    if (!item) {
      setDetail(null);
      return;
    }
    setDetailLoading(true);
    try {
      const next = await window.fd0.itemDetail({
        scopeId: item.scopeId,
        name: item.recordName,
        raw: typeFilter() === "secret" && showAllSecrets(),
      });
      if (request === detailRequest) setDetail(next);
    } catch (error) {
      if (request === detailRequest) setAppError(errorText(error));
    } finally {
      if (request === detailRequest) setDetailLoading(false);
    }
  }

  function notify(message: string): void {
    setToast(message);
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => setToast(""), 3200);
  }

  function selectItem(item: ItemSummary): void {
    setSelectedID(item.id);
    setRecentIDs((current) => [item.id, ...current.filter((id) => id !== item.id)].slice(0, 20));
  }

  function openItems(view: MainView): void {
    setMainView(view);
    setVaultFilter("");
  }

  async function lockVault(): Promise<void> {
    try {
      await window.fd0.lock();
      setStatus((current) => (current ? { ...current, unlocked: false } : current));
      setInventory({ scopes: [], items: [], counts: {} });
      setDetail(null);
      setSelectedID("");
    } catch (error) {
      setAppError(errorText(error));
    }
  }

  async function syncVault(): Promise<void> {
    if (syncing()) return;
    setSyncing(true);
    setAppError("");
    try {
      if (!window.fd0.development) await window.fd0.sync();
      await refresh();
      notify(window.fd0.development ? "Development vault refreshed." : "Vault synced.");
    } catch (error) {
      setAppError(errorText(error));
    } finally {
      setSyncing(false);
    }
  }

  createEffect(() => {
    const visible = filteredItems();
    if (!visible.some((item) => item.id === selectedID())) setSelectedID(visible[0]?.id ?? "");
  });

  createEffect(() => {
    void loadDetail(selectedItem());
  });

  createEffect(() => {
    localStorage.setItem("fd0.compactRows", compactRows() ? "1" : "0");
  });

  onMount(() => {
    void refresh();
    const statusTimer = setInterval(() => void checkLockState(), 10_000);
    const refreshOnFocus = () => void refresh();
    window.addEventListener("focus", refreshOnFocus);
    const shortcuts = hotkeys.create({
      "mod+f": { label: "Find", run: () => searchInput?.focus(), inInput: true },
      "mod+n": { label: "New item", run: () => { setAddOpen(true); } },
      "mod+,": { label: "Settings", run: () => { setMainView("settings"); } },
      "mod+shift+l": { label: "Lock", run: lockVault },
      esc: {
        label: "Close",
        run: () => {
          if (recoveryOpen()) setRecoveryOpen(false);
          else if (newVaultOpen()) setNewVaultOpen(false);
          else if (shareScope()) setShareScope(null);
          else if (editSSHHost()) setEditSSHHost(null);
          else if (editSecret()) setEditSecret(null);
          else if (editPass()) setEditPass(null);
          else if (addOpen()) setAddOpen(false);
          else searchInput?.blur();
        },
        inInput: true,
      },
    });
    const unsubscribe = window.fd0.onCommand((command) => {
      if (command === "focus-search") searchInput?.focus();
      if (command === "new-item") setAddOpen(true);
      if (command === "open-settings") setMainView("settings");
      if (command === "lock") void lockVault();
      if (command === "refresh") void refresh();
    });
    onCleanup(() => {
      shortcuts.dispose();
      unsubscribe();
      clearInterval(statusTimer);
      window.removeEventListener("focus", refreshOnFocus);
      if (toastTimer) clearTimeout(toastTimer);
    });
  });

  return (
    <div classList={{ app: true, "is-mac": window.fd0.platform === "darwin", compact: compactRows() }}>
      <Show
        when={!loading()}
        fallback={
          <div class="boot-screen">
            <Logo />
            <div class="boot-progress" />
          </div>
        }
      >
        <Show
          when={status()?.unlocked}
          fallback={
            <Show
              when={status()?.vaultExists !== false}
              fallback={
                <OnboardingScreen
                  onCreated={(next) => {
                    setStatus(next);
                    setAppError("");
                    void refresh();
                  }}
                />
              }
            >
              <UnlockScreen
                status={status()}
                error={appError()}
                onUnlock={(next) => {
                  setStatus(next);
                  setAppError("");
                  void refresh();
                }}
              />
            </Show>
          }
        >
          <header class="titlebar">
            <Logo />
            <div class="global-search">
              <IconSearch size={17} aria-hidden="true" />
              <input
                ref={searchInput}
                aria-label="Search vault"
                placeholder="Search passwords, access, or secrets"
                value={query()}
                onInput={(event) => setQuery(event.currentTarget.value)}
              />
              <kbd>⌘F</kbd>
            </div>
            <div class="titlebar-spacer" />
            <button
              class="sync-status"
              type="button"
              onClick={() => void syncVault()}
              title={window.fd0.development ? "Refresh development vault" : "Sync vault now"}
              disabled={syncing()}
            >
              <span classList={{ "status-dot": true, local: window.fd0.development }} />
              {syncing() ? "Syncing…" : window.fd0.development ? "Development vault" : "Sync now"}
            </button>
            <IconButton label="Lock fd0" onClick={() => void lockVault()}>
              <IconLock size={18} />
            </IconButton>
            <button class="primary-button title-add" type="button" onClick={() => setAddOpen(true)}>
              <IconPlus size={17} />
              Add
            </button>
          </header>

          <Sidebar
            inventory={inventory()}
            typeFilter={typeFilter()}
            mainView={mainView()}
            vaultFilter={vaultFilter()}
            onType={(type) => {
              setTypeFilter(type);
              setMainView("items");
              setVaultFilter("");
            }}
            onView={openItems}
            onCreateVault={() => setNewVaultOpen(true)}
            onShareVault={setShareScope}
            onVault={(scope) => {
              setMainView("items");
              setVaultFilter(scope.id);
            }}
          />

          <Show
            when={mainView() === "items" || mainView() === "favorites" || mainView() === "recent"}
            fallback={
              <WorkspacePanel
                view={mainView()}
                status={status()!}
                compactRows={compactRows()}
                onCompactRows={setCompactRows}
                onNotify={notify}
                onStatus={setStatus}
                onRecovery={() => setRecoveryOpen(true)}
                onError={setAppError}
              />
            }
          >
            <section class="item-column" aria-label="Items">
              <header class="column-heading">
                <div>
                  <h1>{title()}</h1>
                  <span>{filteredItems().length} items</span>
                </div>
                <Show when={mainView() === "items" && typeFilter() === "secret"}>
                  <label class="switch-label">
                    <span>Show all</span>
                    <input
                      type="checkbox"
                      checked={showAllSecrets()}
                      onChange={(event) => setShowAllSecrets(event.currentTarget.checked)}
                    />
                    <span class="switch-track"><span /></span>
                  </label>
                </Show>
              </header>
              <Show when={typeFilter() === "secret" && showAllSecrets()}>
                <div class="raw-notice">Showing every stored record as a general secret.</div>
              </Show>
              <div class="item-list">
                <For
                  each={filteredItems()}
                  fallback={
                    <div class="empty-list">
                      <IconSearch size={24} />
                      <strong>No matching items</strong>
                      <span>Try another search or filter.</span>
                    </div>
                  }
                >
                  {(item) => (
                    <ItemRow item={item} selected={item.id === selectedID()} onSelect={() => selectItem(item)} />
                  )}
                </For>
              </div>
            </section>
            <DetailPanel
              detail={detail()}
              loading={detailLoading()}
              raw={typeFilter() === "secret" && showAllSecrets()}
              onCopy={(field) => {
                const item = detail()!.item;
                void window.fd0
                  .copy({ scopeId: item.scopeId, name: item.recordName, path: field.path })
                  .then(() => notify("Copied. Clipboard clears in 30 seconds."))
                  .catch((error) => setAppError(errorText(error)));
              }}
              onRemove={() => {
                const item = detail()?.item;
                if (!item) return;
                void window.fd0
                  .remove({ scopeId: item.scopeId, name: item.recordName })
                  .then(async (result) => {
                    if (!result.ok) return;
                    notify("Item removed.");
                    setSelectedID("");
                    await refresh();
                  })
                  .catch((error) => setAppError(errorText(error)));
              }}
              onEdit={() => {
                const item = detail()?.item;
                if (!item) return;
                const ref = { scopeId: item.scopeId, name: item.recordName };
                if (item.kind === "password") {
                  void window.fd0.editPass(ref).then(setEditPass).catch((error) => setAppError(errorText(error)));
                } else if (item.kind === "secret") {
                  void window.fd0.editSecret(ref).then(setEditSecret).catch((error) => setAppError(errorText(error)));
                } else if (item.kind === "ssh" && item.badge === "SSH HOST") {
                  void window.fd0.editSSHHost(ref).then(setEditSSHHost).catch((error) => setAppError(errorText(error)));
                }
              }}
              onSaveAttachment={(field) => {
                const item = detail()?.item;
                if (!item) return;
                void window.fd0
                  .saveAttachment({ scopeId: item.scopeId, name: item.recordName, path: field.path })
                  .then((result) => result.saved && notify("Attachment saved."))
                  .catch((error) => setAppError(errorText(error)));
              }}
              onFavorite={() => {
                const item = detail()?.item;
                if (!item || item.kind !== "password") return;
                void window.fd0
                  .setFavorite({ scopeId: item.scopeId, name: item.recordName }, !item.favorite)
                  .then(async () => {
                    notify(item.favorite ? "Removed from favorites." : "Added to favorites.");
                    await refresh();
                    await loadDetail(selectedItem());
                  })
                  .catch((error) => setAppError(errorText(error)));
              }}
              onOpenURL={(url) => void window.fd0.openExternal(url).catch((error) => setAppError(errorText(error)))}
              onError={(message) => setAppError(message)}
              onRefresh={() => void loadDetail(selectedItem())}
            />
          </Show>

          <Show when={appError()}>
            <div class="error-banner" role="alert">
              <IconAlertTriangle size={18} />
              <span>{appError()}</span>
              <button type="button" onClick={() => setAppError("")} aria-label="Dismiss error"><IconX size={17} /></button>
            </div>
          </Show>
          <Show when={toast()}>
            <div class="toast" role="status"><IconCheck size={17} />{toast()}</div>
          </Show>
          <Show when={addOpen()}>
            <AddItemModal
              scopes={inventory().scopes}
              onClose={() => setAddOpen(false)}
              onSaved={async (ref) => {
                setAddOpen(false);
                notify("Item saved.");
                if (ref) {
                  setMainView("items");
                  setTypeFilter("all");
                  setVaultFilter("");
                  setQuery("");
                }
                await refresh(ref);
              }}
            />
          </Show>
          <Show when={editPass()}>
            {(input) => (
              <PassEditorModal
                input={input()}
                onClose={() => setEditPass(null)}
                onSaved={async () => {
                  setEditPass(null);
                  notify("Changes saved.");
                  await refresh();
                  await loadDetail(selectedItem());
                }}
              />
            )}
          </Show>
          <Show when={editSecret()}>
            {(input) => (
              <SecretEditorModal
                input={input()}
                onClose={() => setEditSecret(null)}
                onSaved={async (ref) => {
                  setEditSecret(null);
                  notify("Changes saved.");
                  await refresh(ref);
                }}
              />
            )}
          </Show>
          <Show when={editSSHHost()}>
            {(input) => (
              <SSHHostEditorModal
                input={input()}
                onClose={() => setEditSSHHost(null)}
                onSaved={async (ref) => {
                  setEditSSHHost(null);
                  notify("Changes saved.");
                  await refresh(ref);
                }}
              />
            )}
          </Show>
          <Show when={recoveryOpen()}>
            <RecoveryExportModal
              onClose={() => setRecoveryOpen(false)}
              onSaved={() => {
                setRecoveryOpen(false);
                notify("Recovery file saved.");
              }}
            />
          </Show>
          <Show when={newVaultOpen()}>
            <CreateVaultModal
              onClose={() => setNewVaultOpen(false)}
              onSaved={async () => {
                setNewVaultOpen(false);
                notify("Vault created.");
                await refresh();
              }}
            />
          </Show>
          <Show when={shareScope()}>
            {(scope) => (
              <ShareVaultModal
                scope={scope()}
                onClose={() => setShareScope(null)}
                onNotify={notify}
                onChanged={async () => {
                  await refresh();
                }}
              />
            )}
          </Show>
        </Show>
      </Show>
    </div>
  );
}

function Logo(): JSX.Element {
  return (
    <div class="logo" aria-label="fd0">
      <strong>fd0</strong>
    </div>
  );
}

function UnlockScreen(props: {
  status: VaultStatus | null;
  error: string;
  onUnlock(status: VaultStatus): void;
}): JSX.Element {
  const [passphrase, setPassphrase] = createSignal("");
  const [passphraseVisible, setPassphraseVisible] = createSignal(false);
  const [pin, setPIN] = createSignal("");
  const [methodID, setMethodID] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  let input: HTMLInputElement | undefined;

  const methods = createMemo(() => props.status?.authMethods ?? []);
  const selectedMethod = createMemo(() => methods().find((method) => method.id === methodID()) ?? methods()[0]);

  createEffect(() => {
    const available = methods();
    if (available.length === 0 || available.some((method) => method.id === methodID())) return;
    setMethodID(available.find((method) => method.default)?.id ?? available[0]!.id);
  });

  onMount(() => input?.focus());

  async function unlock(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const method = selectedMethod();
    if (!method || (method.type === "passphrase" && !passphrase())) return;
    setBusy(true);
    setError("");
    try {
      const result = await window.fd0.unlock({
        method: method.id,
        passphrase: method.type === "passphrase" ? passphrase() : "",
        pin: method.type === "yubikey" ? pin() : "",
      });
      setPassphrase("");
      setPIN("");
      props.onUnlock(result);
    } catch (cause) {
      setError(errorText(cause));
      input?.select();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="locked-shell">
      <header class="locked-titlebar"><Logo /></header>
      <main class="unlock-main">
        <div class="unlock-glyph"><IconLock size={30} /></div>
        <h1>Unlock fd0</h1>
        <p>Your vault stays encrypted until you unlock it on this device.</p>
        <form onSubmit={unlock}>
          <Show when={methods().length > 1}>
            <div class="unlock-methods" role="radiogroup" aria-label="Unlock method">
              <For each={methods()}>
                {(method) => (
                  <button
                    classList={{ active: selectedMethod()?.id === method.id }}
                    type="button"
                    role="radio"
                    aria-checked={selectedMethod()?.id === method.id}
                    onClick={() => {
                      setMethodID(method.id);
                      queueMicrotask(() => input?.focus());
                    }}
                  >
                    {method.type === "yubikey" ? <IconDeviceUsb size={17} /> : <IconKey size={17} />}
                    {method.label}
                  </button>
                )}
              </For>
            </div>
          </Show>
          <Show when={selectedMethod()?.type === "passphrase"}>
            <label for="vault-passphrase">Passphrase</label>
            <div class="input-action">
              <input
                ref={input}
                id="vault-passphrase"
                type={passphraseVisible() ? "text" : "password"}
                autocomplete="current-password"
                spellcheck={false}
                value={passphrase()}
                onInput={(event) => setPassphrase(event.currentTarget.value)}
              />
              <button
                type="button"
                aria-label={passphraseVisible() ? "Hide passphrase" : "Show passphrase"}
                aria-pressed={passphraseVisible()}
                title={passphraseVisible() ? "Hide passphrase" : "Show passphrase"}
                onClick={() => setPassphraseVisible((visible) => !visible)}
              >
                {passphraseVisible() ? <IconEyeOff size={18} /> : <IconEye size={18} />}
              </button>
            </div>
          </Show>
          <Show when={selectedMethod()?.type === "yubikey"}>
            <div class="yubikey-prompt"><IconDeviceUsb size={20} /><span>Insert your YubiKey. fd0 will ask for touch when needed.</span></div>
            <Show when={selectedMethod()?.pinMode !== "none"}>
              <label for="yubikey-pin">YubiKey PIV PIN{selectedMethod()?.pinMode === "optional" ? " (optional for legacy methods)" : ""}</label>
              <input
                ref={input}
                id="yubikey-pin"
                type="password"
                inputmode="numeric"
                autocomplete="off"
                maxlength="8"
                value={pin()}
                onInput={(event) => setPIN(event.currentTarget.value)}
              />
            </Show>
            <Show when={!props.status?.yubikey}>
              <div class="inline-error">This build does not include YubiKey support.</div>
            </Show>
          </Show>
          <Show when={error() || props.error}>
            <div class="inline-error" role="alert">{error() || props.error}</div>
          </Show>
          <button
            class="primary-button unlock-button"
            type="submit"
            disabled={busy() || !selectedMethod() || (selectedMethod()?.type === "passphrase" && !passphrase()) || (selectedMethod()?.type === "yubikey" && !props.status?.yubikey)}
          >
            {busy() ? selectedMethod()?.type === "yubikey" ? "Waiting for YubiKey…" : "Unlocking…" : "Unlock"}
          </button>
        </form>
        <Show when={window.fd0.development}>
          <div class="dev-vault-note">
            <span>Development vault</span>
            <code>fd0-desktop-dev</code>
          </div>
        </Show>
      </main>
    </div>
  );
}

function OnboardingScreen(props: { onCreated(status: VaultStatus): void }): JSX.Element {
  const [mode, setMode] = createSignal<"create" | "restore">("create");
  const [label, setLabel] = createSignal("Personal");
  const [passphrase, setPassphrase] = createSignal("");
  const [confirmation, setConfirmation] = createSignal("");
  const [recoveryPassphrase, setRecoveryPassphrase] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const strength = createMemo(() => password.strength(passphrase()));

  async function create(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (passphrase() !== confirmation()) {
      setError("Passphrases do not match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const status = await window.fd0.createVault(passphrase(), label());
      setPassphrase("");
      setConfirmation("");
      props.onCreated(status);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  async function restore(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (passphrase() !== confirmation()) {
      setError("Passphrases do not match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const status = await window.fd0.restoreVault(recoveryPassphrase(), passphrase());
      if (!status) return;
      setRecoveryPassphrase("");
      setPassphrase("");
      setConfirmation("");
      props.onCreated(status);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="locked-shell">
      <header class="locked-titlebar"><Logo /></header>
      <main class="onboarding-main">
        <div class="onboarding-copy">
          <span class="eyebrow">{mode() === "create" ? "New vault" : "Existing identity"}</span>
          <h1>Protect your passwords with fd0</h1>
          <p>{mode() === "create" ? "Your passphrase unlocks this device. fd0 never sends it to a server and cannot recover it for you." : "Restore your identity from an offline recovery file, then sync its vaults to this device."}</p>
        </div>
        <div class="onboarding-card">
          <div class="onboarding-tabs" role="tablist">
            <button classList={{ active: mode() === "create" }} type="button" onClick={() => { setMode("create"); setError(""); }}>Create new</button>
            <button classList={{ active: mode() === "restore" }} type="button" onClick={() => { setMode("restore"); setError(""); }}>Restore</button>
          </div>
          <Show
            when={mode() === "create"}
            fallback={
              <form onSubmit={restore}>
                <label><span>Recovery passphrase</span><input type="password" required autocomplete="off" value={recoveryPassphrase()} onInput={(event) => setRecoveryPassphrase(event.currentTarget.value)} /></label>
                <label><span>New passphrase for this device</span><input type="password" required minlength="12" autocomplete="new-password" value={passphrase()} onInput={(event) => setPassphrase(event.currentTarget.value)} /></label>
                <div class="onboarding-strength"><span class={`score-${strength().score}`} /><small>{passphrase() ? strength().label : "At least 12 characters"}</small></div>
                <label><span>Confirm new passphrase</span><input type="password" required autocomplete="new-password" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} /></label>
                <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
                <button class="primary-button" type="submit" disabled={busy() || passphrase().length < 12 || !recoveryPassphrase()}>{busy() ? "Restoring…" : "Choose recovery file and restore"}</button>
              </form>
            }
          >
            <form onSubmit={create}>
              <label><span>First vault</span><input required value={label()} onInput={(event) => setLabel(event.currentTarget.value)} /></label>
              <label><span>Passphrase</span><input type="password" required minlength="12" autocomplete="new-password" value={passphrase()} onInput={(event) => setPassphrase(event.currentTarget.value)} /></label>
              <div class="onboarding-strength"><span class={`score-${strength().score}`} /><small>{passphrase() ? strength().label : "At least 12 characters"}</small></div>
              <label><span>Confirm passphrase</span><input type="password" required autocomplete="new-password" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} /></label>
              <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
              <button class="primary-button" type="submit" disabled={busy() || passphrase().length < 12}>{busy() ? "Creating vault…" : "Create vault"}</button>
            </form>
          </Show>
        </div>
      </main>
    </div>
  );
}

function Sidebar(props: {
  inventory: Inventory;
  typeFilter: TypeFilter;
  mainView: MainView;
  vaultFilter: string;
  onType(type: TypeFilter): void;
  onView(view: MainView): void;
  onVault(scope: ScopeSummary): void;
  onCreateVault(): void;
  onShareVault(scope: ScopeSummary): void;
}): JSX.Element {
  const [vaultMenu, setVaultMenu] = createSignal("");

  onMount(() => {
    const closeMenu = (event: PointerEvent) => {
      if (!(event.target instanceof Element) || !event.target.closest(".vault-row")) setVaultMenu("");
    };
    document.addEventListener("pointerdown", closeMenu);
    onCleanup(() => document.removeEventListener("pointerdown", closeMenu));
  });

  return (
    <aside class="sidebar">
      <div class="sidebar-label">Library</div>
      <TypePicker value={props.typeFilter} counts={props.inventory.counts} onChange={props.onType} />
      <div class="sidebar-label">Views</div>
      <SidebarButton active={props.mainView === "favorites"} icon={IconStar} label="Favorites" count={props.inventory.counts.favorite} onClick={() => props.onView("favorites")} />
      <SidebarButton active={props.mainView === "recent"} icon={IconHistory} label="Recently used" onClick={() => props.onView("recent")} />
      <div class="sidebar-label sidebar-label-action"><span>Vaults</span><button type="button" aria-label="Create vault" title="Create vault" onClick={props.onCreateVault}><IconPlus size={14} /></button></div>
      <For each={props.inventory.scopes}>
        {(scope, index) => (
          <div class="vault-row">
            <button
              classList={{ "sidebar-item": true, active: props.vaultFilter === scope.id }}
              type="button"
              onClick={() => {
                setVaultMenu("");
                props.onVault(scope);
              }}
            >
              <span classList={{ "vault-dot": true, work: index() % 3 === 1, shared: index() % 3 === 2 }} />
              <span>{scope.label}</span>
              <span class="sidebar-count">{props.inventory.items.filter((item) => item.scopeId === scope.id).length}</span>
            </button>
            <button
              class="vault-more"
              type="button"
              aria-label={`Actions for ${scope.label}`}
              title={`Actions for ${scope.label}`}
              aria-haspopup="menu"
              aria-expanded={vaultMenu() === scope.id}
              onClick={() => setVaultMenu((current) => current === scope.id ? "" : scope.id)}
            ><IconDots size={16} /></button>
            <Show when={vaultMenu() === scope.id}>
              <div class="context-menu vault-context-menu" role="menu" aria-label={`${scope.label} vault actions`}>
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setVaultMenu("");
                    props.onShareVault(scope);
                  }}
                ><IconUserPlus size={16} />Share vault…</button>
              </div>
            </Show>
          </div>
        )}
      </For>
      <div class="sidebar-label">Tools</div>
      <SidebarButton active={props.mainView === "generator"} icon={IconDice5} label="Password generator" onClick={() => props.onView("generator")} />
      <div class="sidebar-bottom">
        <SidebarButton active={props.mainView === "support"} icon={IconHelp} label="Support" onClick={() => props.onView("support")} />
        <SidebarButton active={props.mainView === "settings"} icon={IconSettings} label="Settings" onClick={() => props.onView("settings")} />
      </div>
    </aside>
  );
}

function SidebarButton(props: {
  active?: boolean;
  icon: IconComponent;
  label: string;
  count?: number;
  onClick(): void;
}): JSX.Element {
  return (
    <button classList={{ "sidebar-item": true, active: props.active }} type="button" onClick={props.onClick}>
      <Dynamic component={props.icon} size={16} strokeWidth={1.7} />
      <span>{props.label}</span>
      <Show when={props.count}><span class="sidebar-count">{props.count}</span></Show>
    </button>
  );
}

function TypePicker(props: {
  value: TypeFilter;
  counts: Record<string, number>;
  onChange(type: TypeFilter): void;
}): JSX.Element {
  const [open, setOpen] = createSignal(false);
  let root: HTMLDivElement | undefined;
  const current = createMemo(() => typeOptions.find((option) => option.id === props.value) ?? typeOptions[0]!);

  onMount(() => {
    const close = (event: PointerEvent) => {
      if (root && !root.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", close);
    onCleanup(() => document.removeEventListener("pointerdown", close));
  });

  return (
    <div class="type-picker" ref={root}>
      <button
        class="type-picker-button"
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open()}
        onClick={() => setOpen(!open())}
        onKeyDown={(event) => {
          if (event.key === "Escape") setOpen(false);
        }}
      >
        <Dynamic component={current().icon} size={16} strokeWidth={1.8} />
        <span>{current().label}</span>
        <span class="sidebar-count">{props.counts[current().id] ?? props.counts.all ?? 0}</span>
        <IconChevronDown size={15} />
      </button>
      <Show when={open()}>
        <div class="type-menu" role="listbox" aria-label="Item type">
          <For each={typeOptions}>
            {(option) => (
              <button
                type="button"
                role="option"
                aria-selected={option.id === props.value}
                onClick={() => {
                  props.onChange(option.id);
                  setOpen(false);
                }}
              >
                <Dynamic component={option.icon} size={16} strokeWidth={1.8} />
                <span>{option.label}</span>
                <span>{props.counts[option.id] ?? 0}</span>
              </button>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}

function ItemRow(props: { item: ItemSummary; selected: boolean; onSelect(): void }): JSX.Element {
  const icon = () => kindIcons[props.item.kind];
  return (
    <button classList={{ "item-row": true, selected: props.selected }} type="button" onClick={props.onSelect}>
      <span classList={{ "item-icon": true, [props.item.kind]: true }}>
        <Dynamic component={icon()} size={17} strokeWidth={1.7} />
      </span>
      <span class="item-copy">
        <strong>{props.item.title}</strong>
        <span>{props.item.subtitle || props.item.vault}</span>
      </span>
      <span class="kind-badge">{props.item.badge}</span>
    </button>
  );
}

function DetailPanel(props: {
  detail: ItemDetail | null;
  loading: boolean;
  raw: boolean;
  onCopy(field: FieldView): void;
  onRemove(): void;
  onEdit(): void;
  onSaveAttachment(field: FieldView): void;
  onFavorite(): void;
  onOpenURL(url: string): void;
  onError(message: string): void;
  onRefresh(): void;
}): JSX.Element {
  const [revealed, setRevealed] = createSignal<Record<string, string>>({});
  const [actionsOpen, setActionsOpen] = createSignal(false);
  const [largeType, setLargeType] = createSignal<{ field: FieldView; value: string } | null>(null);
  let actionsRoot: HTMLDivElement | undefined;
  const sections = createMemo(() => {
    const groups = new Map<string, FieldView[]>();
    for (const field of props.detail?.fields ?? []) {
      const section = field.section || (props.raw ? "Stored record" : "Details");
      groups.set(section, [...(groups.get(section) ?? []), field]);
    }
    return [...groups.entries()];
  });
  const primaryField = createMemo(() => {
    if (props.raw || props.detail?.item.kind !== "password") return undefined;
    const fields = (props.detail?.fields ?? []).flatMap(flattenFieldViews);
    return fields.find((field) => field.type === "secret" && /^(password|pass|pin)$/i.test(field.name))
      ?? fields.find((field) => field.type === "secret");
  });
  const websiteField = createMemo(() => (props.detail?.fields ?? []).flatMap(flattenFieldViews).find((field) => field.type === "url" && field.value));
  const canEdit = createMemo(() => {
    const item = props.detail?.item;
    if (!item || props.raw) return false;
    return item.kind === "password" || item.kind === "secret" || (item.kind === "ssh" && item.badge === "SSH HOST");
  });

  createEffect(() => {
    props.detail?.item.id;
    setRevealed({});
    setActionsOpen(false);
    setLargeType(null);
  });

  onMount(() => {
    const closeActions = (event: PointerEvent) => {
      if (actionsRoot && !actionsRoot.contains(event.target as Node)) setActionsOpen(false);
    };
    document.addEventListener("pointerdown", closeActions);
    onCleanup(() => document.removeEventListener("pointerdown", closeActions));
  });

  createEffect(() => {
    const remaining = (props.detail?.fields ?? [])
      .flatMap(flattenFieldViews)
      .map((field) => field.remaining ?? 0)
      .filter((value) => value > 0);
    if (remaining.length === 0) return;
    const timer = setTimeout(props.onRefresh, Math.min(...remaining) * 1000 + 250);
    onCleanup(() => clearTimeout(timer));
  });

  async function reveal(field: FieldView): Promise<void> {
    const existing = revealed()[field.path];
    if (existing !== undefined) {
      setRevealed((current) => {
        const next = { ...current };
        delete next[field.path];
        return next;
      });
      return;
    }
    const item = props.detail?.item;
    if (!item) return;
    try {
      const result = await window.fd0.reveal({ scopeId: item.scopeId, name: item.recordName, path: field.path });
      setRevealed((current) => ({ ...current, [field.path]: result.value }));
      setTimeout(() => {
        setRevealed((current) => {
          const next = { ...current };
          delete next[field.path];
          return next;
        });
      }, 15_000);
    } catch (error) {
      props.onError(errorText(error));
    }
  }

  async function showLargeType(field: FieldView): Promise<void> {
    const item = props.detail?.item;
    if (!item) return;
    try {
      const value = field.sensitive
        ? (await window.fd0.reveal({ scopeId: item.scopeId, name: item.recordName, path: field.path })).value
        : field.value ?? (await window.fd0.reveal({ scopeId: item.scopeId, name: item.recordName, path: field.path })).value;
      if (!value) return;
      setActionsOpen(false);
      setLargeType({ field, value });
    } catch (error) {
      props.onError(errorText(error));
    }
  }

  return (
    <article class="detail-panel">
      <Show
        when={props.detail}
        fallback={
          <div class="empty-detail">
            <IconKey size={28} />
            <strong>Select an item</strong>
            <span>Choose an item to view its details.</span>
          </div>
        }
      >
        {(detail) => (
          <>
            <header class="detail-header">
              <span classList={{ "detail-icon": true, [detail().item.kind]: true }}>
                <Dynamic component={kindIcons[detail().item.kind]} size={21} strokeWidth={1.7} />
              </span>
              <div class="detail-title">
                <h1>{detail().item.title}</h1>
                <span>{props.raw ? "Generic stored record" : detail().item.subtitle || detail().item.kind}</span>
              </div>
              <div class="detail-actions">
                <Show when={detail().item.kind === "password" && !props.raw}>
                  <IconButton label={detail().item.favorite ? "Remove from favorites" : "Add to favorites"} onClick={props.onFavorite}>
                    <IconStar size={17} fill={detail().item.favorite ? "currentColor" : "none"} />
                  </IconButton>
                </Show>
                <div class="action-menu" ref={actionsRoot}>
                  <button
                    class="icon-button"
                    type="button"
                    aria-label="More actions"
                    title="More actions"
                    aria-haspopup="menu"
                    aria-expanded={actionsOpen()}
                    onClick={() => setActionsOpen((open) => !open)}
                  ><IconDots size={18} /></button>
                  <Show when={actionsOpen()}>
                    <div class="context-menu" role="menu" aria-label="Item actions">
                      <Show when={canEdit()}>
                        <button type="button" role="menuitem" onClick={() => { setActionsOpen(false); props.onEdit(); }}><IconAdjustmentsHorizontal size={16} />Edit item</button>
                      </Show>
                      <Show when={primaryField()}>
                        {(field) => (
                          <>
                            <button type="button" role="menuitem" onClick={() => void showLargeType(field())}><IconTextSize size={16} />Show in large type</button>
                            <button type="button" role="menuitem" onClick={() => { props.onCopy(field()); setActionsOpen(false); }}><IconCopy size={16} />Copy {field().name}</button>
                          </>
                        )}
                      </Show>
                      <Show when={websiteField()}>
                        {(field) => <button type="button" role="menuitem" onClick={() => { props.onOpenURL(field().value!); setActionsOpen(false); }}><IconExternalLink size={16} />Open website</button>}
                      </Show>
                      <div class="context-menu-separator" role="separator" />
                      <button class="danger" type="button" role="menuitem" onClick={() => { setActionsOpen(false); props.onRemove(); }}><IconTrash size={16} />Remove item</button>
                    </div>
                  </Show>
                </div>
              </div>
            </header>
            <div classList={{ "detail-body": true, loading: props.loading }}>
              <For each={sections()}>
                {([section, fields]) => (
                  <section class="field-section">
                    <h2>{section}</h2>
                    <div class="field-list">
                      <For each={fields}>
                        {(field) => (
                          <FieldRow
                            field={field}
                            revealed={revealed()[field.path]}
                            largeType={detail().item.kind === "password" && !props.raw && ["text", "secret", "totp"].includes(field.type)}
                            onReveal={(next) => void reveal(next)}
                            onCopy={props.onCopy}
                            onLargeType={(next) => void showLargeType(next)}
                            onSaveFile={props.onSaveAttachment}
                            onOpenURL={props.onOpenURL}
                          />
                        )}
                      </For>
                    </div>
                  </section>
                )}
              </For>
              <footer class="detail-meta">
                <span class="vault-pill"><span class="vault-dot" />{detail().item.vault}</span>
                <span>{detail().item.updatedAt ? relativeDate(detail().item.updatedAt!) : "Stored securely in fd0"}</span>
              </footer>
            </div>
          </>
        )}
      </Show>
      <Show when={largeType()}>
        {(current) => (
          <LargeTypeModal
            label={current().field.name}
            value={current().value}
            onClose={() => setLargeType(null)}
            onCopy={() => props.onCopy(current().field)}
          />
        )}
      </Show>
    </article>
  );
}

function FieldRow(props: {
  field: FieldView;
  revealed?: string;
  largeType?: boolean;
  onReveal(field: FieldView): void;
  onCopy(field: FieldView): void;
  onLargeType(field: FieldView): void;
  onSaveFile(field: FieldView): void;
  onOpenURL(url: string): void;
}): JSX.Element {
  const shownValue = () => {
    if (props.revealed !== undefined) return props.revealed;
    if (props.field.sensitive) return "••••••••••••••••";
    return props.field.value || "Not set";
  };
  return (
    <>
      <div classList={{ "field-row": true, raw: props.field.type === "raw" }}>
        <span class="field-label">{props.field.name}</span>
        <Show
          when={props.field.file}
          fallback={
            <Show
              when={props.field.type === "url" && props.field.value}
              fallback={<span classList={{ "field-value": true, secret: props.field.sensitive, totp: props.field.type === "totp" }}>{shownValue()}</span>}
            >
              <button class="url-value" type="button" onClick={() => props.onOpenURL(props.field.value!)}>
                {props.field.value}<IconExternalLink size={14} />
              </button>
            </Show>
          }
        >
          {(file) => <span class="file-value"><IconFolder size={16} />{file().name}<small>{formatBytes(file().size)}</small></span>}
        </Show>
        <span class="field-actions">
          <Show when={props.field.file}>
            <IconButton label={`Save ${props.field.name}`} onClick={() => props.onSaveFile(props.field)}><IconDownload size={17} /></IconButton>
          </Show>
          <Show when={props.largeType}>
            <IconButton label={`Show ${props.field.name} in large type`} onClick={() => props.onLargeType(props.field)}><IconTextSize size={17} /></IconButton>
          </Show>
          <Show when={props.field.sensitive}>
            <IconButton label={props.revealed !== undefined ? "Hide value" : "Reveal value"} onClick={() => props.onReveal(props.field)}>
              {props.revealed !== undefined ? <IconEyeOff size={17} /> : <IconEye size={17} />}
            </IconButton>
          </Show>
          <Show when={props.field.copyable}>
            <IconButton label={`Copy ${props.field.name}`} onClick={() => props.onCopy(props.field)}><IconCopy size={17} /></IconButton>
          </Show>
        </span>
      </div>
      <Show when={props.field.children?.length}>
        <div class="nested-fields">
          <For each={props.field.children}>
            {(child) => (
              <FieldRow
                field={child}
                revealed={undefined}
                largeType={props.largeType}
                onReveal={props.onReveal}
                onCopy={props.onCopy}
                onLargeType={props.onLargeType}
                onSaveFile={props.onSaveFile}
                onOpenURL={props.onOpenURL}
              />
            )}
          </For>
        </div>
      </Show>
    </>
  );
}

function LargeTypeModal(props: { label: string; value: string; onClose(): void; onCopy(): void }): JSX.Element {
  onMount(() => {
    const timer = setTimeout(props.onClose, 30_000);
    onCleanup(() => clearTimeout(timer));
  });
  const characters = () => Array.from(props.value);
  const displayCharacter = (character: string) => {
    if (character === " ") return "␠";
    if (character === "\n") return "↵";
    if (character === "\t") return "⇥";
    return character;
  };
  return (
    <div class="modal-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section class="modal large-type-modal" role="dialog" aria-modal="true" aria-labelledby="large-type-title">
        <header>
          <div><h1 id="large-type-title">{props.label}</h1></div>
          <div class="large-type-actions">
            <IconButton label={`Copy ${props.label}`} onClick={props.onCopy}><IconCopy size={18} /></IconButton>
            <IconButton label="Close large type" onClick={props.onClose}><IconX size={18} /></IconButton>
          </div>
        </header>
        <div class="large-type-grid">
          <For each={characters()}>
            {(character, index) => (
              <span classList={{ "large-type-character": true, symbol: /[^a-z0-9]/i.test(character), digit: /\d/.test(character) }}>
                <strong>{displayCharacter(character)}</strong>
                <small>{index() + 1}</small>
              </span>
            )}
          </For>
        </div>
      </section>
    </div>
  );
}

function WorkspacePanel(props: {
  view: MainView;
  status: VaultStatus;
  compactRows: boolean;
  onCompactRows(value: boolean): void;
  onNotify(message: string): void;
  onStatus(status: VaultStatus): void;
  onRecovery(): void;
  onError(message: string): void;
}): JSX.Element {
  const [launchAtLogin, setLaunchAtLogin] = createSignal(false);
  onMount(() => {
    void window.fd0.launchAtLogin().then(setLaunchAtLogin).catch((error) => props.onError(errorText(error)));
  });
  return (
    <>
      <Show when={props.view === "generator"}>
        <PasswordGeneratorPanel onNotify={props.onNotify} onError={props.onError} />
      </Show>
      <Show when={props.view === "support"}>
        <SupportPanel status={props.status} onStatus={props.onStatus} onNotify={props.onNotify} onError={props.onError} />
      </Show>
      <Show when={props.view === "settings"}>
        <section class="workspace-panel">
          <header><h1>Settings</h1><p>Control how fd0 behaves on this device.</p></header>
          <div class="settings-group">
            <h2>Appearance</h2>
            <label class="setting-row">
              <span><strong>Compact item rows</strong><small>Show more items without changing text size.</small></span>
              <input type="checkbox" checked={props.compactRows} onChange={(event) => props.onCompactRows(event.currentTarget.checked)} />
            </label>
          </div>
          <div class="settings-group">
            <h2>Desktop</h2>
            <label class="setting-row">
              <span><strong>Open at login</strong><small>Keep fd0 ready in the menu bar after you sign in.</small></span>
              <input
                type="checkbox"
                disabled={window.fd0.development}
                checked={launchAtLogin()}
                onChange={(event) => {
                  const requested = event.currentTarget.checked;
                  void window.fd0.setLaunchAtLogin(requested).then(setLaunchAtLogin).catch((error) => props.onError(errorText(error)));
                }}
              />
            </label>
          </div>
          <div class="settings-group">
            <h2>Security</h2>
            <Show when={(props.status.authMethods?.length ?? 0) > 0}>
              <label class="setting-row">
                <span><strong>Default unlock method</strong><small>Used first when fd0 Desktop opens this vault.</small></span>
                <SelectControl
                  class="setting-select"
                  containerClass="setting-select-control"
                  value={props.status.authMethods?.find((method) => method.default)?.id ?? ""}
                  onChange={(event) => {
                    void window.fd0
                      .setDefaultAuthMethod(event.currentTarget.value)
                      .then((next) => {
                        props.onStatus(next);
                        props.onNotify("Default unlock method updated.");
                      })
                      .catch((error) => props.onError(errorText(error)));
                  }}
                >
                  <option value="">Automatic</option>
                  <For each={props.status.authMethods}>{(method) => <option value={method.id}>{method.label}</option>}</For>
                </SelectControl>
              </label>
            </Show>
            <div class="setting-row static">
              <span><strong>Clipboard clearing</strong><small>Copied secrets are removed after 30 seconds.</small></span>
              <span class="setting-value">30 seconds</span>
            </div>
            <div class="setting-row static">
              <span><strong>Vault lifecycle</strong><small>The fd0 agent enforces idle and maximum unlock time.</small></span>
              <span class="setting-value">Managed by fd0</span>
            </div>
            <div class="setting-row static">
              <span><strong>Recovery file</strong><small>Export an offline identity backup protected by a separate passphrase.</small></span>
              <button class="secondary-button" type="button" onClick={props.onRecovery}>Export…</button>
            </div>
          </div>
        </section>
      </Show>
    </>
  );
}

function SupportPanel(props: {
  status: VaultStatus;
  onStatus(status: VaultStatus): void;
  onNotify(message: string): void;
  onError(message: string): void;
}): JSX.Element {
  const [update, setUpdate] = createSignal<UpdateStatus>({ state: "unsupported" });
  onMount(() => {
    void window.fd0.updateStatus().then(setUpdate).catch((error) => props.onError(errorText(error)));
    const unsubscribe = window.fd0.onUpdate(setUpdate);
    onCleanup(unsubscribe);
  });
  const updateLabel = createMemo(() => {
    const current = update();
    switch (current.state) {
      case "checking": return "Checking…";
      case "available": return `${current.version ?? "New version"} available`;
      case "downloading": return `Downloading ${Math.round(current.progress ?? 0)}%`;
      case "ready": return `${current.version ?? "Update"} ready`;
      case "current": return "Up to date";
      case "error": return current.message ?? "Update check failed";
      case "unsupported": return "Available in installed builds";
      default: return "Not checked";
    }
  });
  return (
    <section class="workspace-panel support-panel">
      <header><h1>Support</h1><p>Health, updates, and help for this device.</p></header>
      <div class="health-summary" classList={{ warning: Boolean(props.status.agentMismatch) }}>
        {props.status.agentMismatch ? <IconAlertTriangle size={28} /> : <IconShieldCheck size={28} />}
        <div>
          <strong>{props.status.agentMismatch ? "Local service needs a restart" : "Everything is working"}</strong>
          <span>{props.status.agentMismatch ? "The app and running fd0 agent use different versions." : "Your vault and local fd0 service are available."}</span>
        </div>
      </div>
      <div class="support-grid">
        <div><span>Vault</span><strong>{props.status.unlocked ? "Unlocked" : "Locked"}</strong></div>
        <div><span>Local service</span><strong>{props.status.agentMismatch ? "Restart required" : props.status.agentRunning ? "Running" : "Stopped"}</strong></div>
        <div><span>App version</span><strong>{props.status.expectedVersion || props.status.version || "Development"}</strong></div>
        <div><span>Build</span><strong>{props.status.expectedFlavor || props.status.flavor || "standard"}</strong></div>
      </div>
      <Show when={props.status.agentMismatch}>
        <div class="update-row service-warning">
          <div><span>Compatibility</span><strong>Restarting will lock this vault once.</strong></div>
          <button
            class="secondary-button"
            type="button"
            onClick={() => void window.fd0.restartAgent()
              .then((next) => {
                props.onStatus(next);
                props.onNotify("Local service restarted.");
              })
              .catch((error) => props.onError(errorText(error)))}
          ><IconRefresh size={16} />Restart service</button>
        </div>
      </Show>
      <div class="update-row">
        <div><span>Updates</span><strong>{updateLabel()}</strong></div>
        <Show
          when={update().state === "ready"}
          fallback={
            <button
              class="secondary-button"
              type="button"
              disabled={update().state === "checking" || update().state === "downloading" || update().state === "unsupported"}
              onClick={() => void window.fd0.checkForUpdates().then(setUpdate).catch((error) => props.onError(errorText(error)))}
            ><IconRefresh size={16} />Check now</button>
          }
        >
          <button class="primary-button" type="button" onClick={() => void window.fd0.installUpdate().catch((error) => props.onError(errorText(error)))}>Restart and update</button>
        </Show>
      </div>
      <div class="support-actions">
        <button class="secondary-button" type="button" onClick={() => void window.fd0.openExternal("https://fd0.sh/docs").catch((error) => props.onError(errorText(error)))}><IconExternalLink size={16} />Open documentation</button>
        <button class="secondary-button" type="button" onClick={() => void window.fd0.openExternal("https://github.com/ValentinKolb/fd0.sh/issues").catch((error) => props.onError(errorText(error)))}><IconAlertTriangle size={16} />Report a problem</button>
      </div>
    </section>
  );
}

function SecretEditorModal(props: {
  input: SaveSecretInput;
  onClose(): void;
  onSaved(ref: RecordRef): Promise<void>;
}): JSX.Element {
  const [name, setName] = createSignal(props.input.name);
  const [value, setValue] = createSignal(props.input.value);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const nextName = name().trim();
      await window.fd0.saveSecret({ ...props.input, name: nextName, value: value() });
      await props.onSaved({ scopeId: props.input.scopeId, name: nextName });
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="modal-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="edit-secret-title">
        <header>
          <div><h1 id="edit-secret-title">Edit secret</h1><p>The name and value remain encrypted in this vault.</p></div>
          <IconButton label="Close" onClick={props.onClose}><IconX size={18} /></IconButton>
        </header>
        <form onSubmit={save}>
          <div class="form-grid">
            <label class="full"><span>Name</span><input required value={name()} onInput={(event) => setName(event.currentTarget.value)} /></label>
            <label class="full"><span>Value</span><textarea required spellcheck={false} value={value()} onInput={(event) => setValue(event.currentTarget.value)} /></label>
          </div>
          <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
          <footer><button class="secondary-button" type="button" onClick={props.onClose}>Cancel</button><button class="primary-button" type="submit" disabled={busy()}>{busy() ? "Saving…" : "Save changes"}</button></footer>
        </form>
      </section>
    </div>
  );
}

function CreateVaultModal(props: { onClose(): void; onSaved(): Promise<void> }): JSX.Element {
  const [label, setLabel] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await window.fd0.createScope(label().trim());
      await props.onSaved();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="modal-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section class="modal small-modal" role="dialog" aria-modal="true" aria-labelledby="create-vault-title">
        <header>
          <div><h1 id="create-vault-title">Create vault</h1><p>Items in a vault share one membership and sync boundary.</p></div>
          <IconButton label="Close" onClick={props.onClose}><IconX size={18} /></IconButton>
        </header>
        <form onSubmit={save}>
          <label><span>Name</span><input autofocus required value={label()} onInput={(event) => setLabel(event.currentTarget.value)} /></label>
          <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
          <footer><button class="secondary-button" type="button" onClick={props.onClose}>Cancel</button><button class="primary-button" type="submit" disabled={busy() || !label().trim()}>{busy() ? "Creating…" : "Create vault"}</button></footer>
        </form>
      </section>
    </div>
  );
}

function SSHHostEditorModal(props: {
  input: SaveSSHHostInput;
  onClose(): void;
  onSaved(ref: RecordRef): Promise<void>;
}): JSX.Element {
  const [alias, setAlias] = createSignal(props.input.host.Alias);
  const [hostname, setHostname] = createSignal(props.input.host.Hostname);
  const [user, setUser] = createSignal(props.input.host.User ?? "");
  const [port, setPort] = createSignal(props.input.host.Port || 22);
  const [keyName, setKeyName] = createSignal(props.input.host.KeyName ?? "");
  const [proxyJump, setProxyJump] = createSignal(props.input.host.ProxyJump ?? "");
  const [description, setDescription] = createSignal(props.input.host.Description ?? "");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const nextAlias = alias().trim();
      await window.fd0.saveSSHHost({
        ...props.input,
        host: {
          ...props.input.host,
          Alias: nextAlias,
          Hostname: hostname().trim(),
          User: user().trim(),
          Port: port(),
          KeyName: keyName().trim(),
          ProxyJump: proxyJump().trim(),
          Description: description().trim(),
        },
      });
      await props.onSaved({ scopeId: props.input.scopeId, name: `host:${nextAlias}` });
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="modal-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="edit-ssh-title">
        <header>
          <div><h1 id="edit-ssh-title">Edit SSH host</h1><p>Changes are rendered into your fd0 SSH configuration after sync.</p></div>
          <IconButton label="Close" onClick={props.onClose}><IconX size={18} /></IconButton>
        </header>
        <form onSubmit={save}>
          <div class="form-grid">
            <label><span>Alias</span><input required value={alias()} onInput={(event) => setAlias(event.currentTarget.value)} /></label>
            <label><span>Host</span><input required value={hostname()} onInput={(event) => setHostname(event.currentTarget.value)} /></label>
            <label><span>User</span><input value={user()} onInput={(event) => setUser(event.currentTarget.value)} /></label>
            <label><span>Port</span><input type="number" min="1" max="65535" value={port()} onInput={(event) => setPort(Number(event.currentTarget.value))} /></label>
            <label><span>SSH key</span><input value={keyName()} onInput={(event) => setKeyName(event.currentTarget.value)} /></label>
            <label><span>Proxy jump</span><input value={proxyJump()} onInput={(event) => setProxyJump(event.currentTarget.value)} /></label>
            <label class="full"><span>Notes</span><textarea value={description()} onInput={(event) => setDescription(event.currentTarget.value)} /></label>
          </div>
          <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
          <footer><button class="secondary-button" type="button" onClick={props.onClose}>Cancel</button><button class="primary-button" type="submit" disabled={busy()}>{busy() ? "Saving…" : "Save changes"}</button></footer>
        </form>
      </section>
    </div>
  );
}

function RecoveryExportModal(props: { onClose(): void; onSaved(): void }): JSX.Element {
  const [passphrase, setPassphrase] = createSignal("");
  const [confirmation, setConfirmation] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const strength = createMemo(() => password.strength(passphrase()));

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (passphrase() !== confirmation()) {
      setError("Passphrases do not match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await window.fd0.exportRecovery(passphrase());
      if (result.saved) props.onSaved();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="modal-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-title">
        <header>
          <div><h1 id="recovery-title">Export recovery file</h1><p>This restores your fd0 identity if every device is lost.</p></div>
          <IconButton label="Close" onClick={props.onClose}><IconX size={18} /></IconButton>
        </header>
        <form onSubmit={save}>
          <div class="recovery-warning"><IconAlertTriangle size={20} /><span>Store the file offline. Anyone with the file and this separate passphrase can impersonate your identity.</span></div>
          <div class="form-grid">
            <label class="full"><span>Recovery passphrase</span><input type="password" required minlength="12" autocomplete="new-password" value={passphrase()} onInput={(event) => setPassphrase(event.currentTarget.value)} /></label>
            <div class="onboarding-strength full"><span class={`score-${strength().score}`} /><small>{passphrase() ? strength().label : "At least 12 characters"}</small></div>
            <label class="full"><span>Confirm recovery passphrase</span><input type="password" required autocomplete="new-password" value={confirmation()} onInput={(event) => setConfirmation(event.currentTarget.value)} /></label>
          </div>
          <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
          <footer><button class="secondary-button" type="button" onClick={props.onClose}>Cancel</button><button class="primary-button" type="submit" disabled={busy() || passphrase().length < 12}>{busy() ? "Encrypting…" : "Choose location…"}</button></footer>
        </form>
      </section>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function flattenFieldViews(field: FieldView): FieldView[] {
  return [field, ...(field.children ?? []).flatMap(flattenFieldViews)];
}

function relativeDate(raw: string): string {
  const date = new Date(raw);
  if (Number.isNaN(date.valueOf())) return raw;
  const seconds = Math.round((date.valueOf() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, "hour");
  return formatter.format(Math.round(hours / 24), "day");
}

export default App;
