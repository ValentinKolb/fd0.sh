import { Dynamic } from "solid-js/web";
import { For, Show, createMemo, createSignal, onCleanup, onMount, type Component, type JSX } from "solid-js";
import {
  IconAdjustmentsHorizontal,
  IconBraces,
  IconChevronDown,
  IconEye,
  IconEyeOff,
  IconFileImport,
  IconHexagonLetterK,
  IconKey,
  IconServer,
  IconTerminal2,
  IconX,
  type IconProps,
} from "@tabler/icons-solidjs";
import type { RecordRef, SavePassInput, ScopeSummary } from "../../../shared/contracts";
import { errorText } from "../errors";
import { IconButton, SelectControl } from "./Controls";
import { PasswordGeneratorPopover } from "./PasswordGenerator";

type AddItemKind = "password" | "secret" | "ssh" | "ssh-key" | "kubernetes" | "talos";
type IconComponent = Component<IconProps>;

const itemKinds: Array<{ id: AddItemKind; label: string; description: string; icon: IconComponent }> = [
  { id: "password", label: "Password", description: "Login, website, or app account", icon: IconKey },
  { id: "secret", label: "Secret", description: "API token or arbitrary protected value", icon: IconBraces },
  { id: "ssh", label: "SSH host", description: "Server connection and login details", icon: IconTerminal2 },
  { id: "ssh-key", label: "SSH key", description: "Generate a new Ed25519 key", icon: IconKey },
  { id: "kubernetes", label: "Kubernetes", description: "Import contexts from a kubeconfig", icon: IconHexagonLetterK },
  { id: "talos", label: "Talos", description: "Import contexts from a talosconfig", icon: IconServer },
];

export function AddItemModal(props: {
  scopes: ScopeSummary[];
  onClose(): void;
  onSaved(ref?: RecordRef): Promise<void>;
}): JSX.Element {
  const [kind, setKind] = createSignal<AddItemKind>("password");
  const [kindOpen, setKindOpen] = createSignal(false);
  const [scopeID, setScopeID] = createSignal(props.scopes[0]?.id ?? "");
  const [title, setTitle] = createSignal("");
  const [website, setWebsite] = createSignal("");
  const [username, setUsername] = createSignal("");
  const [secret, setSecret] = createSignal("");
  const [secretVisible, setSecretVisible] = createSignal(false);
  const [generatorOpen, setGeneratorOpen] = createSignal(false);
  const [host, setHost] = createSignal("");
  const [port, setPort] = createSignal(22);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  let kindRoot: HTMLDivElement | undefined;

  const currentKind = createMemo(() => itemKinds.find((option) => option.id === kind()) ?? itemKinds[0]!);
  const importsConfig = createMemo(() => kind() === "kubernetes" || kind() === "talos");
  const titleLabel = createMemo(() => kind() === "ssh" ? "Alias" : kind() === "secret" || kind() === "ssh-key" ? "Name" : "Title");
  const canSave = createMemo(() => {
    if (!scopeID()) return false;
    if (importsConfig()) return true;
    if (!title().trim()) return false;
    if (kind() === "secret" && !secret()) return false;
    return kind() !== "ssh" || Boolean(host().trim());
  });

  onMount(() => {
    const close = (event: PointerEvent) => {
      if (kindRoot && !kindRoot.contains(event.target as Node)) setKindOpen(false);
    };
    document.addEventListener("pointerdown", close);
    onCleanup(() => document.removeEventListener("pointerdown", close));
  });

  async function savePassword(name: string): Promise<RecordRef> {
    const fields: SavePassInput["item"]["fields"] = [];
    if (username()) fields.push({ type: "text", name: "username", value: username() });
    if (secret()) fields.push({ type: "secret", name: "password", value: secret() });
    await window.fd0.savePass({
      scopeId: scopeID(),
      recordName: name,
      create: true,
      item: { title: name, urls: website().trim() ? [website().trim()] : [], fields },
    });
    return { scopeId: scopeID(), name: `pass:${name}` };
  }

  async function saveCurrentItem(): Promise<RecordRef | undefined> {
    const name = title().trim();
    const selectedKind = kind();
    switch (selectedKind) {
      case "password":
        return savePassword(name);
      case "secret":
        await window.fd0.saveSecret({ scopeId: scopeID(), name, value: secret(), create: true });
        return { scopeId: scopeID(), name };
      case "ssh":
        await window.fd0.saveSSHHost({
          scopeId: scopeID(),
          host: { Alias: name, Hostname: host().trim(), User: username().trim(), Port: port() },
        });
        return { scopeId: scopeID(), name: `host:${name}` };
      case "ssh-key":
        await window.fd0.generateSSHKey({ scopeId: scopeID(), name, comment: username().trim() });
        return { scopeId: scopeID(), name: `ssh:${name}` };
      case "kubernetes":
      case "talos": {
        const imported = await window.fd0.importConfig(selectedKind, scopeID());
        if (!imported?.imported[0]) return undefined;
        return { scopeId: scopeID(), name: `${selectedKind === "kubernetes" ? "kube" : "talos"}:${imported.imported[0]}` };
      }
    }
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (!canSave()) return;
    setBusy(true);
    setError("");
    try {
      const saved = await saveCurrentItem();
      if (saved || !importsConfig()) await props.onSaved(saved);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="modal-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section class="modal add-item-modal" role="dialog" aria-modal="true" aria-labelledby="add-title">
        <header>
          <div><h1 id="add-title">New item</h1><p>Choose what you want to protect, then save it to a vault.</p></div>
          <IconButton label="Close" onClick={props.onClose}><IconX size={18} /></IconButton>
        </header>
        <form onSubmit={save}>
          <div classList={{ "add-item-overview": true, compact: importsConfig() }}>
            <div class="add-kind-picker" ref={kindRoot}>
              <span class="add-field-label">Item type</span>
              <button type="button" aria-haspopup="menu" aria-expanded={kindOpen()} onClick={() => setKindOpen((open) => !open)}>
                <Dynamic component={currentKind().icon} size={19} strokeWidth={1.7} />
                <span><strong>{currentKind().label}</strong><small>{currentKind().description}</small></span>
                <IconChevronDown size={16} />
              </button>
              <Show when={kindOpen()}>
                <div class="add-kind-menu" role="menu" aria-label="Item type">
                  <For each={itemKinds}>
                    {(option) => (
                      <button
                        classList={{ active: option.id === kind() }}
                        type="button"
                        role="menuitemradio"
                        aria-checked={option.id === kind()}
                        onClick={() => {
                          setKind(option.id);
                          setKindOpen(false);
                          setGeneratorOpen(false);
                          setError("");
                        }}
                      >
                        <Dynamic component={option.icon} size={18} strokeWidth={1.7} />
                        <span><strong>{option.label}</strong><small>{option.description}</small></span>
                      </button>
                    )}
                  </For>
                </div>
              </Show>
            </div>
            <Show when={!importsConfig()}>
              <label class="add-title-field"><span>{titleLabel()}</span><input autofocus required placeholder={`Enter ${titleLabel().toLowerCase()}`} value={title()} onInput={(event) => setTitle(event.currentTarget.value)} /></label>
            </Show>
          </div>

          <div class="add-item-fields">
            <Show when={kind() === "password"}>
              <label><span>Website</span><input type="url" placeholder="https://" value={website()} onInput={(event) => setWebsite(event.currentTarget.value)} /></label>
              <label><span>Username</span><input autocomplete="username" value={username()} onInput={(event) => setUsername(event.currentTarget.value)} /></label>
              <label>
                <span>Password</span>
                <div class="password-entry-control">
                  <input autocomplete="new-password" type={secretVisible() ? "text" : "password"} value={secret()} onInput={(event) => setSecret(event.currentTarget.value)} />
                  <button type="button" aria-label={secretVisible() ? "Hide password" : "Show password"} title={secretVisible() ? "Hide password" : "Show password"} onClick={() => setSecretVisible((visible) => !visible)}>
                    {secretVisible() ? <IconEyeOff size={17} /> : <IconEye size={17} />}
                  </button>
                  <div class="password-generator-anchor">
                    <button type="button" aria-label="Password generator options" title="Password generator options" aria-expanded={generatorOpen()} onClick={() => setGeneratorOpen((open) => !open)}><IconAdjustmentsHorizontal size={17} /></button>
                    <Show when={generatorOpen()}>
                      <PasswordGeneratorPopover
                        onClose={() => setGeneratorOpen(false)}
                        onUse={(value) => {
                          setSecret(value);
                          setGeneratorOpen(false);
                        }}
                      />
                    </Show>
                  </div>
                </div>
              </label>
            </Show>
            <Show when={kind() === "secret"}>
              <label><span>Value</span><textarea required spellcheck={false} value={secret()} onInput={(event) => setSecret(event.currentTarget.value)} /></label>
            </Show>
            <Show when={kind() === "ssh"}>
              <div class="form-grid">
                <label class="full"><span>Host</span><input required placeholder="server.example.com" value={host()} onInput={(event) => setHost(event.currentTarget.value)} /></label>
                <label><span>User</span><input autocomplete="username" value={username()} onInput={(event) => setUsername(event.currentTarget.value)} /></label>
                <label><span>Port</span><input type="number" min="1" max="65535" value={port()} onInput={(event) => setPort(Number(event.currentTarget.value))} /></label>
              </div>
            </Show>
            <Show when={kind() === "ssh-key"}>
              <label><span>Comment</span><input placeholder="user@example.com" value={username()} onInput={(event) => setUsername(event.currentTarget.value)} /></label>
            </Show>
            <Show when={importsConfig()}>
              <div class="import-explainer">
                <IconFileImport size={22} />
                <div>
                  <strong>{kind() === "kubernetes" ? "Choose a kubeconfig" : "Choose a talosconfig"}</strong>
                  <span>fd0 imports supported contexts and keeps every credential encrypted in the selected vault.</span>
                </div>
              </div>
            </Show>
          </div>

          <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
          <footer class="add-item-footer">
            <label class="add-vault-control"><span>Vault</span><SelectControl aria-label="Vault" value={scopeID()} onChange={(event) => setScopeID(event.currentTarget.value)}><For each={props.scopes}>{(scope) => <option value={scope.id}>{scope.label}</option>}</For></SelectControl></label>
            <div><button class="secondary-button" type="button" onClick={props.onClose}>Cancel</button><button class="primary-button" type="submit" disabled={busy() || !canSave()}>{busy() ? "Working…" : importsConfig() ? "Choose file…" : "Save item"}</button></div>
          </footer>
        </form>
      </section>
    </div>
  );
}
