import { For, Show, createEffect, createMemo, createSignal, type JSX } from "solid-js";
import { IconCheck, IconKey, IconPlus, IconSearch } from "@tabler/icons-solidjs";
import type { SSHKeySummary } from "../../../shared/contracts";
import { toAppError } from "../lib/errors";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";
import { Field, Input } from "../ui/Fields";
import { Modal } from "../ui/Modal";

export function SSHKeyPicker(props: {
  scopeId: string;
  current: string;
  onSelect(key: SSHKeySummary | null): void;
  onClose(): void;
}): JSX.Element {
  const vault = useVault();
  const [keys, setKeys] = createSignal<SSHKeySummary[]>([]);
  const [query, setQuery] = createSignal("");
  const [loading, setLoading] = createSignal(true);
  const [creating, setCreating] = createSignal(false);
  const [busy, setBusy] = createSignal(false);
  const [name, setName] = createSignal("");
  const [comment, setComment] = createSignal("");

  const filtered = createMemo(() => {
    const needle = query().trim().toLocaleLowerCase();
    if (!needle) return keys();
    return keys().filter((key) =>
      [key.name, key.algorithm, key.fingerprint, key.comment ?? ""].some((value) =>
        value.toLocaleLowerCase().includes(needle),
      ),
    );
  });
  const missingCurrent = createMemo(() => Boolean(props.current) && !loading() && !keys().some((key) => key.name === props.current));

  async function load(): Promise<void> {
    setLoading(true);
    try {
      setKeys(await window.fd0.listSSHKeys(props.scopeId));
    } catch (cause) {
      vault.pushError(toAppError(cause, "fd0 could not load SSH keys"));
    } finally {
      setLoading(false);
    }
  }

  createEffect(() => {
    props.scopeId;
    void load();
  });

  async function createKey(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const keyName = name().trim();
    if (!keyName || busy()) return;
    setBusy(true);
    try {
      await window.fd0.generateSSHKey({ scopeId: props.scopeId, name: keyName, comment: comment().trim() });
      const next = await window.fd0.listSSHKeys(props.scopeId);
      const created = next.find((key) => key.name === keyName);
      if (!created) throw new Error("The new SSH key did not appear in this vault");
      await vault.refresh();
      props.onSelect(created);
      vault.notify(`${created.name} created and selected`);
      props.onClose();
    } catch (cause) {
      vault.pushError(toAppError(cause, `fd0 could not create ${keyName || "that SSH key"}`));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={creating() ? "Create SSH key" : "Choose SSH key"}
      description={
        creating()
          ? "fd0 generates an Ed25519 key inside this vault and selects it for the server."
          : "Only keys from the server's vault can be assigned."
      }
      size="small"
      onClose={props.onClose}
      footer={
        <div class="editor-footer-actions">
          <Show
            when={creating()}
            fallback={<Button onClick={props.onClose}>Cancel</Button>}
          >
            <Button onClick={() => setCreating(false)}>Back</Button>
            <Button variant="primary" type="submit" form="ssh-key-create-form" disabled={busy() || !name().trim()}>
              {busy() ? "Creating…" : "Create and select"}
            </Button>
          </Show>
        </div>
      }
    >
      <Show
        when={!creating()}
        fallback={
          <form id="ssh-key-create-form" class="field-stack" onSubmit={createKey}>
            <Field label="Name">
              {(field) => (
                <Input
                  id={field.id}
                  autofocus
                  required
                  placeholder="deploy"
                  value={name()}
                  onInput={(event) => setName(event.currentTarget.value)}
                />
              )}
            </Field>
            <Field label="Comment" optional hint="Helps you recognise the key on a server.">
              {(field) => (
                <Input
                  id={field.id}
                  placeholder="you@example.com"
                  value={comment()}
                  onInput={(event) => setComment(event.currentTarget.value)}
                />
              )}
            </Field>
          </form>
        }
      >
        <div class="ssh-key-picker">
          <label class="ssh-key-search">
            <IconSearch size={16} aria-hidden="true" />
            <Input
              autofocus
              aria-label="Search SSH keys"
              placeholder="Search keys"
              value={query()}
              onInput={(event) => setQuery(event.currentTarget.value)}
            />
          </label>

          <Show when={missingCurrent()}>
            <p class="field-message is-error" role="alert">
              “{props.current}” is no longer available in this vault. Choose another key or use no fd0 key.
            </p>
          </Show>

          <div class="ssh-key-options" role="listbox" aria-label="SSH keys">
            <button
              type="button"
              role="option"
              aria-selected={!props.current}
              classList={{ "ssh-key-option": true, "is-selected": !props.current }}
              onClick={() => {
                props.onSelect(null);
                props.onClose();
              }}
            >
              <span class="ssh-key-option-glyph" aria-hidden="true">
                <IconKey size={17} />
              </span>
              <span class="ssh-key-option-copy">
                <strong>No fd0 key</strong>
                <small>Let SSH use the other identities configured on this device.</small>
              </span>
              <Show when={!props.current}>
                <IconCheck size={16} aria-hidden="true" />
              </Show>
            </button>

            <Show when={!loading()} fallback={<p class="ssh-key-picker-empty">Loading keys…</p>}>
              <For each={filtered()}>
                {(key) => (
                  <button
                    type="button"
                    role="option"
                    aria-selected={key.name === props.current}
                    classList={{ "ssh-key-option": true, "is-selected": key.name === props.current }}
                    onClick={() => {
                      props.onSelect(key);
                      props.onClose();
                    }}
                  >
                    <span class="ssh-key-option-glyph" aria-hidden="true">
                      <IconKey size={17} />
                    </span>
                    <span class="ssh-key-option-copy">
                      <strong>{key.name}</strong>
                      <small>{key.comment || key.algorithm}</small>
                      <code>{key.fingerprint}</code>
                    </span>
                    <Show when={key.name === props.current}>
                      <IconCheck size={16} aria-hidden="true" />
                    </Show>
                  </button>
                )}
              </For>
              <Show when={filtered().length === 0}>
                <p class="ssh-key-picker-empty">No matching SSH keys in this vault.</p>
              </Show>
            </Show>
          </div>

          <Button class="ssh-key-create-action" onClick={() => setCreating(true)}>
            <IconPlus size={16} aria-hidden="true" />
            Create new SSH key
          </Button>
        </div>
      </Show>
    </Modal>
  );
}
