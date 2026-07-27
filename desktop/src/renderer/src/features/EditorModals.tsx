import { Show, createMemo, createSignal, type JSX } from "solid-js";
import { IconAlertTriangle, IconTransfer } from "@tabler/icons-solidjs";
import type { ItemSummary, ScopeSummary } from "../../../shared/contracts";
import { toAppError } from "../lib/errors";
import { useVault } from "../lib/store";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { Field, Input, SecretInput, Select, StrengthMeter, Textarea } from "../ui/Fields";

function Footer(props: {
  onCancel(): void;
  busy: boolean;
  label: string;
  busyLabel: string;
  disabled?: boolean;
  form?: string;
}): JSX.Element {
  return (
    <>
      <Button onClick={props.onCancel}>Cancel</Button>
      <Button variant="primary" type="submit" form={props.form ?? "editor-form"} disabled={props.busy || props.disabled}>
        {props.busy ? props.busyLabel : props.label}
      </Button>
    </>
  );
}

export function MoveItemModal(props: {
  item: ItemSummary;
  scopes: ScopeSummary[];
  onClose(): void;
  onMoved(targetScopeId: string): Promise<void>;
}): JSX.Element {
  const vault = useVault();
  const options = createMemo(() =>
    props.scopes
      .filter((scope) => scope.id !== props.item.scopeId)
      .map((scope) => ({ value: scope.id, label: scope.label })),
  );
  const [targetScopeId, setTargetScopeId] = createSignal(options()[0]?.value ?? "");
  const [busy, setBusy] = createSignal(false);

  async function move(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (!targetScopeId()) return;
    setBusy(true);
    try {
      const result = await window.fd0.moveItem({
        source: { scopeId: props.item.scopeId, name: props.item.recordName },
        targetScopeId: targetScopeId(),
      });
      if (!result.ok) return;
      await props.onMoved(targetScopeId());
    } catch (cause) {
      vault.pushError(toAppError(cause, `fd0 could not move ${props.item.title}`));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Move to another vault"
      description={`Move ${props.item.title} without changing its contents.`}
      size="small"
      onClose={props.onClose}
      footer={
        <Footer
          form="move-item-form"
          onCancel={props.onClose}
          busy={busy()}
          label="Continue…"
          busyLabel="Moving…"
          disabled={!targetScopeId()}
        />
      }
    >
      <form id="move-item-form" class="field-stack" onSubmit={move}>
        <Field label="Destination vault" hint="Vault access controls who can open this item.">
          {(field) => (
            <Select
              id={field.id}
              value={targetScopeId()}
              options={options()}
              onChange={setTargetScopeId}
              placeholder="Choose a vault"
            />
          )}
        </Field>
        <div class="callout">
          <IconTransfer size={17} aria-hidden="true" />
          <p>The item keeps its name and contents. You will confirm the access change before it moves.</p>
        </div>
      </form>
    </Modal>
  );
}

export function RenameItemModal(props: {
  item: ItemSummary;
  onClose(): void;
  onRenamed(name: string): Promise<void>;
}): JSX.Element {
  const vault = useVault();
  const [name, setName] = createSignal(props.item.title);
  const [busy, setBusy] = createSignal(false);
  const nextName = () => name().trim();

  async function rename(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (!nextName() || nextName() === props.item.title) return;
    setBusy(true);
    try {
      const result = await window.fd0.renameItem({
        source: { scopeId: props.item.scopeId, name: props.item.recordName },
        name: nextName(),
      });
      if (result.ok) await props.onRenamed(nextName());
    } catch (cause) {
      vault.pushError(toAppError(cause, `fd0 could not rename ${props.item.title}`));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`Rename ${props.item.title}`}
      description="The generated configuration will use the new name."
      size="small"
      dirty={nextName() !== props.item.title}
      onClose={props.onClose}
      footer={
        <Footer
          form="rename-item-form"
          onCancel={props.onClose}
          busy={busy()}
          label="Continue…"
          busyLabel="Renaming…"
          disabled={!nextName() || nextName() === props.item.title}
        />
      }
    >
      <form id="rename-item-form" class="field-stack" onSubmit={rename}>
        <Field label="Name">
          {(field) => (
            <Input
              id={field.id}
              autofocus
              required
              value={name()}
              onInput={(event) => setName(event.currentTarget.value)}
            />
          )}
        </Field>
      </form>
    </Modal>
  );
}

export function CreateVaultModal(props: { onClose(): void; onSaved(): Promise<void> }): JSX.Element {
  const vault = useVault();
  const [label, setLabel] = createSignal("");
  const [busy, setBusy] = createSignal(false);

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    setBusy(true);
    try {
      await window.fd0.createScope(label().trim());
      await props.onSaved();
    } catch (cause) {
      vault.pushError(toAppError(cause, "fd0 could not create that vault"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="New vault"
      description="A vault is a group of items you can share with other people as one unit."
      size="small"
      dirty={Boolean(label().trim())}
      onClose={props.onClose}
      footer={<Footer onCancel={props.onClose} busy={busy()} label="Create vault" busyLabel="Creating…" disabled={!label().trim()} />}
    >
      <form id="editor-form" class="field-stack" onSubmit={save}>
        <Field label="Name" hint="For example: Personal, Work, or the name of a team.">
          {(field) => (
            <Input id={field.id} autofocus required value={label()} onInput={(event) => setLabel(event.currentTarget.value)} />
          )}
        </Field>
      </form>
    </Modal>
  );
}

export function RecoveryExportModal(props: { onClose(): void; onSaved(): void }): JSX.Element {
  const vault = useVault();
  const [passphrase, setPassphrase] = createSignal("");
  const [confirmation, setConfirmation] = createSignal("");
  const [busy, setBusy] = createSignal(false);

  const mismatch = createMemo(() => confirmation().length > 0 && passphrase() !== confirmation());
  const matched = createMemo(() => confirmation().length > 0 && passphrase() === confirmation() && passphrase().length >= 12);

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (passphrase() !== confirmation()) return;
    setBusy(true);
    try {
      const result = await window.fd0.exportRecovery(passphrase());
      if (result.saved) {
        props.onSaved();
        return;
      }
      vault.notify("No recovery file was saved");
    } catch (cause) {
      vault.pushError(toAppError(cause, "fd0 could not create the recovery file"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Create a recovery file"
      description="This file restores your fd0 identity if you lose every device."
      dirty={Boolean(passphrase() || confirmation())}
      onClose={props.onClose}
      footer={
        <Footer
          onCancel={props.onClose}
          busy={busy()}
          label="Choose where to save…"
          busyLabel="Encrypting…"
          disabled={passphrase().length < 12 || mismatch() || !confirmation()}
        />
      }
    >
      <div class="callout callout-warn">
        <IconAlertTriangle size={17} aria-hidden="true" />
        <div>
          <strong>Keep this file offline.</strong>
          <p>Anyone who has both the file and this passphrase can act as you. Store it somewhere separate from this device.</p>
        </div>
      </div>
      <form id="editor-form" class="field-stack" onSubmit={save}>
        <Field label="Passphrase for the recovery file" hint="Different from your vault passphrase.">
          {(field) => (
            <>
              <SecretInput
                id={field.id}
                what="passphrase"
                required
                minlength="12"
                autocomplete="new-password"
                value={passphrase()}
                onInput={(event) => setPassphrase(event.currentTarget.value)}
              />
              <StrengthMeter value={passphrase()} />
            </>
          )}
        </Field>
        <Field
          label="Repeat passphrase"
          error={mismatch() ? "Doesn't match yet" : undefined}
          success={matched() ? "Passphrases match" : undefined}
        >
          {(field) => (
            <SecretInput
              id={field.id}
              what="passphrase"
              required
              autocomplete="new-password"
              aria-invalid={mismatch()}
              value={confirmation()}
              onInput={(event) => setConfirmation(event.currentTarget.value)}
            />
          )}
        </Field>
      </form>
      <Show when={vault.status()?.readiness?.recoveryVerifiedAt}>
        <p class="inline-note">Creating a new recovery file replaces the one you made earlier.</p>
      </Show>
    </Modal>
  );
}
