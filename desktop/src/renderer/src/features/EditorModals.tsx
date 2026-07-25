import { Show, createMemo, createSignal, type JSX } from "solid-js";
import { IconAlertTriangle } from "@tabler/icons-solidjs";
import { toAppError } from "../lib/errors";
import { useVault } from "../lib/store";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { Field, Input, SecretInput, StrengthMeter, Textarea } from "../ui/Fields";

function Footer(props: { onCancel(): void; busy: boolean; label: string; busyLabel: string; disabled?: boolean }): JSX.Element {
  return (
    <>
      <Button onClick={props.onCancel}>Cancel</Button>
      <Button variant="primary" type="submit" form="editor-form" disabled={props.busy || props.disabled}>
        {props.busy ? props.busyLabel : props.label}
      </Button>
    </>
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
