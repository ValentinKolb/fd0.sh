import { Show, batch, createSignal, createUniqueId, type JSX } from "solid-js";
import { IconAlertTriangle } from "@tabler/icons-solidjs";
import type { VaultStatus } from "../../../shared/contracts";
import { appWarning, toAppError, type AppError } from "../lib/errors";
import { Button } from "../ui/Button";
import { Field, Input, SecretInput, StrengthMeter } from "../ui/Fields";

type Mode = "create" | "restore";

const MIN_LENGTH = 12;

/**
 * First run. This is the only place a person picks a passphrase fd0 can never
 * reset, so the consequence is stated before the button rather than after the
 * vault exists, and the confirmation is checked while it is typed.
 */
export function Onboarding(props: { onCreated(status: VaultStatus): void }): JSX.Element {
  const [mode, setMode] = createSignal<Mode>("create");
  const [label, setLabel] = createSignal("Personal");
  const [passphrase, setPassphrase] = createSignal("");
  const [confirmation, setConfirmation] = createSignal("");
  const [recoveryPassphrase, setRecoveryPassphrase] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<AppError | null>(null);

  const createTabID = createUniqueId();
  const restoreTabID = createUniqueId();
  const panelID = createUniqueId();

  const longEnough = (): boolean => passphrase().length >= MIN_LENGTH;
  const mismatch = (): boolean => confirmation().length > 0 && confirmation() !== passphrase();
  const matches = (): boolean => confirmation().length > 0 && confirmation() === passphrase();
  const confirmError = (): string | undefined => (mismatch() ? "Doesn't match yet" : undefined);
  const confirmSuccess = (): string | undefined => (matches() && longEnough() ? "Passphrases match" : undefined);

  /** Secrets never survive a tab switch — the two flows mean different things. */
  function selectMode(next: Mode): void {
    if (mode() === next) return;
    batch(() => {
      setMode(next);
      setPassphrase("");
      setConfirmation("");
      setRecoveryPassphrase("");
      setError(null);
    });
  }

  async function create(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (passphrase() !== confirmation()) {
      setError(appWarning("The two passphrases do not match", "Retype the confirmation so both fields are identical."));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await window.fd0.createVault(passphrase(), label());

      /*
       * `vault.create` reports `unlocked: true`, but the session locks again
       * within about a second. Without this the user is sent straight back to
       * the unlock screen and asked for the passphrase they typed a moment ago.
       *
       * Unlock unconditionally rather than branching on the reported state:
       * reading the status first only races the lock. The user has just proved
       * they know the passphrase, and it is cleared immediately afterwards,
       * exactly as on the unlock screen. No protocol or lifetime is changed.
       */
      let status = created;
      try {
        const fresh = await window.fd0.status();
        const method =
          fresh.authMethods?.find((candidate) => candidate.default && candidate.type === "passphrase") ??
          fresh.authMethods?.find((candidate) => candidate.type === "passphrase");
        status = await window.fd0.unlock({ method: method?.id ?? "", passphrase: passphrase() });
      } catch {
        // The vault exists either way — fall through to the unlock screen
        // rather than leaving the user on a dead form.
        status = created;
      }
      setPassphrase("");
      setConfirmation("");
      props.onCreated(status);
    } catch (cause) {
      setError(toAppError(cause, "fd0 could not create the vault"));
    } finally {
      setBusy(false);
    }
  }

  async function restore(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (passphrase() !== confirmation()) {
      setError(appWarning("The two passphrases do not match", "Retype the confirmation so both fields are identical."));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const status = await window.fd0.restoreVault(recoveryPassphrase(), passphrase());
      // No status means the file picker was cancelled; nothing to report.
      if (!status) return;
      setRecoveryPassphrase("");
      setPassphrase("");
      setConfirmation("");
      props.onCreated(status);
    } catch (cause) {
      setError(toAppError(cause, "fd0 could not restore from that recovery file"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="auth-shell">
      {/* Empty on purpose: it exists only as a drag region. A wordmark here
          sits underneath the macOS traffic lights, and the screen already says
          what app this is. */}
      <header class="auth-titlebar" aria-hidden="true" />
      <main class="auth-main">
        <div class="auth-copy">
          <span class="eyebrow">{mode() === "create" ? "New vault" : "Restore"}</span>
          <h1>{mode() === "create" ? "Protect your passwords with fd0" : "Bring your vaults to this device"}</h1>
          <p>
            {mode() === "create"
              ? "Your passphrase unlocks this device. fd0 never sends it to a server and cannot recover it for you."
              : "Restore from the recovery file you saved earlier, then sync your vaults to this device."}
          </p>
        </div>
        <div class="auth-card">
          <div class="auth-tabs" role="tablist" aria-label="Set up fd0">
            <button
              id={createTabID}
              classList={{ "is-active": mode() === "create" }}
              type="button"
              role="tab"
              aria-selected={mode() === "create"}
              aria-controls={panelID}
              onClick={() => selectMode("create")}
            >
              Create new
            </button>
            <button
              id={restoreTabID}
              classList={{ "is-active": mode() === "restore" }}
              type="button"
              role="tab"
              aria-selected={mode() === "restore"}
              aria-controls={panelID}
              onClick={() => selectMode("restore")}
            >
              Restore
            </button>
          </div>
          <div id={panelID} role="tabpanel" aria-labelledby={mode() === "create" ? createTabID : restoreTabID}>
            <Show
              when={mode() === "create"}
              fallback={
                <form class="auth-form" onSubmit={(event) => void restore(event)}>
                  <div class="field-stack">
                    <Field label="Recovery passphrase" hint="The passphrase you chose when you saved the recovery file.">
                      {(field) => (
                        <SecretInput
                          id={field.id}
                          aria-describedby={field.describedBy}
                          what="recovery passphrase"
                          autocomplete="off"
                          required
                          value={recoveryPassphrase()}
                          onInput={(event) => setRecoveryPassphrase(event.currentTarget.value)}
                        />
                      )}
                    </Field>
                    <Field label="New passphrase for this device">
                      {(field) => (
                        <SecretInput
                          id={field.id}
                          aria-describedby={field.describedBy}
                          what="passphrase"
                          autocomplete="new-password"
                          required
                          minlength={MIN_LENGTH}
                          value={passphrase()}
                          onInput={(event) => setPassphrase(event.currentTarget.value)}
                        />
                      )}
                    </Field>
                    <StrengthMeter value={passphrase()} minLength={MIN_LENGTH} />
                    <Field label="Confirm new passphrase" error={confirmError()} success={confirmSuccess()}>
                      {(field) => (
                        <SecretInput
                          id={field.id}
                          aria-describedby={field.describedBy}
                          aria-invalid={mismatch()}
                          what="passphrase"
                          autocomplete="new-password"
                          required
                          value={confirmation()}
                          onInput={(event) => setConfirmation(event.currentTarget.value)}
                        />
                      )}
                    </Field>
                  </div>
                  <ErrorCallout error={error()} />
                  <Button
                    variant="primary"
                    block
                    type="submit"
                    disabled={busy() || !longEnough() || !matches() || !recoveryPassphrase()}
                  >
                    {busy() ? "Restoring…" : "Choose recovery file and restore"}
                  </Button>
                </form>
              }
            >
              <form class="auth-form" onSubmit={(event) => void create(event)}>
                <div class="field-stack">
                  <Field label="First vault" hint="A name for this group of items. You can add more vaults later.">
                    {(field) => (
                      <Input
                        id={field.id}
                        aria-describedby={field.describedBy}
                        required
                        value={label()}
                        onInput={(event) => setLabel(event.currentTarget.value)}
                      />
                    )}
                  </Field>
                  <Field label="Passphrase">
                    {(field) => (
                      <SecretInput
                        id={field.id}
                        aria-describedby={field.describedBy}
                        what="passphrase"
                        autocomplete="new-password"
                        required
                        minlength={MIN_LENGTH}
                        value={passphrase()}
                        onInput={(event) => setPassphrase(event.currentTarget.value)}
                      />
                    )}
                  </Field>
                  <StrengthMeter value={passphrase()} minLength={MIN_LENGTH} />
                  <Field label="Confirm passphrase" error={confirmError()} success={confirmSuccess()}>
                    {(field) => (
                      <SecretInput
                        id={field.id}
                        aria-describedby={field.describedBy}
                        aria-invalid={mismatch()}
                        what="passphrase"
                        autocomplete="new-password"
                        required
                        value={confirmation()}
                        onInput={(event) => setConfirmation(event.currentTarget.value)}
                      />
                    )}
                  </Field>
                </div>
                <div class="callout callout-warn">
                  <IconAlertTriangle size={18} aria-hidden="true" />
                  <div>
                    <strong>Only this passphrase opens your vault.</strong>
                    <p>
                      fd0 cannot reset it and no one can unlock the vault without it. The next step is saving a recovery
                      file, which is your only way back in if you forget it.
                    </p>
                  </div>
                </div>
                <ErrorCallout error={error()} />
                <Button variant="primary" block type="submit" disabled={busy() || !longEnough() || !matches()}>
                  {busy() ? "Creating vault…" : "Create vault"}
                </Button>
              </form>
            </Show>
          </div>
        </div>
      </main>
    </div>
  );
}

function ErrorCallout(props: { error: AppError | null }): JSX.Element {
  return (
    <Show when={props.error}>
      {(error) => (
        <div class="callout callout-error" role="alert">
          <strong>{error().title}</strong>
          <Show when={error().detail}>
            <p>{error().detail}</p>
          </Show>
          <Show when={error().technical}>
            <details class="technical-details">
              <summary>Technical details</summary>
              <pre>{error().technical}</pre>
            </details>
          </Show>
        </div>
      )}
    </Show>
  );
}
