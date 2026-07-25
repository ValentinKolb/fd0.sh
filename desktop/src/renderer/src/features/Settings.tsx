import { For, Show, createMemo, createSignal, onMount, type JSX } from "solid-js";
import { plural } from "../lib/format";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";
import { Select, Switch } from "../ui/Fields";

/**
 * Device settings.
 *
 * Two rules shape this panel. Anything fd0 does not actually let you change
 * here is stated as a fact with its reason instead of being rendered as a dead
 * control, and the one unfinished safety step — the recovery file — is allowed
 * to shout, because losing it is the only unrecoverable failure in the product.
 */
export function Settings(props: { onExportRecovery(): void; onShowShortcuts(): void }): JSX.Element {
  const vault = useVault();
  const [launchAtLogin, setLaunchAtLogin] = createSignal(false);

  // A development run uses a throwaway profile, so registering a login item
  // would point the real session at a vault that is about to be deleted.
  const inDevelopment = window.fd0.development;

  onMount(() => {
    void window.fd0
      .launchAtLogin()
      .then(setLaunchAtLogin)
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not read your startup setting");
      });
  });

  const authMethods = () => vault.status()?.authMethods ?? [];
  const defaultMethod = () => authMethods().find((method) => method.default)?.id ?? "";

  const lockingValue = createMemo(() => {
    const millis = vault.status()?.idleTimeoutMillis;
    if (!millis) return "Managed by fd0";
    // Sub-minute timeouts exist in test profiles; never round them away to zero.
    const minutes = Math.max(1, Math.round(millis / 60_000));
    return `After ${plural(minutes, "minute")}`;
  });

  function changeLaunchAtLogin(value: boolean): void {
    void window.fd0
      .setLaunchAtLogin(value)
      .then(setLaunchAtLogin)
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not change your startup setting");
      });
  }

  function changeDefaultMethod(method: string): void {
    void window.fd0
      .setDefaultAuthMethod(method)
      .then((next) => {
        vault.setStatus(next);
        vault.notify("Default unlock method updated");
      })
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not change the default unlock method");
      });
  }

  return (
    <section class="panel">
      <header class="panel-header">
        <h1>Settings</h1>
        <p>Control how fd0 behaves on this device.</p>
      </header>

      <div class="panel-column">
        <section class="setting-group">
          <h2 class="eyebrow">Appearance</h2>
          <Switch
            label="Compact rows"
            description="Fit more items on screen without making the text smaller."
            checked={vault.compactRows()}
            onChange={(value) => vault.setCompactRows(value)}
          />
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Desktop</h2>
          <Switch
            label="Open at login"
            description={
              inDevelopment
                ? "Unavailable while fd0 runs in development, which uses a temporary vault."
                : "Keep fd0 ready in the menu bar after you sign in."
            }
            checked={launchAtLogin()}
            disabled={inDevelopment}
            onChange={changeLaunchAtLogin}
          />
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Security</h2>

          <Show when={authMethods().length > 0}>
            <div class="setting-row">
              <div>
                <strong>Default unlock method</strong>
                <small>Tried first when fd0 opens this vault on this device.</small>
              </div>
              <Select
                label="Default unlock method"
                value={defaultMethod()}
                onChange={changeDefaultMethod}
                options={[
                  { value: "", label: "Automatic", hint: "Whichever method fd0 considers best" },
                  ...authMethods().map((method) => ({ value: method.id, label: method.label })),
                ]}
              />
            </div>
          </Show>

          <div class="setting-row setting-static">
            <div>
              <strong>Clipboard</strong>
              <small>Copied secrets are cleared automatically.</small>
            </div>
            <span class="setting-value">After 30 seconds</span>
          </div>

          <div class="setting-row setting-static">
            <div>
              <strong>Automatic locking</strong>
              <small>
                fd0 locks itself after a period of inactivity. This is enforced outside the app and cannot be
                changed here.
              </small>
            </div>
            <span class="setting-value">{lockingValue()}</span>
          </div>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Backup</h2>
          <Show
            when={vault.needsRecovery()}
            fallback={
              <div class="setting-row">
                <div>
                  <strong>Recovery file</strong>
                  <small>An offline copy of this vault's identity, protected by its own passphrase.</small>
                </div>
                <Button onClick={props.onExportRecovery}>Export…</Button>
              </div>
            }
          >
            <div class="callout callout-warn">
              <span class="eyebrow">Not set up yet</span>
              <div class="setting-row">
                <div>
                  <strong>Recovery file</strong>
                  <small>
                    This is the only way back into your vault if you lose this device. It is protected by its own
                    passphrase, and nobody can recreate it for you — not even fd0.
                  </small>
                </div>
                <Button variant="primary" onClick={props.onExportRecovery}>
                  Create recovery file
                </Button>
              </div>
            </div>
          </Show>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Keyboard</h2>
          <div class="setting-row">
            <div>
              <strong>Shortcuts</strong>
              <small>fd0 is fully operable from the keyboard.</small>
            </div>
            <Button onClick={props.onShowShortcuts}>View all shortcuts</Button>
          </div>
        </section>
      </div>
    </section>
  );
}
