import { Show, createMemo, createSignal, onCleanup, type JSX } from "solid-js";
import { IconAlertTriangle, IconCopy, IconFolder, IconRefresh } from "@tabler/icons-solidjs";
import type { StartupStatus } from "../../../shared/contracts";
import { toAppError, type AppError } from "../lib/errors";
import { Button } from "../ui/Button";

/**
 * Shown instead of the app when the local service never came up.
 *
 * The raw failure text used to be the headline, so the first thing a person read
 * was a protocol string. The headline is now plain language and states that the
 * vault data is untouched; the raw text moves behind a disclosure for support.
 */
export function StartupRecovery(props: {
  status: StartupStatus;
  onStatus(status: StartupStatus): void;
}): JSX.Element {
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal<AppError | null>(null);
  const [copied, setCopied] = createSignal(false);
  let copyReset: ReturnType<typeof setTimeout> | undefined;

  onCleanup(() => clearTimeout(copyReset));

  const starting = (): boolean => props.status.state === "starting";

  const technical = createMemo(() =>
    [props.status.message, error()?.technical]
      .filter((line): line is string => Boolean(line))
      .join("\n\n"),
  );

  async function run(operation: () => Promise<StartupStatus>): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      props.onStatus(await operation());
    } catch (cause) {
      setError(toAppError(cause, "fd0 could not restart its local service"));
    } finally {
      setBusy(false);
    }
  }

  async function copyDiagnostics(): Promise<void> {
    try {
      await window.fd0.copyDiagnostics();
      setCopied(true);
      clearTimeout(copyReset);
      copyReset = setTimeout(() => setCopied(false), 2000);
    } catch (cause) {
      setError(toAppError(cause, "fd0 could not copy the diagnostics"));
    }
  }

  return (
    <div class="auth-shell">
      {/* Empty on purpose: it exists only as a drag region. A wordmark here
          sits underneath the macOS traffic lights, and the screen already says
          what app this is. */}
      <header class="auth-titlebar" aria-hidden="true" />
      <main class="auth-main startup-recovery">
        <div class="auth-card">
          <div class="startup-glyph" aria-hidden="true">
            {starting() ? <IconRefresh size={26} /> : <IconAlertTriangle size={26} />}
          </div>
          <span class="eyebrow">{starting() ? "Starting" : "Needs attention"}</span>
          <h1>{starting() ? "Starting fd0" : "fd0 needs attention"}</h1>
          <p>
            {starting()
              ? "Connecting to the local service…"
              : "fd0 could not start its local service. Your vault data has not been changed."}
          </p>
          <Show when={error()}>
            {(current) => (
              <div class="callout callout-error" role="alert">
                <strong>{current().title}</strong>
                <Show when={current().detail}>
                  <p>{current().detail}</p>
                </Show>
              </div>
            )}
          </Show>
          <Show when={technical()}>
            <details class="technical-details">
              <summary>Technical details</summary>
              <pre>{technical()}</pre>
            </details>
          </Show>
          <Show when={props.status.state === "error"}>
            <div class="startup-actions">
              <Button
                variant="primary"
                block
                disabled={busy()}
                onClick={() => void run(() => window.fd0.retryStartup())}
              >
                <IconRefresh size={16} />
                Try again
              </Button>
              <Button block disabled={busy()} onClick={() => void run(() => window.fd0.repairService())}>
                Repair local service
              </Button>
              <Button block onClick={() => void copyDiagnostics()}>
                <IconCopy size={16} />
                {copied() ? "Diagnostics copied" : "Copy diagnostics"}
              </Button>
              <Button block onClick={() => void window.fd0.openLogs()}>
                <IconFolder size={16} />
                Open logs
              </Button>
              <Button variant="quiet" block onClick={() => void window.fd0.quit()}>
                Quit fd0
              </Button>
            </div>
          </Show>
        </div>
      </main>
    </div>
  );
}
