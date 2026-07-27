import { For, Show, createSignal, type JSX } from "solid-js";
import { Portal } from "solid-js/web";
import { IconAlertTriangle, IconCheck, IconChevronDown, IconInfoCircle, IconX } from "@tabler/icons-solidjs";
import type { AppError } from "../lib/errors";
import { Button, IconButton } from "./Button";

/**
 * Stacked errors. Previously a single string signal, so a second failure
 * silently replaced the first and the user never saw it.
 */
export function ErrorStack(props: { errors: AppError[]; onDismiss(id: number): void }): JSX.Element {
  return (
    <Portal>
      <div class="notice-stack" aria-live="assertive">
        <For each={props.errors}>{(error) => <ErrorNotice error={error} onDismiss={() => props.onDismiss(error.id)} />}</For>
      </div>
    </Portal>
  );
}

function ErrorNotice(props: { error: AppError; onDismiss(): void }): JSX.Element {
  const [showTechnical, setShowTechnical] = createSignal(false);
  return (
    <div classList={{ notice: true, [`notice-${props.error.severity}`]: true }} role="alert">
      <span class="notice-glyph" aria-hidden="true">
        {props.error.severity === "warning" ? <IconInfoCircle size={18} /> : <IconAlertTriangle size={18} />}
      </span>
      <div class="notice-copy">
        <strong>{props.error.title}</strong>
        <Show when={props.error.detail}>
          <p>{props.error.detail}</p>
        </Show>
        <Show when={props.error.action || props.error.technical}>
          <div class="notice-actions">
            <Show when={props.error.action}>
              {(action) => (
                <Button size="sm" onClick={() => void action().run()}>
                  {action().label}
                </Button>
              )}
            </Show>
            <Show when={props.error.technical}>
              <button
                class="notice-disclosure"
                type="button"
                aria-expanded={showTechnical()}
                onClick={() => setShowTechnical((current) => !current)}
              >
                <IconChevronDown size={13} classList={{ "is-rotated": showTechnical() }} />
                Details
              </button>
            </Show>
          </div>
        </Show>
        <Show when={showTechnical() && props.error.technical}>
          <pre class="notice-technical">{props.error.technical}</pre>
        </Show>
      </div>
      <IconButton label="Dismiss" size="sm" onClick={props.onDismiss}>
        <IconX size={16} />
      </IconButton>
    </div>
  );
}

export type ToastMessage = {
  id: number;
  text: string;
  /** Seconds remaining until the clipboard clears, shown as a countdown. */
  countdown?: number;
  action?: {
    label: string;
    run(): void | Promise<void>;
  };
};

export function Toasts(props: { toasts: ToastMessage[] }): JSX.Element {
  return (
    <Portal>
      <div class="toast-stack" aria-live="polite">
        <For each={props.toasts}>
          {(toast) => (
            <div class="toast" role="status">
              <IconCheck size={16} />
              <span>{toast.text}</span>
              <Show when={toast.countdown !== undefined}>
                <span class="toast-countdown">{toast.countdown}s</span>
              </Show>
              <Show when={toast.action}>
                {(action) => (
                  <button class="toast-action" type="button" onClick={() => void action().run()}>
                    {action().label}
                  </button>
                )}
              </Show>
            </div>
          )}
        </For>
      </div>
    </Portal>
  );
}

/** A persistent readiness banner whose reminder can be snoozed without hiding the underlying health state. */
export function SafetyBanner(props: {
  title: string;
  description: string;
  actionLabel: string;
  onAction(): void;
  onSnooze(): void;
}): JSX.Element {
  return (
    <div class="safety-banner" role="status">
      <span class="safety-glyph" aria-hidden="true">
        <IconAlertTriangle size={18} />
      </span>
      <div class="safety-copy">
        <strong>{props.title}</strong>
        <span>{props.description}</span>
      </div>
      <div class="safety-actions">
        <Button variant="quiet" size="sm" onClick={props.onSnooze}>
          Remind me later
        </Button>
        <Button size="sm" onClick={props.onAction}>
          {props.actionLabel}
        </Button>
      </div>
    </div>
  );
}
