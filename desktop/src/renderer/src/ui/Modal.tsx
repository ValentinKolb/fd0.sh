import { Show, createSignal, createUniqueId, onCleanup, onMount, type JSX } from "solid-js";
import { Portal } from "solid-js/web";
import { IconX } from "@tabler/icons-solidjs";
import { IconButton } from "./Button";
import { isTopOverlay, popOverlay, pushOverlay } from "./overlayStack";

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

export type ModalProps = {
  title: string;
  description?: string;
  size?: "small" | "default" | "wide" | "full";
  /**
   * When true, closing via Escape or backdrop asks for confirmation first.
   * Prevents silent loss of a half-filled form.
   */
  dirty?: boolean;
  onClose(): void;
  footer?: JSX.Element;
  headerActions?: JSX.Element;
  children: JSX.Element;
};

export function Modal(props: ModalProps): JSX.Element {
  const titleID = createUniqueId();
  const descriptionID = createUniqueId();
  const [confirmingClose, setConfirmingClose] = createSignal(false);
  let token: symbol | undefined;
  let panel: HTMLElement | undefined;
  let previouslyFocused: HTMLElement | null = null;

  function requestClose(): void {
    if (props.dirty) {
      setConfirmingClose(true);
      return;
    }
    props.onClose();
  }

  onMount(() => {
    token = pushOverlay();
    previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;

    // Focus the first meaningful control, not the close button.
    queueMicrotask(() => {
      if (!panel) return;
      const candidates = [...panel.querySelectorAll<HTMLElement>(FOCUSABLE)];
      const preferred = candidates.find((node) => !node.hasAttribute("data-modal-dismiss")) ?? candidates[0];
      preferred?.focus();
    });

    const onKeyDown = (event: KeyboardEvent) => {
      if (!token || !isTopOverlay(token)) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        if (confirmingClose()) setConfirmingClose(false);
        else requestClose();
        return;
      }
      if (event.key !== "Tab" || !panel) return;
      const focusable = [...panel.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
        (node) => node.offsetParent !== null || node === document.activeElement,
      );
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !panel.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown, true);
    onCleanup(() => {
      document.removeEventListener("keydown", onKeyDown, true);
      if (token) popOverlay(token);
      previouslyFocused?.focus();
    });
  });

  return (
    <Portal>
      <div
        class="modal-backdrop"
        role="presentation"
        onPointerDown={(event) => {
          if (event.target !== event.currentTarget) return;
          if (!token || !isTopOverlay(token)) return;
          requestClose();
        }}
      >
        <section
          ref={panel}
          classList={{ modal: true, [`modal-${props.size ?? "default"}`]: true }}
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleID}
          aria-describedby={props.description ? descriptionID : undefined}
        >
          <header class="modal-header">
            <div class="modal-heading">
              <h1 id={titleID}>{props.title}</h1>
              <Show when={props.description}>
                <p id={descriptionID}>{props.description}</p>
              </Show>
            </div>
            <div class="modal-header-actions">
              {props.headerActions}
              <IconButton label="Close" data-modal-dismiss onClick={requestClose}>
                <IconX size={18} />
              </IconButton>
            </div>
          </header>
          <div class="modal-body">{props.children}</div>
          <Show when={props.footer}>
            <footer class="modal-footer">{props.footer}</footer>
          </Show>

          <Show when={confirmingClose()}>
            <div class="modal-confirm" role="alertdialog" aria-label="Discard changes?">
              <div class="modal-confirm-panel">
                <strong>Discard your changes?</strong>
                <p>This form has unsaved changes. Closing now loses them.</p>
                <div class="modal-confirm-actions">
                  <button class="button" type="button" onClick={() => setConfirmingClose(false)}>
                    Keep editing
                  </button>
                  <button class="button button-danger" type="button" onClick={() => props.onClose()}>
                    Discard
                  </button>
                </div>
              </div>
            </div>
          </Show>
        </section>
      </div>
    </Portal>
  );
}
