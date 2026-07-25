import { Show, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import { IconCopy, IconX } from "@tabler/icons-solidjs";
import { Button, IconButton } from "../ui/Button";
import { LargeTypeGrid, createAutoCloseCountdown } from "./LargeType";

/**
 * The entire document of the always-on-top large-type window.
 *
 * The value is never in this window's URL, its storage, or its bundle: the
 * window asks the main process for it once over IPC, and the main process only
 * answers this window. Closing it drops the value in main as well, so nothing
 * survives the 30-second window.
 */
export function LargeTypeWindow(): JSX.Element {
  const [label, setLabel] = createSignal("");
  const [value, setValue] = createSignal("");
  const [copied, setCopied] = createSignal(false);
  const [unavailable, setUnavailable] = createSignal(false);
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  const close = (): void => {
    void window.fd0.closeLargeType().catch(() => undefined);
  };

  const remaining = createAutoCloseCountdown(close);

  onMount(() => {
    void window.fd0
      .largeTypeValue()
      .then((payload) => {
        if (!payload) {
          setUnavailable(true);
          return;
        }
        setLabel(payload.label);
        setValue(payload.value);
      })
      .catch(() => setUnavailable(true));

    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      close();
    };
    document.addEventListener("keydown", onKeyDown);

    onCleanup(() => {
      document.removeEventListener("keydown", onKeyDown);
      clearTimeout(copyTimer);
    });
  });

  function copy(): void {
    void window.fd0
      .copyLargeType()
      .then(() => {
        setCopied(true);
        clearTimeout(copyTimer);
        copyTimer = setTimeout(() => setCopied(false), 2000);
      })
      .catch(() => setCopied(false));
  }

  return (
    <div class="large-type-window">
      <header class="large-type-window-bar">
        <div class="large-type-window-heading">
          <h1>{label() || "Large type"}</h1>
          <p>Read this out or type it into another device.</p>
        </div>
        <div class="large-type-window-actions">
          <span class="large-type-timer" aria-live="off">
            closes in {remaining()}s
          </span>
          <Button size="sm" onClick={copy} disabled={unavailable()}>
            <IconCopy size={15} />
            {copied() ? "Copied" : "Copy"}
          </Button>
          <IconButton label="Close" onClick={close}>
            <IconX size={18} />
          </IconButton>
        </div>
      </header>

      <div class="large-type-window-body">
        <Show
          when={!unavailable()}
          fallback={<p class="large-type-window-empty">That value is no longer available.</p>}
        >
          <LargeTypeGrid value={value()} />
        </Show>
      </div>
    </div>
  );
}
