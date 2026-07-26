import { For, createSignal, onCleanup, onMount, type Accessor, type JSX } from "solid-js";
import { IconCopy } from "@tabler/icons-solidjs";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";

export const AUTO_CLOSE_SECONDS = 30;

/**
 * Counts down to the auto-close and fires `onElapsed` once.
 *
 * Shared so the in-window modal and the floating window cannot drift apart on
 * how long a secret stays readable.
 */
export function createAutoCloseCountdown(onElapsed: () => void): Accessor<number> {
  const [remaining, setRemaining] = createSignal(AUTO_CLOSE_SECONDS);

  onMount(() => {
    const tick = setInterval(() => {
      setRemaining((current) => {
        if (current <= 1) {
          onElapsed();
          return 0;
        }
        return current - 1;
      });
    }, 1000);
    onCleanup(() => clearInterval(tick));
  });

  return remaining;
}

/** One cell per character, with its position and digit/symbol colouring. */
export function LargeTypeGrid(props: { value: string }): JSX.Element {
  const characters = () => Array.from(props.value);
  const display = (character: string): string => {
    if (character === " ") return "␠";
    if (character === "\n") return "↵";
    if (character === "\t") return "⇥";
    return character;
  };

  return (
    <div class="large-type-grid">
      <For each={characters()}>
        {(character, index) => (
          <span
            classList={{
              "large-type-character": true,
              "is-digit": /\d/.test(character),
              "is-symbol": /[^a-z0-9]/i.test(character),
            }}
          >
            <strong>{display(character)}</strong>
            <small>{index() + 1}</small>
          </span>
        )}
      </For>
    </div>
  );
}

/**
 * Reads a secret out loud, one character at a time.
 *
 * This is the fallback surface: normally the value opens in its own always-on-top
 * window (see LargeTypeWindow), and this modal only appears when that window
 * could not be created.
 *
 * The auto-close is visible. Previously the dialog simply vanished after
 * 30 seconds with no warning, which is alarming when you are halfway through
 * typing a code into another device.
 */
export function LargeType(props: { label: string; value: string; onCopy(): void; onClose(): void }): JSX.Element {
  const remaining = createAutoCloseCountdown(() => props.onClose());

  return (
    <Modal
      title={props.label}
      description="Read this out or type it into another device."
      size="wide"
      onClose={props.onClose}
      headerActions={
        <>
          <span class="large-type-timer" aria-live="off">
            closes in {remaining()}s
          </span>
          <Button size="sm" onClick={props.onCopy}>
            <IconCopy size={15} />
            Copy
          </Button>
        </>
      }
    >
      <LargeTypeGrid value={props.value} />
    </Modal>
  );
}
