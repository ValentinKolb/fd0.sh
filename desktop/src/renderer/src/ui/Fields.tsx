import { For, Show, createMemo, createSignal, createUniqueId, splitProps, type JSX } from "solid-js";
import { IconCheck, IconChevronDown, IconEye, IconEyeOff } from "@tabler/icons-solidjs";
import { Popover } from "./Popover";
import { password } from "@valentinkolb/stdlib";
import { IconButton } from "./Button";

type FieldShellProps = {
  label: string;
  hint?: string;
  /** Rendered in danger styling below the control and announced to assistive tech. */
  error?: string;
  /** Rendered in success styling. Used for live confirmation, e.g. "Passphrases match". */
  success?: string;
  optional?: boolean;
  children(props: FieldRenderProps): JSX.Element;
};

/**
 * Values handed to a Field's child.
 *
 * Every one of these is CONSTANT for the life of the field. They used to be
 * derived reactively (`describedBy` flipped between undefined and an id as a
 * hint turned into an error), which made Solid re-run the child function and
 * rebuild the <input> mid-typing — dropping and duplicating keystrokes in
 * exactly the fields that show live validation.
 */
export type FieldRenderProps = {
  id: string;
  describedBy: string;
};

/** Label + control + one message slot. Every form control in the app uses this. */
export function Field(props: FieldShellProps): JSX.Element {
  const id = createUniqueId();
  const messageID = createUniqueId();
  const message = () => props.error ?? props.success ?? props.hint;
  return (
    <div class="field">
      <label class="field-label" for={id}>
        <span>{props.label}</span>
        <Show when={props.optional}>
          {/* A separate node with its own gap; concatenated text would read
              as "Notesoptional" to anything reading the label directly. */}
          <span class="field-optional">optional</span>
        </Show>
      </label>
      {props.children({ id, describedBy: messageID })}
      <Show when={message()}>
        <p
          id={messageID}
          classList={{ "field-message": true, "is-error": Boolean(props.error), "is-success": Boolean(props.success && !props.error) }}
          role={props.error ? "alert" : undefined}
        >
          {message()}
        </p>
      </Show>
    </div>
  );
}

type InputProps = JSX.InputHTMLAttributes<HTMLInputElement>;

export function Input(props: InputProps): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <input {...rest} classList={{ input: true, [local.class ?? ""]: Boolean(local.class) }} />;
}

export function Textarea(props: JSX.TextareaHTMLAttributes<HTMLTextAreaElement>): JSX.Element {
  const [local, rest] = splitProps(props, ["class"]);
  return <textarea {...rest} classList={{ input: true, textarea: true, [local.class ?? ""]: Boolean(local.class) }} />;
}

export type SelectOption = {
  value: string;
  label: string;
  /** Secondary text shown in the list, never in the trigger. */
  hint?: string;
};

type SelectProps = {
  value: string;
  options: SelectOption[];
  onChange(value: string): void;
  id?: string;
  /** Accessible name when no visible <label> points at this control. */
  label?: string;
  "aria-describedby"?: string;
  disabled?: boolean;
  class?: string;
  /** Shown when `value` matches no option. */
  placeholder?: string;
};

/**
 * A select that renders its own list.
 *
 * A real `<select>` cannot be styled past the trigger: macOS draws the popup
 * itself, so the app's surfaces, radii and focus ring stop at the edge of the
 * menu. This keeps the same keyboard contract (typeahead, Home/End, arrows,
 * Escape) and portals the list so it is never clipped.
 */
export function Select(props: SelectProps): JSX.Element {
  const [open, setOpen] = createSignal(false);
  const [trigger, setTrigger] = createSignal<HTMLButtonElement>();
  const [activeIndex, setActiveIndex] = createSignal(0);
  const listID = createUniqueId();
  let typeahead = "";
  let typeaheadTimer: ReturnType<typeof setTimeout> | undefined;

  const selectedIndex = createMemo(() => props.options.findIndex((option) => option.value === props.value));
  const selected = createMemo(() => props.options[selectedIndex()]);

  function commit(index: number): void {
    const option = props.options[index];
    if (!option) return;
    props.onChange(option.value);
    setOpen(false);
    trigger()?.focus();
  }

  function openList(): void {
    setActiveIndex(Math.max(0, selectedIndex()));
    setOpen(true);
  }

  function move(delta: number): void {
    if (props.options.length === 0) return;
    setActiveIndex((current) => {
      const next = current + delta;
      if (next < 0) return props.options.length - 1;
      if (next >= props.options.length) return 0;
      return next;
    });
  }

  function onTypeahead(key: string): void {
    typeahead += key.toLowerCase();
    if (typeaheadTimer) clearTimeout(typeaheadTimer);
    typeaheadTimer = setTimeout(() => {
      typeahead = "";
    }, 600);
    const index = props.options.findIndex((option) => option.label.toLowerCase().startsWith(typeahead));
    if (index >= 0) setActiveIndex(index);
  }

  function onKeyDown(event: KeyboardEvent): void {
    if (!open()) {
      if (event.key === "ArrowDown" || event.key === "ArrowUp" || event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openList();
      }
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      move(1);
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      move(-1);
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      setActiveIndex(0);
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      setActiveIndex(props.options.length - 1);
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      commit(activeIndex());
      return;
    }
    if (event.key.length === 1) onTypeahead(event.key);
  }

  return (
    <>
      <button
        ref={setTrigger}
        id={props.id}
        type="button"
        classList={{ select: true, "is-open": open(), [props.class ?? ""]: Boolean(props.class) }}
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open()}
        aria-controls={listID}
        aria-label={props.label}
        aria-describedby={props["aria-describedby"]}
        disabled={props.disabled}
        onClick={() => (open() ? setOpen(false) : openList())}
        onKeyDown={onKeyDown}
      >
        <span class="select-value">{selected()?.label ?? props.placeholder ?? ""}</span>
        <IconChevronDown size={15} aria-hidden="true" />
      </button>

      <Popover
        anchor={trigger()}
        open={open()}
        onClose={() => setOpen(false)}
        align="start"
        role="listbox"
        label={props.label}
        class="select-list"
        matchAnchorWidth
      >
        <div id={listID} aria-activedescendant={`${listID}-${activeIndex()}`}>
          <For each={props.options}>
            {(option, index) => (
              <button
                id={`${listID}-${index()}`}
                type="button"
                role="option"
                aria-selected={option.value === props.value}
                classList={{ "select-option": true, "is-active": index() === activeIndex() }}
                onPointerMove={() => setActiveIndex(index())}
                onClick={() => commit(index())}
              >
                <span class="select-option-copy">
                  <span>{option.label}</span>
                  <Show when={option.hint}>
                    <small>{option.hint}</small>
                  </Show>
                </span>
                <Show when={option.value === props.value}>
                  <IconCheck size={14} />
                </Show>
              </button>
            )}
          </For>
        </div>
      </Popover>
    </>
  );
}

type SecretInputProps = Omit<InputProps, "type"> & {
  /** Accessible name for the visibility toggle, e.g. "passphrase". */
  what?: string;
};

/** A password input with a visibility toggle that keeps its own pressed state. */
export function SecretInput(props: SecretInputProps): JSX.Element {
  const [visible, setVisible] = createSignal(false);
  const [local, rest] = splitProps(props, ["what", "class"]);
  const what = () => local.what ?? "value";
  return (
    <div class="input-with-action">
      <Input {...rest} class={local.class} type={visible() ? "text" : "password"} spellcheck={false} />
      <IconButton
        label={visible() ? `Hide ${what()}` : `Show ${what()}`}
        aria-pressed={visible()}
        size="sm"
        tabIndex={-1}
        onClick={() => setVisible((current) => !current)}
      >
        {visible() ? <IconEyeOff size={16} /> : <IconEye size={16} />}
      </IconButton>
    </div>
  );
}

/**
 * Strength meter.
 *
 * Renders nothing at all for an empty value. The previous implementation showed
 * a filled green segment on an empty field, which read as "this is already a
 * strong passphrase" before anything had been typed.
 */
export function StrengthMeter(props: { value: string; minLength?: number }): JSX.Element {
  const minLength = () => props.minLength ?? 12;
  const result = createMemo(() => (props.value ? password.strength(props.value) : null));
  const tooShort = createMemo(() => props.value.length > 0 && props.value.length < minLength());
  return (
    <div class="strength" aria-live="polite">
      <div class="strength-track">
        <div
          classList={{ "strength-fill": true, [`strength-${result()?.score ?? 0}`]: true }}
          style={{ width: `${result() ? (result()!.score + 1) * 20 : 0}%` }}
        />
      </div>
      <div class="strength-text">
        <Show
          when={result()}
          fallback={<span class="strength-hint">At least {minLength()} characters</span>}
        >
          {(strength) => (
            <>
              <span classList={{ "strength-label": true, [`strength-text-${strength().score}`]: true }}>
                {tooShort() ? `Too short — ${minLength()} characters minimum` : strength().label}
              </span>
              <Show when={!tooShort()}>
                <span class="strength-time">{strength().crackTime} to crack</span>
              </Show>
            </>
          )}
        </Show>
      </div>
      <Show when={result()?.feedback.length && !tooShort()}>
        <p class="strength-feedback">{result()!.feedback[0]}</p>
      </Show>
    </div>
  );
}

/** A labelled on/off control. One switch style for the whole app. */
export function Switch(props: {
  label: string;
  description?: string;
  checked: boolean;
  disabled?: boolean;
  onChange(value: boolean): void;
}): JSX.Element {
  return (
    <label classList={{ switch: true, "is-disabled": props.disabled }}>
      <span class="switch-copy">
        <strong>{props.label}</strong>
        <Show when={props.description}>
          <small>{props.description}</small>
        </Show>
      </span>
      <input
        type="checkbox"
        role="switch"
        class="switch-input"
        checked={props.checked}
        disabled={props.disabled}
        onChange={(event) => props.onChange(event.currentTarget.checked)}
      />
      <span class="switch-track" aria-hidden="true">
        <span class="switch-thumb" />
      </span>
    </label>
  );
}
