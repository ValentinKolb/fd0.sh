import { For, Show, createEffect, createMemo, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import { IconCopy, IconDeviceFloppy, IconRefresh } from "@tabler/icons-solidjs";
import { password } from "@valentinkolb/stdlib";
import { errorText } from "../lib/errors";
import { Button, IconButton } from "../ui/Button";
import { Field, Select, Switch } from "../ui/Fields";

type GeneratorMode = "random" | "memorable" | "pin";

const modes: Array<{ id: GeneratorMode; label: string; blurb: string }> = [
  { id: "random", label: "Random", blurb: "Strongest. Use where you never type it by hand." },
  { id: "memorable", label: "Memorable", blurb: "Words you can read out or type on a phone." },
  { id: "pin", label: "PIN", blurb: "Digits only, for devices and door codes." },
];

function createPasswordGenerator() {
  const [mode, setMode] = createSignal<GeneratorMode>("random");
  const [length, setLength] = createSignal(24);
  const [uppercase, setUppercase] = createSignal(true);
  const [numbers, setNumbers] = createSignal(true);
  const [symbols, setSymbols] = createSignal(true);
  const [words, setWords] = createSignal(6);
  const [separator, setSeparator] = createSignal("-");
  const [capitalize, setCapitalize] = createSignal(false);
  const [addNumber, setAddNumber] = createSignal(true);
  const [addSymbol, setAddSymbol] = createSignal(false);
  const [pinLength, setPINLength] = createSignal(6);
  const [value, setValue] = createSignal("");

  const regenerate = (): void => {
    switch (mode()) {
      case "memorable":
        setValue(
          password.memorable({
            words: words(),
            separator: separator(),
            capitalize: capitalize(),
            fullWords: true,
            addNumber: addNumber(),
            addSymbol: addSymbol(),
          }),
        );
        break;
      case "pin":
        setValue(password.pin({ length: pinLength() }));
        break;
      default:
        setValue(password.random({ length: length(), uppercase: uppercase(), numbers: numbers(), symbols: symbols() }));
    }
  };

  createEffect(regenerate);
  return {
    mode, setMode,
    length, setLength,
    uppercase, setUppercase,
    numbers, setNumbers,
    symbols, setSymbols,
    words, setWords,
    separator, setSeparator,
    capitalize, setCapitalize,
    addNumber, setAddNumber,
    addSymbol, setAddSymbol,
    pinLength, setPINLength,
    value,
    strength: createMemo(() => password.strength(value())),
    regenerate,
  };
}

type GeneratorState = ReturnType<typeof createPasswordGenerator>;

function ModePicker(props: { generator: GeneratorState }): JSX.Element {
  return (
    <div class="segmented" role="radiogroup" aria-label="Generator type">
      <For each={modes}>
        {(mode) => (
          <button
            type="button"
            role="radio"
            aria-checked={props.generator.mode() === mode.id}
            classList={{ "is-active": props.generator.mode() === mode.id }}
            onClick={() => props.generator.setMode(mode.id)}
          >
            {mode.label}
          </button>
        )}
      </For>
    </div>
  );
}

function GeneratorOptions(props: { generator: GeneratorState }): JSX.Element {
  const generator = props.generator;
  return (
    <div class="generator-options">
      <Show when={generator.mode() === "random"}>
        <div class="slider-row">
          <label for="generator-length">Length</label>
          <input
            id="generator-length"
            type="range"
            min="12"
            max="64"
            value={generator.length()}
            onInput={(event) => generator.setLength(Number(event.currentTarget.value))}
          />
          <output for="generator-length">{generator.length()}</output>
        </div>
        <Switch label="Uppercase letters" checked={generator.uppercase()} onChange={generator.setUppercase} />
        <Switch label="Numbers" checked={generator.numbers()} onChange={generator.setNumbers} />
        <Switch label="Symbols" checked={generator.symbols()} onChange={generator.setSymbols} />
      </Show>

      <Show when={generator.mode() === "memorable"}>
        <div class="slider-row">
          <label for="generator-words">Words</label>
          <input
            id="generator-words"
            type="range"
            min="3"
            max="10"
            value={generator.words()}
            onInput={(event) => generator.setWords(Number(event.currentTarget.value))}
          />
          <output for="generator-words">{generator.words()}</output>
        </div>
        <Field label="Separator">
          {(field) => (
            <Select
              id={field.id}
              label="Separator"
              value={generator.separator()}
              onChange={generator.setSeparator}
              options={[
                { value: "-", label: "Hyphen" },
                { value: " ", label: "Space" },
                { value: ".", label: "Period" },
                { value: "_", label: "Underscore" },
              ]}
            />
          )}
        </Field>
        <Switch label="Capitalise words" checked={generator.capitalize()} onChange={generator.setCapitalize} />
        <Switch label="Add a number" checked={generator.addNumber()} onChange={generator.setAddNumber} />
        <Switch label="Add a symbol" checked={generator.addSymbol()} onChange={generator.setAddSymbol} />
      </Show>

      <Show when={generator.mode() === "pin"}>
        <div class="slider-row">
          <label for="generator-digits">Digits</label>
          <input
            id="generator-digits"
            type="range"
            min="4"
            max="12"
            value={generator.pinLength()}
            onInput={(event) => generator.setPINLength(Number(event.currentTarget.value))}
          />
          <output for="generator-digits">{generator.pinLength()}</output>
        </div>
      </Show>
    </div>
  );
}

function GeneratedValue(props: { generator: GeneratorState; compact?: boolean }): JSX.Element {
  return (
    <div classList={{ "generated-value": true, "is-compact": props.compact }}>
      <code>{props.generator.value()}</code>
      <IconButton label="Generate another value" size={props.compact ? "sm" : "md"} onClick={props.generator.regenerate}>
        <IconRefresh size={props.compact ? 15 : 17} />
      </IconButton>
    </div>
  );
}

function StrengthLine(props: { generator: GeneratorState }): JSX.Element {
  const strength = () => props.generator.strength();
  return (
    <div class="strength">
      <div class="strength-track">
        <div classList={{ "strength-fill": true, [`strength-${strength().score}`]: true }} style={{ width: `${(strength().score + 1) * 20}%` }} />
      </div>
      <div class="strength-text">
        <span classList={{ "strength-label": true, [`strength-text-${strength().score}`]: true }}>{strength().label}</span>
        <span class="strength-time">{strength().crackTime} to crack</span>
      </div>
    </div>
  );
}

export function PasswordGeneratorPanel(props: {
  onNotify(message: string, countdownSeconds?: number): void;
  onError(message: string): void;
  onSaveAsItem(value: string): void;
}): JSX.Element {
  const generator = createPasswordGenerator();

  return (
    <section class="panel generator-panel">
      <header class="panel-header">
        <h1>Password generator</h1>
        <p>Create a strong password. Nothing is stored until you save it.</p>
      </header>
      <div class="panel-column">
        <ModePicker generator={generator} />
        <p class="inline-note">{modes.find((mode) => mode.id === generator.mode())?.blurb}</p>

        <GeneratedValue generator={generator} />
        <Show when={generator.mode() !== "pin"}>
          <StrengthLine generator={generator} />
        </Show>

        <div class="generator-actions">
          <Button
            variant="primary"
            onClick={() => {
              void window.fd0
                .copyText(generator.value())
                .then((result) => props.onNotify("Password copied — clears in", result.clearAfterSeconds))
                .catch((error) => props.onError(errorText(error)));
            }}
          >
            <IconCopy size={15} />
            Copy
          </Button>
          {/* Previously the generator was a dead end: you could copy a value but
              never keep it. Saving is the obvious next step after generating. */}
          <Button onClick={() => props.onSaveAsItem(generator.value())}>
            <IconDeviceFloppy size={15} />
            Save as a new item
          </Button>
        </div>

        <GeneratorOptions generator={generator} />
      </div>
    </section>
  );
}

export function PasswordGeneratorPopover(props: { onUse(value: string): void; onClose(): void; inline?: boolean }): JSX.Element {
  const generator = createPasswordGenerator();

  onMount(() => {
    const close = (event: KeyboardEvent): void => {
      if (event.key !== "Escape") return;
      event.stopPropagation();
      props.onClose();
    };
    document.addEventListener("keydown", close);
    onCleanup(() => document.removeEventListener("keydown", close));
  });

  return (
    <div
      classList={{ "generator-popover": true, inline: Boolean(props.inline) }}
      role={props.inline ? "group" : "dialog"}
      aria-label="Password generator"
      onPointerDown={(event) => event.stopPropagation()}
    >
      <GeneratedValue generator={generator} compact />
      {/* Always rendered, hidden for PIN: removing it would change the
          popover's height when the mode changes. */}
      <div classList={{ "generator-strength-slot": true, "is-hidden": generator.mode() === "pin" }} aria-hidden={generator.mode() === "pin"}>
        <StrengthLine generator={generator} />
      </div>
      <ModePicker generator={generator} />
      <GeneratorOptions generator={generator} />
      <footer class="generator-popover-footer">
        <Button size="sm" onClick={props.onClose}>Cancel</Button>
        <Button size="sm" variant="primary" onClick={() => props.onUse(generator.value())}>Use this</Button>
      </footer>
    </div>
  );
}
