import { Show, createEffect, createMemo, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import { IconCopy, IconRefresh } from "@tabler/icons-solidjs";
import { password } from "@valentinkolb/stdlib";
import { errorText } from "../errors";
import { IconButton, SelectControl } from "./Controls";

type GeneratorMode = "random" | "memorable" | "pin";

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

  const regenerate = () => {
    switch (mode()) {
      case "memorable":
        setValue(password.memorable({
          words: words(),
          separator: separator(),
          capitalize: capitalize(),
          fullWords: true,
          addNumber: addNumber(),
          addSymbol: addSymbol(),
        }));
        break;
      case "pin":
        setValue(password.pin({ length: pinLength() }));
        break;
      default:
        setValue(password.random({
          length: length(),
          uppercase: uppercase(),
          numbers: numbers(),
          symbols: symbols(),
        }));
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

function GeneratorModePicker(props: { generator: GeneratorState }): JSX.Element {
  const generator = props.generator;
  return (
    <div class="generator-mode" role="radiogroup" aria-label="Generator type">
      <button classList={{ active: generator.mode() === "random" }} type="button" role="radio" aria-checked={generator.mode() === "random"} onClick={() => generator.setMode("random")}>Password</button>
      <button classList={{ active: generator.mode() === "memorable" }} type="button" role="radio" aria-checked={generator.mode() === "memorable"} onClick={() => generator.setMode("memorable")}>Memorable</button>
      <button classList={{ active: generator.mode() === "pin" }} type="button" role="radio" aria-checked={generator.mode() === "pin"} onClick={() => generator.setMode("pin")}>PIN</button>
    </div>
  );
}

function GeneratorOptions(props: { generator: GeneratorState }): JSX.Element {
  const generator = props.generator;
  return (
    <div class="generator-controls">
      <Show when={generator.mode() === "random"}>
        <label><span>Length</span><input aria-label="Length" type="range" min="12" max="64" value={generator.length()} onInput={(event) => generator.setLength(Number(event.currentTarget.value))} /><output>{generator.length()}</output></label>
        <label class="toggle"><span>Uppercase</span><input type="checkbox" checked={generator.uppercase()} onChange={(event) => generator.setUppercase(event.currentTarget.checked)} /></label>
        <label class="toggle"><span>Numbers</span><input type="checkbox" checked={generator.numbers()} onChange={(event) => generator.setNumbers(event.currentTarget.checked)} /></label>
        <label class="toggle"><span>Symbols</span><input type="checkbox" checked={generator.symbols()} onChange={(event) => generator.setSymbols(event.currentTarget.checked)} /></label>
      </Show>
      <Show when={generator.mode() === "memorable"}>
        <label><span>Words</span><input aria-label="Words" type="range" min="3" max="10" value={generator.words()} onInput={(event) => generator.setWords(Number(event.currentTarget.value))} /><output>{generator.words()}</output></label>
        <label><span>Separator</span><SelectControl aria-label="Separator" value={generator.separator()} onChange={(event) => generator.setSeparator(event.currentTarget.value)}><option value="-">Hyphen</option><option value=" ">Space</option><option value=".">Period</option><option value="_">Underscore</option></SelectControl></label>
        <label class="toggle"><span>Capitalize words</span><input type="checkbox" checked={generator.capitalize()} onChange={(event) => generator.setCapitalize(event.currentTarget.checked)} /></label>
        <label class="toggle"><span>Add number</span><input type="checkbox" checked={generator.addNumber()} onChange={(event) => generator.setAddNumber(event.currentTarget.checked)} /></label>
        <label class="toggle"><span>Add symbol</span><input type="checkbox" checked={generator.addSymbol()} onChange={(event) => generator.setAddSymbol(event.currentTarget.checked)} /></label>
      </Show>
      <Show when={generator.mode() === "pin"}>
        <label><span>Digits</span><input aria-label="Digits" type="range" min="4" max="12" value={generator.pinLength()} onInput={(event) => generator.setPINLength(Number(event.currentTarget.value))} /><output>{generator.pinLength()}</output></label>
      </Show>
    </div>
  );
}

export function PasswordGeneratorPanel(props: { onNotify(message: string): void; onError(message: string): void }): JSX.Element {
  const generator = createPasswordGenerator();
  return (
    <section class="workspace-panel generator-panel">
      <header><h1>Password generator</h1><p>Create a strong password without storing it.</p></header>
      <GeneratorModePicker generator={generator} />
      <div class="generated-value">
        <code>{generator.value()}</code>
        <IconButton
          label="Copy generated value"
          onClick={() => void window.fd0.copyText(generator.value()).then(() => props.onNotify("Generated value copied. Clipboard clears in 30 seconds.")).catch((error) => props.onError(errorText(error)))}
        ><IconCopy size={18} /></IconButton>
        <IconButton label="Generate another value" onClick={generator.regenerate}><IconRefresh size={18} /></IconButton>
      </div>
      <Show when={generator.mode() !== "pin"}>
        <div class="strength-line"><span class={`score-${generator.strength().score}`} /><strong>{generator.strength().label}</strong><small>{generator.strength().crackTime}</small></div>
      </Show>
      <GeneratorOptions generator={generator} />
    </section>
  );
}

export function PasswordGeneratorPopover(props: { onUse(value: string): void; onClose(): void; inline?: boolean }): JSX.Element {
  const generator = createPasswordGenerator();

  onMount(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && props.onClose();
    document.addEventListener("keydown", close);
    onCleanup(() => document.removeEventListener("keydown", close));
  });

  return (
    <div classList={{ "password-generator-popover": true, inline: Boolean(props.inline) }} role={props.inline ? "group" : "dialog"} aria-label="Password generator options" onPointerDown={(event) => event.stopPropagation()}>
      <div class="generator-preview">
        <code>{generator.value()}</code>
        <IconButton label="Generate another value" onClick={generator.regenerate}><IconRefresh size={17} /></IconButton>
      </div>
      <Show when={generator.mode() !== "pin"}>
        <div class="generator-popover-strength"><span class={`score-${generator.strength().score}`} /><small>{generator.strength().label}</small></div>
      </Show>
      <GeneratorModePicker generator={generator} />
      <GeneratorOptions generator={generator} />
      <footer>
        <button class="secondary-button" type="button" onClick={props.onClose}>Cancel</button>
        <button class="primary-button" type="button" onClick={() => props.onUse(generator.value())}>Use</button>
      </footer>
    </div>
  );
}
