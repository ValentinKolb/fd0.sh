import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { IconRefresh } from "@tabler/icons-solidjs";
import "@xterm/xterm/css/xterm.css";
import { Show, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import type { TerminalExit, TerminalTheme } from "../../../shared/contracts";
import { cleanTerminalTitle, resolveTerminalTheme } from "../lib/terminal";

const darkTheme: ITheme = {
  background: "#0b0e0c",
  foreground: "#e7ebe8",
  cursor: "#ffad0a",
  cursorAccent: "#0b0e0c",
  selectionBackground: "#ffad0a40",
  selectionInactiveBackground: "#8d969044",
  scrollbarSliderBackground: "#69736c66",
  scrollbarSliderHoverBackground: "#89938c88",
  black: "#101411",
  red: "#ff6961",
  green: "#7dcc75",
  yellow: "#ffbd35",
  blue: "#74a7ff",
  magenta: "#c993ff",
  cyan: "#67c8c2",
  white: "#e7ebe8",
  brightBlack: "#748078",
  brightRed: "#ff8d87",
  brightGreen: "#9be493",
  brightYellow: "#ffd16d",
  brightBlue: "#9bc0ff",
  brightMagenta: "#ddb7ff",
  brightCyan: "#8ce0db",
  brightWhite: "#ffffff",
};

const lightTheme: ITheme = {
  background: "#f7f8f6",
  foreground: "#17201b",
  cursor: "#b66d00",
  cursorAccent: "#f7f8f6",
  selectionBackground: "#ffad0a42",
  selectionInactiveBackground: "#6470692f",
  scrollbarSliderBackground: "#64706955",
  scrollbarSliderHoverBackground: "#4f5a5480",
  black: "#202722",
  red: "#b52f2a",
  green: "#397a36",
  yellow: "#946000",
  blue: "#315fa8",
  magenta: "#7d47a5",
  cyan: "#24756f",
  white: "#e8ebe8",
  brightBlack: "#667169",
  brightRed: "#d94b44",
  brightGreen: "#4f9650",
  brightYellow: "#b67a00",
  brightBlue: "#4779c6",
  brightMagenta: "#9962c2",
  brightCyan: "#338d86",
  brightWhite: "#ffffff",
};

function exitLabel(result: TerminalExit): string {
  if (result.signal) return `Closed by signal ${result.signal}`;
  return result.exitCode === 0 ? "Session closed" : `Session closed · exit ${result.exitCode}`;
}

export function TerminalWindow(): JSX.Element {
  let container!: HTMLDivElement;
  let terminal: Terminal | undefined;
  let fit: FitAddon | undefined;
  let resizeObserver: ResizeObserver | undefined;
  let fitFrame = 0;
  const [host, setHost] = createSignal("SSH host");
  const [processName, setProcessName] = createSignal("ssh");
  const [remoteTitle, setRemoteTitle] = createSignal("");
  const [theme, setTheme] = createSignal<TerminalTheme>("system");
  const [exit, setExit] = createSignal<TerminalExit | null>(null);
  const [error, setError] = createSignal("");
  const [ready, setReady] = createSignal(false);
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  const disposers: Array<() => void> = [];

  function secondaryLabel(): string {
    const label = remoteTitle() || processName();
    return label.localeCompare(host(), undefined, { sensitivity: "accent" }) === 0 ? "" : label;
  }

  function applyTheme(): void {
    const resolved = resolveTerminalTheme(theme(), systemTheme.matches);
    document.documentElement.dataset.theme = resolved;
    document.documentElement.style.colorScheme = resolved;
    if (terminal) terminal.options.theme = resolved === "dark" ? darkTheme : lightTheme;
  }

  function scheduleFit(): void {
    cancelAnimationFrame(fitFrame);
    fitFrame = requestAnimationFrame(() => {
      if (!terminal || !fit || !container.isConnected) return;
      fit.fit();
    });
  }

  async function startSession(): Promise<void> {
    if (!terminal || !fit) return;
    setError("");
    setExit(null);
    setRemoteTitle("");
    window.fd0.setTerminalTitle("");
    fit.fit();
    try {
      await window.fd0.startTerminal(terminal.cols, terminal.rows);
      terminal.focus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "fd0 could not start this SSH session.");
    }
  }

  function retrySession(): void {
    if (terminal && fit) {
      void startSession();
      return;
    }
    window.location.reload();
  }

  onMount(() => {
    const initialise = async (): Promise<void> => {
      try {
        const info = await window.fd0.terminalSession();
        setHost(info.host);
        setTheme(info.terminalTheme);
        applyTheme();

        terminal = new Terminal({
          allowProposedApi: false,
          convertEol: false,
          cursorBlink: true,
          cursorStyle: "block",
          fontFamily: '"Geist Mono Variable", "SFMono-Regular", Consolas, monospace',
          fontSize: 14,
          fontWeight: 450,
          letterSpacing: 0,
          lineHeight: 1.16,
          scrollback: 10_000,
          theme: resolveTerminalTheme(theme(), systemTheme.matches) === "dark" ? darkTheme : lightTheme,
        });
        fit = new FitAddon();
        terminal.loadAddon(fit);
        terminal.open(container);

        disposers.push(
          window.fd0.onTerminalData((data) => terminal?.write(data)),
          window.fd0.onTerminalExit((result) => {
            setExit(result);
            terminal?.write(`\r\n\x1b[2m${exitLabel(result)}\x1b[0m\r\n`);
          }),
          window.fd0.onTerminalProcess(setProcessName),
          window.fd0.onTerminalTheme((next) => {
            setTheme(next);
            applyTheme();
          }),
        );
        terminal.onData((data) => window.fd0.writeTerminal(data));
        terminal.onResize(({ cols, rows }) => window.fd0.resizeTerminal(cols, rows));
        terminal.onTitleChange((value) => {
          const title = cleanTerminalTitle(value);
          setRemoteTitle(title);
          window.fd0.setTerminalTitle(title);
        });
        terminal.attachCustomKeyEventHandler((event) => {
          const primary = window.fd0.platform === "darwin" ? event.metaKey : event.ctrlKey;
          if (!primary) return true;
          if (event.key.toLowerCase() === "c" && terminal?.hasSelection()) {
            void window.fd0.copyTerminalSelection(terminal.getSelection());
            return false;
          }
          if (event.key.toLowerCase() === "v") {
            void window.fd0.pasteTerminal();
            return false;
          }
          return true;
        });
        resizeObserver = new ResizeObserver(scheduleFit);
        resizeObserver.observe(container);
        setReady(true);
        scheduleFit();
        await startSession();
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "fd0 could not prepare this terminal.");
      }
    };

    const onSystemTheme = (): void => {
      if (theme() === "system") applyTheme();
    };
    systemTheme.addEventListener("change", onSystemTheme);
    disposers.push(() => systemTheme.removeEventListener("change", onSystemTheme));
    void initialise();
  });

  onCleanup(() => {
    cancelAnimationFrame(fitFrame);
    resizeObserver?.disconnect();
    for (const dispose of disposers) dispose();
    terminal?.dispose();
  });

  return (
    <main class={`terminal-window ${window.fd0.platform === "darwin" ? "is-mac" : ""}`}>
      <header class="terminal-window-header">
        <span class={`terminal-status ${exit() || error() ? "is-closed" : "is-open"}`} aria-hidden="true" />
        <div class="terminal-identity">
          <strong>{host()}</strong>
          <Show when={secondaryLabel()}>{(label) => <span>{label()}</span>}</Show>
        </div>
        <Show when={exit() || error()}>
          <button class="terminal-reconnect" type="button" onClick={() => void startSession()}>
            <IconRefresh size={14} aria-hidden="true" />
            Reconnect
          </button>
        </Show>
      </header>
      <section class="terminal-stage" aria-label={`SSH terminal for ${host()}`}>
        <div ref={container} class="terminal-surface" />
        <Show when={!ready() && !error()}>
          <div class="terminal-overlay">Connecting to {host()}…</div>
        </Show>
        <Show when={error()}>
          <div class="terminal-overlay is-error">
            <strong>Could not open {host()}</strong>
            <span>{error()}</span>
            <button type="button" onClick={retrySession}>Try again</button>
          </div>
        </Show>
      </section>
    </main>
  );
}
