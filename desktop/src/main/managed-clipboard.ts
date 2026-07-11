type ClipboardPort = {
  writeText(value: string): void;
  readText(): string;
  clear(): void;
};

export class ManagedClipboard {
  readonly #clipboard: ClipboardPort;
  readonly #clearAfterMs: number;
  #value: string | null = null;
  #timer: ReturnType<typeof setTimeout> | undefined;

  constructor(clipboard: ClipboardPort, clearAfterMs = 30_000) {
    this.#clipboard = clipboard;
    this.#clearAfterMs = clearAfterMs;
  }

  write(value: string): void {
    this.#clipboard.writeText(value);
    this.#value = value;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = setTimeout(() => this.clear(), this.#clearAfterMs);
  }

  clear(): void {
    const value = this.#value;
    this.#value = null;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = undefined;
    if (value !== null && this.#clipboard.readText() === value) this.#clipboard.clear();
  }
}
