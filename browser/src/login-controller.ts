import { findLoginFields } from "./form";
import {
  mountLoginPicker,
  mountLoginPrompt,
  mountLoginTrigger,
  type LoginMatch,
  type LoginPicker,
  type LoginPrompt,
  type LoginTrigger,
} from "./picker";

export type LoginLookup = {
  origin: string;
  credentials: LoginMatch[];
};

export type LoginController = {
  open: () => Promise<boolean>;
  dispose: () => void;
};

export function installLoginController(
  document: Document,
  lookup: () => Promise<LoginLookup>,
  select: (origin: string, credentialId: string) => Promise<void>,
): LoginController {
  let cachedLookup: LoginLookup | undefined;
  let pendingLookup: Promise<LoginLookup> | undefined;
  let picker: LoginPicker | undefined;
  let prompt: LoginPrompt | undefined;
  let trigger: LoginTrigger | undefined;
  let anchor: HTMLInputElement | undefined;
  let suppressFocus: HTMLInputElement | undefined;
  let disposed = false;
  let openSequence = 0;

  async function credentials(): Promise<LoginLookup> {
    if (cachedLookup) return cachedLookup;
    pendingLookup ??= lookup();
    try {
      cachedLookup = await pendingLookup;
      return cachedLookup;
    } finally {
      pendingLookup = undefined;
    }
  }

  function loginAnchor(preferred?: EventTarget | null): HTMLInputElement | undefined {
    const fields = findLoginFields(document);
    if (!fields) return undefined;
    if (preferred === fields.username) return fields.username;
    if (preferred === fields.password) return fields.password;
    if (preferred) return undefined;
    return fields.username ?? fields.password;
  }

  function mountTrigger(nextAnchor: HTMLInputElement): void {
    if (anchor === nextAnchor && trigger?.host.isConnected) return;
    trigger?.close();
    anchor = nextAnchor;
    trigger = mountLoginTrigger(document, nextAnchor, () => {
      void openFor(nextAnchor, true);
    });
  }

  async function openFor(
    nextAnchor: HTMLInputElement,
    explicit = false,
  ): Promise<boolean> {
    const sequence = ++openSequence;
    mountTrigger(nextAnchor);
    if (explicit) trigger?.setBusy(true);
    let result: LoginLookup;
    try {
      result = await credentials();
    } catch (error) {
      if (disposed || sequence !== openSequence) return false;
      if (explicit) {
        picker?.close(false);
        picker = undefined;
        prompt?.close(false);
        const locked =
          error instanceof Error &&
          error.message.toLocaleLowerCase().includes("unlock fd0");
        prompt = mountLoginPrompt(
          document,
          nextAnchor,
          locked ? "Vault locked" : "fd0 unavailable",
          locked
            ? "Unlock fd0 in the desktop app, then try again."
            : "Open fd0 and try again.",
          () => {
            prompt = undefined;
            void openFor(nextAnchor, true);
          },
          () => {
            prompt = undefined;
            suppressFocus = nextAnchor;
          },
        );
      }
      return false;
    } finally {
      if (explicit) trigger?.setBusy(false);
    }
    if (disposed || sequence !== openSequence) {
      return false;
    }
    if (result.credentials.length === 0) {
      trigger?.close();
      trigger = undefined;
      anchor = undefined;
      return false;
    }

    prompt?.close(false);
    prompt = undefined;
    picker?.close(false);
    picker = mountLoginPicker(
      document,
      nextAnchor,
      result.credentials,
      (credentialId) => select(result.origin, credentialId),
      () => {
        picker = undefined;
        suppressFocus = nextAnchor;
      },
    );
    return true;
  }

  function onFocus(event: FocusEvent): void {
    const nextAnchor = loginAnchor(event.target);
    if (!nextAnchor) return;
    if (suppressFocus === nextAnchor) {
      suppressFocus = undefined;
      return;
    }
    void openFor(nextAnchor);
  }

  async function open(): Promise<boolean> {
    const nextAnchor = loginAnchor(document.activeElement) ?? loginAnchor();
    return nextAnchor ? openFor(nextAnchor, true) : false;
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    openSequence += 1;
    document.removeEventListener("focusin", onFocus, true);
    picker?.close(false);
    prompt?.close(false);
    trigger?.close();
  }

  document.addEventListener("focusin", onFocus, true);
  return { open, dispose };
}
