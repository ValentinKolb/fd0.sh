import {
  fillGeneratedPassword,
  fillLogin,
  fillOTP,
  findCredentialFields,
  readLoginCandidate,
} from "./form";
import {
  mountCredentialActionPanel,
  type ActionLoginMatch,
  type CredentialActionPanel,
  type VaultChoice,
} from "./action-panel";
import type { LoginCandidate } from "./form";
import {
  installLoginController,
  type LoginController,
  type LoginLookup,
} from "./login-controller";
import { mountLoginNotice, type LoginNotice } from "./picker";

type NativeError = { code: string; message: string };
type Response<T = unknown> = { ok: boolean; result?: T; error?: NativeError };
type FillRequest = {
  type: "fd0.fill";
  selectionId: string;
  credential: { username?: string; password: string; hasTotp?: boolean };
};
type OpenPickerRequest = { type: "fd0.openPicker" };
type ShowNoticeRequest = {
  type: "fd0.showNotice";
  message: string;
  tone?: "neutral" | "error";
};
type PingRequest = { type: "fd0.ping" };
type FD0ContentGlobal = typeof globalThis & {
  __fd0LoginController?: LoginController;
  __fd0LoginNotice?: LoginNotice;
  __fd0ActionPanel?: CredentialActionPanel;
  __fd0OTPObserver?: MutationObserver;
  __fd0Dispose?: () => void;
};

const contentGlobal = globalThis as FD0ContentGlobal;
document.dispatchEvent(new CustomEvent("fd0:dispose-content-context"));
disposeContentContext();
for (const element of document.querySelectorAll<HTMLElement>(
  [
    "[data-fd0-login-trigger]",
    "[data-fd0-login-prompt]",
    "[data-fd0-login-picker]",
    "[data-fd0-login-notice]",
    "[data-fd0-credential-actions]",
  ].join(","),
)) {
  element.remove();
}

let recentLogin:
  | { origin: string; credentialId: string; expiresAt: number }
  | undefined;
const pendingFillAnchors = new Map<string, HTMLInputElement>();
let otpRequest: Promise<boolean> | undefined;
let otpRetryTimer: number | undefined;
let otpMutationTimer: number | undefined;
const lifecycle = new AbortController();

async function send<T>(message: Record<string, unknown>): Promise<T> {
  let response: Response<T>;
  try {
    response = await chrome.runtime.sendMessage<Response<T>>(message);
  } catch (error) {
    if (!isInvalidatedContext(error)) throw error;
    disposeContentContext();
    const unavailable = new Error(
      "fd0 was updated. Click its Chrome toolbar icon to reconnect.",
    ) as Error & { code?: string };
    unavailable.code = "extension_reloaded";
    throw unavailable;
  }
  if (!response?.ok || response.result === undefined) {
    const error = new Error(response?.error?.message || "fd0 could not complete this action.") as Error & {
      code?: string;
    };
    error.code = response?.error?.code;
    throw error;
  }
  return response.result;
}

function disposeContentContext(): void {
  contentGlobal.__fd0Dispose?.();
  contentGlobal.__fd0LoginController?.dispose();
  contentGlobal.__fd0LoginNotice?.close();
  contentGlobal.__fd0ActionPanel?.close();
  contentGlobal.__fd0OTPObserver?.disconnect();
}

function dispose(): void {
  lifecycle.abort();
  contentGlobal.__fd0LoginController?.dispose();
  contentGlobal.__fd0LoginNotice?.close();
  contentGlobal.__fd0ActionPanel?.close();
  contentGlobal.__fd0OTPObserver?.disconnect();
  if (otpRetryTimer !== undefined) clearTimeout(otpRetryTimer);
  if (otpMutationTimer !== undefined) clearTimeout(otpMutationTimer);
  try {
    chrome.runtime.onMessage.removeListener(onRuntimeMessage);
  } catch {
    // The previous extension context may already be invalidated.
  }
  if (contentGlobal.__fd0Dispose === dispose) {
    delete contentGlobal.__fd0Dispose;
  }
}

contentGlobal.__fd0Dispose = dispose;
document.addEventListener("fd0:dispose-content-context", dispose, {
  signal: lifecycle.signal,
});

function isInvalidatedContext(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.message.toLocaleLowerCase().includes("extension context invalidated")
  );
}

async function lookup(): Promise<LoginLookup> {
  return send<LoginLookup>({ type: "fd0.requestMatches" });
}

async function select(
  origin: string,
  credentialId: string,
  anchor: HTMLInputElement,
): Promise<void> {
  const selectionId = crypto.randomUUID();
  pendingFillAnchors.set(selectionId, anchor);
  const result = await send<{ hasTotp?: boolean }>({
    type: "fd0.selectCredential",
    origin,
    credentialId,
    selectionId,
  }).finally(() => {
    pendingFillAnchors.delete(selectionId);
  });
  recentLogin = undefined;
  contentGlobal.__fd0OTPObserver?.disconnect();
  if (result.hasTotp) {
    recentLogin = {
      origin,
      credentialId,
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
    watchForOTP();
  }
}

async function openTools(
  anchor: HTMLElement,
  currentLookup: LoginLookup,
  candidateOverride?: LoginCandidate,
): Promise<void> {
  contentGlobal.__fd0ActionPanel?.close();
  let scopes: VaultChoice[];
  try {
    const result = await send<{ scopes: VaultChoice[] }>({ type: "fd0.requestScopes" });
    scopes = result.scopes;
  } catch (error) {
    showNotice(messageOf(error), "error");
    return;
  }
  const matches = currentLookup.credentials.filter(
    (match): match is ActionLoginMatch =>
      typeof match.revision === "string" &&
      typeof match.scopeId === "string" &&
      typeof match.scope === "string",
  );
  contentGlobal.__fd0ActionPanel = mountCredentialActionPanel(
    document,
    anchor,
    currentLookup.origin,
    candidateOverride ?? readLoginCandidate(document, anchor),
    matches,
    scopes,
    {
      useGenerated(password) {
        const result = fillGeneratedPassword(document, password, anchor);
        if (!result.passwordFilled) {
          throw new Error("No visible password field was found.");
        }
      },
      async save(input) {
        await send({
          type: "fd0.saveLogin",
          origin: currentLookup.origin,
          ...input,
        });
        contentGlobal.__fd0LoginController?.invalidate();
      },
      async update(input) {
        await send({
          type: "fd0.updateLogin",
          origin: currentLookup.origin,
          ...input,
        });
        contentGlobal.__fd0LoginController?.invalidate();
      },
      async addTOTP(input) {
        await send({
          type: "fd0.addTOTP",
          origin: currentLookup.origin,
          totpUri: input.uri,
          credentialId: input.credentialId,
          revision: input.revision,
        });
        contentGlobal.__fd0LoginController?.invalidate();
      },
    },
  );
}

contentGlobal.__fd0LoginController = installLoginController(
  document,
  lookup,
  select,
  (anchor, currentLookup) => void openTools(anchor, currentLookup),
);

document.addEventListener("focusin", onOTPFocus, {
  capture: true,
  signal: lifecycle.signal,
});
if (findCredentialFields(document).otp) void fillRecentTOTP();

document.addEventListener("submit", onSubmit, {
  capture: true,
  signal: lifecycle.signal,
});
void consumeStagedLogin();

function onRuntimeMessage(
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: unknown) => void,
): boolean | void {
  if (sender.id !== chrome.runtime.id) return;
  if (isPingRequest(message)) {
    sendResponse({ ok: true });
    return;
  }
  if (isFillRequest(message)) {
    const anchor = pendingFillAnchors.get(message.selectionId);
    if (!anchor) {
      sendResponse({ ok: false });
      return;
    }
    try {
      sendResponse({
        ok: true,
        ...fillLogin(document, message.credential, anchor),
      });
    } catch {
      sendResponse({ ok: false });
    }
    return;
  }
  if (isShowNoticeRequest(message)) {
    showNotice(message.message, message.tone);
    sendResponse({ ok: true });
    return;
  }
  if (isOpenPickerRequest(message)) {
    void contentGlobal.__fd0LoginController?.open().then((ok) => sendResponse({ ok }));
    return true;
  }
}

chrome.runtime.onMessage.addListener(onRuntimeMessage);

function onOTPFocus(event: FocusEvent): void {
  const input = event.composedPath().find(isInput);
  if (!input) return;
  const otp = findCredentialFields(document, input).otp;
  if (otp === input) void fillRecentTOTP(input);
}

function onSubmit(event: SubmitEvent): void {
  const form = event.composedPath().find(isForm);
  const candidate = readLoginCandidate(document, form);
  if (!candidate) return;
  queueMicrotask(() => {
    if (event.defaultPrevented) return;
    void send<{ staged: boolean }>({
      type: "fd0.stageLogin",
      candidate,
    });
  });
}

function watchForOTP(): void {
  contentGlobal.__fd0OTPObserver?.disconnect();
  const tryFill = (anchor?: Element): Promise<boolean> => {
    if (otpRequest) return otpRequest;
    otpRequest = fillSelectedTOTP(anchor).finally(() => {
      otpRequest = undefined;
    });
    return otpRequest;
  };
  const fillSelectedTOTP = async (anchor?: Element): Promise<boolean> => {
    if (!recentLogin || recentLogin.expiresAt <= Date.now()) {
      recentLogin = undefined;
      contentGlobal.__fd0OTPObserver?.disconnect();
      return false;
    }
    if (!findCredentialFields(document, anchor).otp) return false;
    try {
      const result = await send<{ code: string; remaining: number; period: number }>({
        type: "fd0.requestTOTP",
        origin: recentLogin.origin,
        credentialId: recentLogin.credentialId,
      });
      if (result.remaining <= 2) {
        if (otpRetryTimer !== undefined) clearTimeout(otpRetryTimer);
        otpRetryTimer = document.defaultView?.setTimeout(
          () => void tryFill(anchor),
          (result.remaining + 1) * 1000,
        );
        return false;
      }
      if (fillOTP(document, result.code, anchor)) {
        showNotice("One-time code filled.");
        contentGlobal.__fd0OTPObserver?.disconnect();
        return true;
      }
    } catch (error) {
      showNotice(messageOf(error), "error");
      contentGlobal.__fd0OTPObserver?.disconnect();
    }
    return false;
  };
  void tryFill();
  const observer = new MutationObserver(() => {
    if (otpMutationTimer !== undefined) clearTimeout(otpMutationTimer);
    otpMutationTimer = document.defaultView?.setTimeout(
      () => void tryFill(),
      120,
    );
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  contentGlobal.__fd0OTPObserver = observer;
}

async function fillRecentTOTP(anchor?: Element): Promise<boolean> {
  if (otpRequest) return otpRequest;
  const request = fillRecentTOTPOnce(anchor);
  otpRequest = request.finally(() => {
    otpRequest = undefined;
  });
  return otpRequest;
}

async function fillRecentTOTPOnce(anchor?: Element): Promise<boolean> {
  if (!findCredentialFields(document, anchor).otp) return false;
  try {
    const result = await send<{
      available: boolean;
      code?: string;
      remaining?: number;
    }>({ type: "fd0.requestRecentTOTP" });
    if (!result.available || !result.code || result.remaining === undefined) return false;
    if (result.remaining <= 2) {
      if (otpRetryTimer !== undefined) clearTimeout(otpRetryTimer);
      otpRetryTimer = document.defaultView?.setTimeout(
        () => void fillRecentTOTP(anchor),
        (result.remaining + 1) * 1000,
      );
      return false;
    }
    if (fillOTP(document, result.code, anchor)) {
      showNotice("One-time code filled.");
      return true;
    }
  } catch {
    // A page may contain a false-positive OTP field while fd0 is closed. Stay quiet.
  }
  return false;
}

async function consumeStagedLogin(): Promise<void> {
  try {
    const result = await send<{
      available: boolean;
      candidate?: LoginCandidate;
    }>({ type: "fd0.consumeStagedLogin" });
    if (!result.available || !result.candidate) return;
    const currentLookup = await lookup();
    const fields = findCredentialFields(document);
    const anchor =
      fields.username ??
      fields.currentPassword ??
      fields.newPassword ??
      fields.otp ??
      document.documentElement;
    await openTools(anchor, currentLookup, result.candidate);
  } catch {
    // Save/update is an optional follow-up. Autofill remains usable if the
    // native host is temporarily unavailable after navigation.
  }
}

function showNotice(
  message: string,
  tone: "neutral" | "error" = "neutral",
): void {
  contentGlobal.__fd0LoginNotice?.close();
  contentGlobal.__fd0LoginNotice = mountLoginNotice(document, message, tone);
}

function messageOf(error: unknown): string {
  return error instanceof Error && error.message
    ? error.message
    : "fd0 could not complete this action.";
}

function isFillRequest(message: unknown): message is FillRequest {
  if (!message || typeof message !== "object") return false;
  const request = message as Partial<FillRequest>;
  return (
    request.type === "fd0.fill" &&
    typeof request.selectionId === "string" &&
    request.selectionId.length > 0 &&
    Boolean(request.credential) &&
    typeof request.credential?.password === "string" &&
    (request.credential.username === undefined ||
      typeof request.credential.username === "string") &&
    (request.credential.hasTotp === undefined ||
      typeof request.credential.hasTotp === "boolean")
  );
}

function isOpenPickerRequest(message: unknown): message is OpenPickerRequest {
  return Boolean(
    message &&
      typeof message === "object" &&
      (message as Partial<OpenPickerRequest>).type === "fd0.openPicker",
  );
}

function isShowNoticeRequest(message: unknown): message is ShowNoticeRequest {
  if (!message || typeof message !== "object") return false;
  const request = message as Partial<ShowNoticeRequest>;
  return (
    request.type === "fd0.showNotice" &&
    typeof request.message === "string" &&
    request.message.length > 0 &&
    (request.tone === undefined ||
      request.tone === "neutral" ||
      request.tone === "error")
  );
}

function isPingRequest(message: unknown): message is PingRequest {
  return Boolean(
    message &&
      typeof message === "object" &&
      (message as Partial<PingRequest>).type === "fd0.ping",
  );
}

function isInput(value: unknown): value is HTMLInputElement {
  return value instanceof HTMLInputElement;
}

function isForm(value: unknown): value is HTMLFormElement {
  return value instanceof HTMLFormElement;
}
