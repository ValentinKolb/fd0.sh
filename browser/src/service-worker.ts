export {};

const nativeHost = "sh.fd0.browser";
const nativeRequestTimeoutMilliseconds = 20_000;

type NativeError = { code: string; message: string };
type NativeResponse<T> = { id?: string; ok: boolean; result?: T; error?: NativeError };
type Match = {
  id: string;
  title: string;
  username?: string;
  revision?: string;
  hasTotp?: boolean;
  scopeId?: string;
  scope?: string;
};
type Scope = { id: string; label: string };
type ContentRequest =
  | { type: "fd0.requestMatches" }
  | {
      type: "fd0.selectCredential";
      origin: string;
      credentialId: string;
      selectionId: string;
    }
  | { type: "fd0.requestTOTP"; origin: string; credentialId: string }
  | { type: "fd0.requestRecentTOTP" }
  | {
      type: "fd0.stageLogin";
      candidate: {
        username: string;
        password: string;
        kind: "login" | "signup" | "password-change";
      };
    }
  | { type: "fd0.consumeStagedLogin" }
  | { type: "fd0.requestScopes" }
  | {
      type: "fd0.saveLogin";
      origin: string;
      scopeId: string;
      title: string;
      username: string;
      password: string;
    }
  | {
      type: "fd0.updateLogin";
      origin: string;
      credentialId: string;
      revision: string;
      title: string;
      username: string;
      password: string;
    }
  | {
      type: "fd0.addTOTP";
      origin: string;
      credentialId: string;
      revision: string;
      totpUri: string;
    };

type RecentTOTPSelection = {
  origin: string;
  credentialId: string;
  expiresAt: number;
};
type StagedLogin = {
  origin: string;
  sourceDocumentId: string;
  username: string;
  password: string;
  kind: "login" | "signup" | "password-change";
  expiresAt: number;
};

const sessionStatePrefix = "fd0:browser:";
const expiryAlarmPrefix = "fd0:browser:expire:";

chrome.runtime.onInstalled.addListener(() => {
  void pruneExpiredState();
  void refreshOpenTabs();
});
chrome.alarms.onAlarm.addListener((alarm) => {
  if (!alarm.name.startsWith(expiryAlarmPrefix)) return;
  void chrome.storage.session.remove(alarm.name.slice(expiryAlarmPrefix.length));
});
void pruneExpiredState();

chrome.action.onClicked.addListener(async (tab) => {
  if (tab.id === undefined) return;
  try {
    const opened = await openPickerInTab(tab.id);
    await showStatus(
      tab.id,
      opened?.ok ? "✓" : "0",
      opened?.ok ? "#18794e" : "#6b7280",
      opened?.ok ? "Choose an fd0 login" : "No fd0 login form is available",
    );
  } catch {
    await showStatus(
      tab.id,
      "!",
      "#b91c1c",
      "fd0 cannot access this page",
    );
  }
});

async function refreshOpenTabs(): Promise<void> {
  let tabs: chrome.tabs.Tab[];
  try {
    tabs = await chrome.tabs.query({});
  } catch {
    return;
  }
  await Promise.allSettled(
    tabs.map(async (tab) => {
      if (tab.id === undefined) return;
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          files: ["content.js"],
        });
      } catch {
        // Chrome may withhold site access. The toolbar action can reconnect later.
      }
    }),
  );
}

async function openPickerInTab(tabId: number): Promise<{ ok?: boolean }> {
  const frames = await chrome.scripting.executeScript<boolean>({
    target: { tabId, allFrames: true },
    func: hasVisibleCredentialField,
  });
  const target = frames
    .filter((frame) => frame.result === true)
    .sort((left, right) => left.frameId - right.frameId)[0];
  if (!target) return { ok: false };
  const options = { frameId: target.frameId };
  try {
    return await chrome.tabs.sendMessage(
      tabId,
      { type: "fd0.openPicker" },
      options,
    );
  } catch {
    await chrome.scripting.executeScript({
      target: { tabId, frameIds: [target.frameId] },
      files: ["content.js"],
    });
    return chrome.tabs.sendMessage(
      tabId,
      { type: "fd0.openPicker" },
      options,
    );
  }
}

function hasVisibleCredentialField(): boolean {
  const roots: (Document | ShadowRoot)[] = [document];
  for (const root of roots) {
    for (const element of root.querySelectorAll("*")) {
      if (element.shadowRoot) roots.push(element.shadowRoot);
    }
    for (const input of root.querySelectorAll<HTMLInputElement>("input")) {
      if (input.disabled || input.readOnly || input.type === "hidden") continue;
      if (input.type !== "password") continue;
      const style = getComputedStyle(input);
      const rect = input.getBoundingClientRect();
      if (
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number(style.opacity) !== 0 &&
        rect.width > 0 &&
        rect.height > 0
      ) {
        return true;
      }
    }
  }
  return false;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !isContentRequest(message)) return;
  void handle(message, sender)
    .then(sendResponse)
    .catch((error: unknown) =>
      sendResponse({
        ok: false,
        error: publicError(error),
      }),
    );
  return true;
});

async function handle(
  request: ContentRequest,
  sender: chrome.runtime.MessageSender,
): Promise<Record<string, unknown>> {
  const origin = senderHTTPSOrigin(sender);
  switch (request.type) {
    case "fd0.requestMatches": {
      const result = await nativeRequest({ operation: "matches", origin });
      if (!isMatchesResult(result)) throw protocolError();
      return { ok: true, result: { origin, credentials: result.credentials } };
    }
    case "fd0.requestScopes": {
      const result = await nativeRequest({ operation: "scopes" });
      if (!isScopesResult(result)) throw protocolError();
      return { ok: true, result };
    }
    case "fd0.selectCredential": {
      assertOrigin(request.origin, origin);
      if (
        typeof request.selectionId !== "string" ||
        request.selectionId.length === 0 ||
        request.selectionId.length > 128
      ) {
        throw nativeError("invalid_request", "fd0 refused that login selection.");
      }
      const { tabId, documentId } = senderDocument(sender);
      const credential = await nativeRequest({
        operation: "reveal",
        origin,
        credentialId: request.credentialId,
      });
      if (!isLoginCredential(credential)) throw protocolError();
      let filled: { ok?: boolean; passwordFilled?: boolean };
      try {
        filled = await chrome.tabs.sendMessage(
          tabId,
          { type: "fd0.fill", credential, selectionId: request.selectionId },
          { documentId },
        );
      } catch {
        throw nativeError("origin_changed", "This page changed before fd0 could fill it.");
      }
      if (!filled?.ok || !filled.passwordFilled) {
        throw nativeError("form_missing", "No visible login form was found.");
      }
      await removeFrameState("totp", sender, origin);
      if (credential.hasTotp) {
        await writeFrameState("totp", sender, origin, {
          origin,
          credentialId: request.credentialId,
          expiresAt: Date.now() + 5 * 60 * 1000,
        });
      }
      await showStatus(tabId, "✓", "#18794e", "Filled login with fd0");
      return { ok: true, result: { hasTotp: credential.hasTotp === true } };
    }
    case "fd0.requestTOTP": {
      assertOrigin(request.origin, origin);
      const result = await nativeRequest({
        operation: "totp",
        origin,
        credentialId: request.credentialId,
      });
      if (!isTOTPResult(result)) throw protocolError();
      return { ok: true, result };
    }
    case "fd0.requestRecentTOTP": {
      const selected = await readFrameState<RecentTOTPSelection>(
        "totp",
        sender,
        origin,
      );
      if (!selected) {
        return { ok: true, result: { available: false } };
      }
      const result = await nativeRequest({
        operation: "totp",
        origin,
        credentialId: selected.credentialId,
      });
      if (!isTOTPResult(result)) throw protocolError();
      return { ok: true, result: { available: true, ...result } };
    }
    case "fd0.stageLogin": {
      if (
        sender.tab?.id === undefined ||
        !sender.documentId ||
        !request.candidate ||
        typeof request.candidate.username !== "string" ||
        typeof request.candidate.password !== "string" ||
        !["login", "signup", "password-change"].includes(request.candidate.kind) ||
        request.candidate.password.length === 0 ||
        request.candidate.password.length > 32 * 1024 ||
        request.candidate.username.length > 32 * 1024
      ) {
        throw nativeError("invalid_request", "fd0 refused that login candidate.");
      }
      await writeFrameState("login", sender, origin, {
        origin,
        sourceDocumentId: sender.documentId,
        ...request.candidate,
        expiresAt: Date.now() + 60 * 1000,
      });
      return { ok: true, result: { staged: true } };
    }
    case "fd0.consumeStagedLogin": {
      const candidate = await readFrameState<StagedLogin>(
        "login",
        sender,
        origin,
      );
      if (!candidate) {
        return { ok: true, result: { available: false } };
      }
      if (candidate.sourceDocumentId === sender.documentId) {
        return { ok: true, result: { available: false } };
      }
      await removeFrameState("login", sender, origin);
      return {
        ok: true,
        result: {
          available: true,
          candidate: {
            username: candidate.username,
            password: candidate.password,
            kind: candidate.kind,
          },
        },
      };
    }
    case "fd0.saveLogin": {
      assertOrigin(request.origin, origin);
      const result = await nativeRequest({
        operation: "save",
        origin,
        scopeId: request.scopeId,
        title: request.title,
        username: request.username,
        password: request.password,
      });
      if (!isMatch(result)) throw protocolError();
      return { ok: true, result };
    }
    case "fd0.updateLogin": {
      assertOrigin(request.origin, origin);
      const result = await nativeRequest({
        operation: "update",
        origin,
        credentialId: request.credentialId,
        revision: request.revision,
        title: request.title,
        username: request.username,
        password: request.password,
      });
      if (!isMatch(result)) throw protocolError();
      return { ok: true, result };
    }
    case "fd0.addTOTP": {
      assertOrigin(request.origin, origin);
      const result = await nativeRequest({
        operation: "add_totp",
        origin,
        credentialId: request.credentialId,
        revision: request.revision,
        totpUri: request.totpUri,
      });
      if (!isMatch(result)) throw protocolError();
      return { ok: true, result };
    }
  }
}

function senderHTTPSOrigin(sender: chrome.runtime.MessageSender): string {
  if (sender.origin !== undefined) {
    const senderOrigin = httpsOrigin(sender.origin);
    if (!senderOrigin) {
      throw nativeError("origin_changed", "fd0 works only on HTTPS pages.");
    }
    return senderOrigin;
  }
  const directOrigin = httpsOrigin(sender.url ?? "");
  if (directOrigin) return directOrigin;
  if ((sender.frameId ?? 0) > 0) {
    throw nativeError("origin_changed", "fd0 works only on HTTPS pages.");
  }
  const origin = httpsOrigin(sender.tab?.url ?? "");
  if (!origin) throw nativeError("origin_changed", "fd0 works only on HTTPS pages.");
  return origin;
}

function senderDocument(sender: chrome.runtime.MessageSender): {
  tabId: number;
  documentId: string;
} {
  if (sender.tab?.id === undefined || !sender.documentId) {
    throw nativeError("origin_changed", "This page changed before fd0 could fill it.");
  }
  return { tabId: sender.tab.id, documentId: sender.documentId };
}

function assertOrigin(requested: string, actual: string): void {
  if (requested !== actual) {
    throw nativeError("origin_changed", "This page changed before fd0 could use that login.");
  }
}

function httpsOrigin(rawURL: string): string | undefined {
  try {
    const url = new URL(rawURL);
    return url.protocol === "https:" ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

async function nativeRequest(payload: Record<string, unknown>): Promise<unknown> {
  const request = { id: crypto.randomUUID(), ...payload };
  const operation = typeof payload.operation === "string" ? payload.operation : "";
  const attempts = ["matches", "scopes", "reveal", "totp"].includes(operation)
    ? 2
    : 1;
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await withTimeout(
        chrome.runtime.sendNativeMessage<NativeResponse<unknown>>(
          nativeHost,
          request,
        ),
        nativeRequestTimeoutMilliseconds,
      );
      if (
        response?.id === request.id &&
        response.ok &&
        response.result !== undefined
      ) {
        return response.result;
      }
      if (
        response?.id === request.id &&
        response.error &&
        isNativeError(response.error)
      ) {
        throw response.error;
      }
      throw protocolError();
    } catch (error) {
      if (isNativeError(error)) throw error;
      lastError = error;
      if (attempt + 1 < attempts) {
        await new Promise((resolve) => setTimeout(resolve, 120));
      }
    }
  }
  throw nativeError(
    "unavailable",
    "fd0 is not connected. Open the desktop app and try again.",
    lastError,
  );
}

function withTimeout<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(nativeError("timeout", "fd0 took too long to respond.")),
      milliseconds,
    );
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function frameStateKey(
  kind: "totp" | "login",
  sender: chrome.runtime.MessageSender,
  origin: string,
): string {
  if (sender.tab?.id === undefined) {
    throw nativeError("origin_changed", "This page changed before fd0 could continue.");
  }
  return `${sessionStatePrefix}${kind}:${sender.tab.id}:${sender.frameId ?? 0}:${encodeURIComponent(origin)}`;
}

async function writeFrameState(
  kind: "totp" | "login",
  sender: chrome.runtime.MessageSender,
  origin: string,
  value: RecentTOTPSelection | StagedLogin,
): Promise<void> {
  const key = frameStateKey(kind, sender, origin);
  await chrome.alarms.create(`${expiryAlarmPrefix}${key}`, {
    when: value.expiresAt,
  });
  await chrome.storage.session.set({ [key]: value });
}

async function readFrameState<T extends RecentTOTPSelection | StagedLogin>(
  kind: "totp" | "login",
  sender: chrome.runtime.MessageSender,
  origin: string,
): Promise<T | undefined> {
  const key = frameStateKey(kind, sender, origin);
  const stored = (await chrome.storage.session.get(key))[key];
  if (!isFrameState(stored, origin, kind) || stored.expiresAt <= Date.now()) {
    await removeSessionState(key);
    return undefined;
  }
  return stored as T;
}

async function removeFrameState(
  kind: "totp" | "login",
  sender: chrome.runtime.MessageSender,
  origin: string,
): Promise<void> {
  await removeSessionState(frameStateKey(kind, sender, origin));
}

async function removeSessionState(key: string): Promise<void> {
  await Promise.all([
    chrome.storage.session.remove(key),
    chrome.alarms.clear(`${expiryAlarmPrefix}${key}`),
  ]);
}

async function pruneExpiredState(): Promise<void> {
  const values = await chrome.storage.session.get(null);
  const expired = Object.entries(values)
    .filter(
      ([key, value]) =>
        key.startsWith(sessionStatePrefix) &&
        (!value ||
          typeof value !== "object" ||
          typeof (value as { expiresAt?: unknown }).expiresAt !== "number" ||
          (value as { expiresAt: number }).expiresAt <= Date.now()),
    )
    .map(([key]) => key);
  await Promise.all(expired.map(removeSessionState));
}

function isFrameState(
  value: unknown,
  origin: string,
  kind: "totp" | "login",
): value is RecentTOTPSelection | StagedLogin {
  if (!value || typeof value !== "object") return false;
  const state = value as Partial<RecentTOTPSelection & StagedLogin>;
  if (state.origin !== origin || typeof state.expiresAt !== "number") return false;
  if (kind === "totp") return typeof state.credentialId === "string";
  return (
    typeof state.sourceDocumentId === "string" &&
    typeof state.username === "string" &&
    typeof state.password === "string" &&
    ["login", "signup", "password-change"].includes(state.kind ?? "")
  );
}

function isContentRequest(value: unknown): value is ContentRequest {
  if (!value || typeof value !== "object") return false;
  const type = (value as { type?: unknown }).type;
  return typeof type === "string" && [
    "fd0.requestMatches",
    "fd0.selectCredential",
    "fd0.requestTOTP",
    "fd0.requestRecentTOTP",
    "fd0.stageLogin",
    "fd0.consumeStagedLogin",
    "fd0.requestScopes",
    "fd0.saveLogin",
    "fd0.updateLogin",
    "fd0.addTOTP",
  ].includes(type);
}

function isMatchesResult(value: unknown): value is { credentials: Match[] } {
  return Boolean(
    value &&
      typeof value === "object" &&
      Array.isArray((value as { credentials?: unknown }).credentials) &&
      (value as { credentials: unknown[] }).credentials.every(isMatch),
  );
}

function isMatch(value: unknown): value is Match {
  if (!value || typeof value !== "object") return false;
  const match = value as Partial<Match>;
  return (
    typeof match.id === "string" &&
    match.id.length > 0 &&
    typeof match.title === "string" &&
    (match.revision === undefined || typeof match.revision === "string") &&
    (match.scopeId === undefined || typeof match.scopeId === "string") &&
    (match.scope === undefined || typeof match.scope === "string") &&
    (match.username === undefined || typeof match.username === "string") &&
    (match.hasTotp === undefined || typeof match.hasTotp === "boolean")
  );
}

function isScopesResult(value: unknown): value is { scopes: Scope[] } {
  return Boolean(
    value &&
      typeof value === "object" &&
      Array.isArray((value as { scopes?: unknown }).scopes) &&
      (value as { scopes: unknown[] }).scopes.every(
        (scope) =>
          Boolean(
            scope &&
              typeof scope === "object" &&
              typeof (scope as Partial<Scope>).id === "string" &&
              typeof (scope as Partial<Scope>).label === "string",
          ),
      ),
  );
}

function isLoginCredential(value: unknown): value is {
  username?: string;
  password: string;
  hasTotp?: boolean;
} {
  if (!value || typeof value !== "object") return false;
  const credential = value as { username?: unknown; password?: unknown; hasTotp?: unknown };
  return (
    typeof credential.password === "string" &&
    (credential.username === undefined || typeof credential.username === "string") &&
    (credential.hasTotp === undefined || typeof credential.hasTotp === "boolean")
  );
}

function isTOTPResult(value: unknown): value is {
  code: string;
  remaining: number;
  period: number;
} {
  if (!value || typeof value !== "object") return false;
  const result = value as { code?: unknown; remaining?: unknown; period?: unknown };
  return (
    typeof result.code === "string" &&
    /^\d{6,8}$/.test(result.code) &&
    typeof result.remaining === "number" &&
    typeof result.period === "number"
  );
}

function isNativeError(value: unknown): value is NativeError {
  if (!value || typeof value !== "object") return false;
  const error = value as Partial<NativeError>;
  return typeof error.code === "string" && typeof error.message === "string";
}

function nativeError(code: string, message: string, _cause?: unknown): NativeError {
  return { code, message };
}

function protocolError(): NativeError {
  return nativeError("invalid_response", "Update fd0, then try again.");
}

function publicError(error: unknown): NativeError {
  if (isNativeError(error)) return error;
  return nativeError("request_failed", "fd0 could not complete this request.");
}

async function showStatus(
  tabId: number,
  text: string,
  color: string,
  title: string,
): Promise<void> {
  await Promise.all([
    chrome.action.setBadgeBackgroundColor({ tabId, color }),
    chrome.action.setBadgeText({ tabId, text }),
    chrome.action.setTitle({ tabId, title }),
  ]);
}
