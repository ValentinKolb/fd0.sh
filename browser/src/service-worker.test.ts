import { describe, expect, test } from "bun:test";

type MessageListener = (
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: unknown) => void,
) => boolean | void;

let messageListener: MessageListener | undefined;
let actionListener: ((tab: chrome.tabs.Tab) => void | Promise<void>) | undefined;
let installedListener: (() => void) | undefined;
let nativeCalls = 0;
let fillCalls = 0;
let lastFillMessage: unknown;
let currentDocumentId = "login-document";
let openPickerCalls = 0;
let lastOpenPickerFrame: number | undefined;
let scriptInjectionCalls = 0;
let failOpenPickerOnce = false;
let failScriptInjectionForTab: number | undefined;
let frameProbeResults = [{ frameId: 0, result: true }];
let alarmListener: ((alarm: { name: string }) => void) | undefined;
const sessionStorage = new Map<string, unknown>();
let nativeResponseOverride:
  | ((request: Record<string, unknown>) => unknown)
  | undefined;
const match = {
  id: "opaque",
  title: "Example",
  username: "user",
  revision: "1",
  scopeId: "s_example",
  scope: "Personal",
};

const chromeMock = {
  runtime: {
    id: "extension-id",
    onMessage: {
      addListener(listener: MessageListener) {
        messageListener = listener;
      },
    },
    onInstalled: {
      addListener(listener: () => void) {
        installedListener = listener;
      },
    },
    async sendNativeMessage(_application: string, request: unknown) {
      nativeCalls += 1;
      const nativeRequest = request as Record<string, unknown>;
      if (nativeResponseOverride) return nativeResponseOverride(nativeRequest);
      if (
        request &&
        typeof request === "object" &&
        (request as { operation?: string }).operation === "matches"
      ) {
        return {
          id: nativeRequest.id,
          ok: true,
          result: {
            credentials: [match],
          },
        };
      }
      return {
        id: nativeRequest.id,
        ok: true,
        result: { username: "user", password: "secret" },
      };
    },
  },
  action: {
    onClicked: {
      addListener(listener: (tab: chrome.tabs.Tab) => void | Promise<void>) {
        actionListener = listener;
      },
    },
    async setBadgeBackgroundColor() {},
    async setBadgeText() {},
    async setTitle() {},
  },
  tabs: {
    async query() {
      return [{ id: 7 }, { id: 8 }, {}];
    },
    async sendMessage(
      _tabId: number,
      message: unknown,
      options?: { documentId?: string; frameId?: number },
    ) {
      if (
        message &&
        typeof message === "object" &&
        (message as { type?: string }).type === "fd0.openPicker"
      ) {
        openPickerCalls += 1;
        lastOpenPickerFrame = options?.frameId;
        if (failOpenPickerOnce) {
          failOpenPickerOnce = false;
          throw new Error("Receiving end does not exist");
        }
        return { ok: true };
      }
      if (options?.documentId !== currentDocumentId) {
        throw new Error("Receiving end does not exist");
      }
      fillCalls += 1;
      lastFillMessage = message;
      return { ok: true, passwordFilled: true };
    },
  },
  scripting: {
    async executeScript(details: {
      target: { tabId: number };
      func?: () => boolean;
    }) {
      scriptInjectionCalls += 1;
      if (details.target.tabId === failScriptInjectionForTab) {
        throw new Error("Cannot access this page");
      }
      return details.func ? frameProbeResults : [];
    },
  },
  storage: {
    session: {
      async get(keys?: string | string[] | null) {
        const selected =
          keys === undefined || keys === null
            ? [...sessionStorage.keys()]
            : typeof keys === "string"
              ? [keys]
              : keys;
        return Object.fromEntries(
          selected
            .filter((key) => sessionStorage.has(key))
            .map((key) => [key, sessionStorage.get(key)]),
        );
      },
      async set(items: Record<string, unknown>) {
        for (const [key, value] of Object.entries(items)) {
          sessionStorage.set(key, value);
        }
      },
      async remove(keys: string | string[]) {
        for (const key of typeof keys === "string" ? [keys] : keys) {
          sessionStorage.delete(key);
        }
      },
    },
  },
  alarms: {
    async create() {},
    async clear() {
      return true;
    },
    onAlarm: {
      addListener(listener: (alarm: { name: string }) => void) {
        alarmListener = listener;
      },
    },
  },
};

(globalThis as unknown as { chrome: typeof chromeMock }).chrome = chromeMock;
await import("./service-worker");

describe("credential selection boundary", () => {
  test("fails closed when the sender origin changed", async () => {
    nativeCalls = 0;
    fillCalls = 0;
    nativeResponseOverride = undefined;
    failOpenPickerOnce = false;
    currentDocumentId = "login-document";
    const response = new Promise<unknown>((resolve) => {
      const keepAlive = messageListener?.(
        {
          type: "fd0.selectCredential",
          origin: "https://example.com",
          credentialId: "opaque",
          selectionId: "selection-origin-change",
        },
        {
          id: "extension-id",
          frameId: 0,
          documentId: "login-document",
          tab: { id: 7, url: "https://attacker.example/login" },
        },
        resolve,
      );
      expect(keepAlive).toBe(true);
    });

    expect(await response).toEqual({
      ok: false,
      error: {
        code: "origin_changed",
        message: "This page changed before fd0 could use that login.",
      },
    });
    expect(nativeCalls).toBe(0);
    expect(fillCalls).toBe(0);
  });

  test("fails closed when the tab navigates during reveal", async () => {
    nativeCalls = 0;
    fillCalls = 0;
    nativeResponseOverride = undefined;
    currentDocumentId = "replacement-document";
    const response = new Promise<unknown>((resolve) => {
      messageListener?.(
        {
          type: "fd0.selectCredential",
          origin: "https://example.com",
          credentialId: "opaque",
          selectionId: "selection-navigation",
        },
        {
          id: "extension-id",
          frameId: 0,
          documentId: "login-document",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });

    expect(await response).toEqual({
      ok: false,
      error: {
        code: "origin_changed",
        message: "This page changed before fd0 could fill it.",
      },
    });
    expect(nativeCalls).toBe(1);
    expect(fillCalls).toBe(0);
  });

  test("reveals only after a same-origin top-frame selection", async () => {
    nativeCalls = 0;
    fillCalls = 0;
    nativeResponseOverride = undefined;
    currentDocumentId = "login-document";
    const response = new Promise<unknown>((resolve) => {
      messageListener?.(
        {
          type: "fd0.selectCredential",
          origin: "https://example.com",
          credentialId: "opaque",
          selectionId: "selection-success",
        },
        {
          id: "extension-id",
          frameId: 0,
          documentId: "login-document",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });

    expect(await response).toEqual({ ok: true, result: { hasTotp: false } });
    expect(nativeCalls).toBe(1);
    expect(fillCalls).toBe(1);
    expect(lastFillMessage).toMatchObject({
      type: "fd0.fill",
      selectionId: "selection-success",
    });
  });
});

describe("credential metadata boundary", () => {
  test("derives the HTTPS origin from the top-frame sender", async () => {
    nativeCalls = 0;
    nativeResponseOverride = undefined;
    const response = new Promise<unknown>((resolve) => {
      const keepAlive = messageListener?.(
        { type: "fd0.requestMatches" },
        {
          id: "extension-id",
          frameId: 0,
          url: "https://example.com/login",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
      expect(keepAlive).toBe(true);
    });

    expect(await response).toEqual({
      ok: true,
      result: {
        origin: "https://example.com",
        credentials: [match],
      },
    });
    expect(nativeCalls).toBe(1);
  });

  test("binds subframe metadata requests to the frame HTTPS origin", async () => {
    nativeCalls = 0;
    nativeResponseOverride = undefined;
    const response = new Promise<unknown>((resolve) => {
      messageListener?.(
        { type: "fd0.requestMatches" },
        {
          id: "extension-id",
          frameId: 2,
          url: "https://example.com/embedded-login",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });

    expect(await response).toEqual({
      ok: true,
      result: {
        origin: "https://example.com",
        credentials: [match],
      },
    });
    expect(nativeCalls).toBe(1);
  });

  test("uses the inherited HTTPS origin for an about:blank frame", async () => {
    nativeCalls = 0;
    nativeResponseOverride = undefined;
    const response = await new Promise<unknown>((resolve) => {
      messageListener?.(
        { type: "fd0.requestMatches" },
        {
          id: "extension-id",
          frameId: 3,
          origin: "https://example.com",
          url: "about:blank",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });

    expect(response).toMatchObject({
      ok: true,
      result: { origin: "https://example.com" },
    });
    expect(nativeCalls).toBe(1);
  });

  test("rejects an opaque subframe instead of inheriting the tab origin", async () => {
    nativeCalls = 0;
    const response = await new Promise<unknown>((resolve) => {
      messageListener?.(
        { type: "fd0.requestMatches" },
        {
          id: "extension-id",
          frameId: 2,
          origin: "null",
          url: "about:blank",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });

    expect(response).toEqual({
      ok: false,
      error: {
        code: "origin_changed",
        message: "fd0 works only on HTTPS pages.",
      },
    });
    expect(nativeCalls).toBe(0);
  });

  test("keeps autofill available during a read-only legacy host transition", async () => {
    nativeCalls = 0;
    const legacyMatch = {
      id: "legacy-opaque",
      title: "Legacy login",
      username: "legacy-user",
    };
    nativeResponseOverride = (request) => ({
      id: request.id,
      ok: true,
      result: { credentials: [legacyMatch] },
    });
    const response = new Promise<unknown>((resolve) => {
      messageListener?.(
        { type: "fd0.requestMatches" },
        {
          id: "extension-id",
          frameId: 0,
          url: "https://example.com/login",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });

    expect(await response).toEqual({
      ok: true,
      result: {
        origin: "https://example.com",
        credentials: [legacyMatch],
      },
    });
    expect(nativeCalls).toBe(1);
    nativeResponseOverride = undefined;
  });
});

describe("native protocol boundary", () => {
  test("rejects a response for a different request", async () => {
    nativeCalls = 0;
    nativeResponseOverride = () => ({
      id: "different-request",
      ok: true,
      result: { credentials: [] },
    });
    const response = new Promise<unknown>((resolve) => {
      messageListener?.(
        { type: "fd0.requestMatches" },
        {
          id: "extension-id",
          frameId: 0,
          url: "https://example.com/login",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });

    expect(await response).toEqual({
      ok: false,
      error: {
        code: "invalid_response",
        message: "Update fd0, then try again.",
      },
    });
    expect(nativeCalls).toBe(1);
    nativeResponseOverride = undefined;
  });

  test("rejects malformed credential metadata", async () => {
    nativeCalls = 0;
    nativeResponseOverride = (request) => ({
      id: request.id,
      ok: true,
      result: { credentials: [{ id: "opaque", title: 7 }] },
    });
    const response = new Promise<unknown>((resolve) => {
      messageListener?.(
        { type: "fd0.requestMatches" },
        {
          id: "extension-id",
          frameId: 0,
          url: "https://example.com/login",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });

    expect(await response).toEqual({
      ok: false,
      error: {
        code: "invalid_response",
        message: "Update fd0, then try again.",
      },
    });
    expect(nativeCalls).toBe(1);
    nativeResponseOverride = undefined;
  });
});

describe("save and update lifecycle", () => {
  test("keeps a submitted candidate session-only and consumes it once", async () => {
    const sender = {
      id: "extension-id",
      frameId: 0,
      documentId: "login-document",
      url: "https://example.com/login",
      tab: { id: 17, url: "https://example.com/login" },
    };
    const stage = new Promise<unknown>((resolve) => {
      messageListener?.(
        {
          type: "fd0.stageLogin",
          candidate: {
            username: "person@example.com",
            password: "new-secret",
            kind: "login",
          },
        },
        sender,
        resolve,
      );
    });
    expect(await stage).toEqual({ ok: true, result: { staged: true } });

    const resultDocument = { ...sender, documentId: "result-document" };
    const consume = () =>
      new Promise<unknown>((resolve) => {
        messageListener?.(
          { type: "fd0.consumeStagedLogin" },
          resultDocument,
          resolve,
        );
      });
    expect(
      await new Promise<unknown>((resolve) => {
        messageListener?.({ type: "fd0.consumeStagedLogin" }, sender, resolve);
      }),
    ).toEqual({
      ok: true,
      result: { available: false },
    });
    expect(await consume()).toEqual({
      ok: true,
      result: {
        available: true,
        candidate: {
          username: "person@example.com",
          password: "new-secret",
          kind: "login",
        },
      },
    });
    expect(await consume()).toEqual({
      ok: true,
      result: { available: false },
    });
  });

  test("sends an explicit update with its opaque revision", async () => {
    let captured: Record<string, unknown> | undefined;
    nativeResponseOverride = (request) => {
      captured = request;
      return { id: request.id, ok: true, result: match };
    };
    const response = new Promise<unknown>((resolve) => {
      messageListener?.(
        {
          type: "fd0.updateLogin",
          origin: "https://example.com",
          credentialId: "opaque",
          revision: "7",
          title: "Example account",
          username: "person@example.com",
          password: "replacement",
        },
        {
          id: "extension-id",
          frameId: 0,
          url: "https://example.com/login",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });
    expect(await response).toEqual({ ok: true, result: match });
    expect(captured).toMatchObject({
      operation: "update",
      origin: "https://example.com",
      credentialId: "opaque",
      revision: "7",
      title: "Example account",
      username: "person@example.com",
      password: "replacement",
    });
    nativeResponseOverride = undefined;
  });

  test("maps save and TOTP mutations to the native protocol exactly once", async () => {
    const captured: Record<string, unknown>[] = [];
    nativeCalls = 0;
    nativeResponseOverride = (request) => {
      captured.push(request);
      return { id: request.id, ok: true, result: match };
    };
    const sender = {
      id: "extension-id",
      frameId: 0,
      url: "https://example.com/login",
      tab: { id: 7, url: "https://example.com/login" },
    };
    const send = (message: Record<string, unknown>) =>
      new Promise<unknown>((resolve) => {
        messageListener?.(message, sender, resolve);
      });

    expect(
      await send({
        type: "fd0.saveLogin",
        origin: "https://example.com",
        scopeId: "s_personal",
        title: "New account",
        username: "person@example.com",
        password: "secret",
      }),
    ).toEqual({ ok: true, result: match });
    expect(
      await send({
        type: "fd0.addTOTP",
        origin: "https://example.com",
        credentialId: "opaque",
        revision: "9",
        totpUri: "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP",
      }),
    ).toEqual({ ok: true, result: match });
    expect(captured).toHaveLength(2);
    expect(captured[0]).toMatchObject({
      operation: "save",
      scopeId: "s_personal",
      title: "New account",
      username: "person@example.com",
      password: "secret",
    });
    expect(captured[1]).toMatchObject({
      operation: "add_totp",
      credentialId: "opaque",
      revision: "9",
      totpUri: "otpauth://totp/Example:user?secret=JBSWY3DPEHPK3PXP",
    });
    expect(nativeCalls).toBe(2);
    nativeResponseOverride = undefined;
  });

  test("does not let another frame consume a submitted candidate", async () => {
    const topFrame = {
      id: "extension-id",
      frameId: 0,
      documentId: "top-document",
      url: "https://example.com/login",
      tab: { id: 19, url: "https://example.com/login" },
    };
    await new Promise<unknown>((resolve) => {
      messageListener?.(
        {
          type: "fd0.stageLogin",
          candidate: {
            username: "person@example.com",
            password: "new-secret",
            kind: "login",
          },
        },
        topFrame,
        resolve,
      );
    });
    const childResult = await new Promise<unknown>((resolve) => {
      messageListener?.(
        { type: "fd0.consumeStagedLogin" },
        {
          ...topFrame,
          frameId: 2,
          documentId: "child-document",
          url: "https://other.example/login",
          origin: "https://other.example",
        },
        resolve,
      );
    });
    expect(childResult).toEqual({
      ok: true,
      result: { available: false },
    });
    const topResult = await new Promise<unknown>((resolve) => {
      messageListener?.(
        { type: "fd0.consumeStagedLogin" },
        { ...topFrame, documentId: "top-result-document" },
        resolve,
      );
    });
    expect(topResult).toMatchObject({
      ok: true,
      result: {
        available: true,
        candidate: { username: "person@example.com" },
      },
    });
  });

  test("never retries a mutation after a transport failure", async () => {
    nativeCalls = 0;
    nativeResponseOverride = () => {
      throw new Error("response lost");
    };
    const response = await new Promise<unknown>((resolve) => {
      messageListener?.(
        {
          type: "fd0.saveLogin",
          origin: "https://example.com",
          scopeId: "s_personal",
          title: "Example",
          username: "person@example.com",
          password: "secret",
        },
        {
          id: "extension-id",
          frameId: 0,
          url: "https://example.com/login",
          tab: { id: 7, url: "https://example.com/login" },
        },
        resolve,
      );
    });
    expect(response).toMatchObject({
      ok: false,
      error: { code: "unavailable" },
    });
    expect(nativeCalls).toBe(1);
    nativeResponseOverride = undefined;
  });

  test("clears the previous TOTP selection when the next login has no TOTP", async () => {
    sessionStorage.clear();
    currentDocumentId = "login-document";
    let revealHasTOTP = true;
    nativeResponseOverride = (request) => ({
      id: request.id,
      ok: true,
      result: {
        username: "person@example.com",
        password: "secret",
        hasTotp: revealHasTOTP,
      },
    });
    const sender = {
      id: "extension-id",
      frameId: 0,
      documentId: "login-document",
      url: "https://example.com/login",
      tab: { id: 31, url: "https://example.com/login" },
    };
    const select = (selectionId: string) =>
      new Promise<unknown>((resolve) => {
        messageListener?.(
          {
            type: "fd0.selectCredential",
            origin: "https://example.com",
            credentialId: "opaque",
            selectionId,
          },
          sender,
          resolve,
        );
      });

    expect(await select("selection-with-totp")).toEqual({
      ok: true,
      result: { hasTotp: true },
    });
    expect(
      [...sessionStorage.keys()].some((key) =>
        key.startsWith("fd0:browser:totp:"),
      ),
    ).toBe(true);

    revealHasTOTP = false;
    expect(await select("selection-without-totp")).toEqual({
      ok: true,
      result: { hasTotp: false },
    });
    expect(
      [...sessionStorage.keys()].some((key) =>
        key.startsWith("fd0:browser:totp:"),
      ),
    ).toBe(false);
    nativeResponseOverride = undefined;
  });

  test("actively expires staged credentials from session storage", async () => {
    sessionStorage.clear();
    const sender = {
      id: "extension-id",
      frameId: 0,
      documentId: "login-document",
      url: "https://example.com/login",
      tab: { id: 23, url: "https://example.com/login" },
    };
    await new Promise<unknown>((resolve) => {
      messageListener?.(
        {
          type: "fd0.stageLogin",
          candidate: {
            username: "person@example.com",
            password: "short-lived",
            kind: "login",
          },
        },
        sender,
        resolve,
      );
    });
    const key = [...sessionStorage.keys()].find((candidate) =>
      candidate.startsWith("fd0:browser:login:"),
    );
    expect(key).toBeDefined();

    alarmListener?.({ name: `fd0:browser:expire:${key}` });
    await Promise.resolve();
    expect(sessionStorage.has(key!)).toBe(false);
  });
});

describe("toolbar action", () => {
  test("best-effort refreshes eligible open tabs after an extension update", async () => {
    scriptInjectionCalls = 0;
    failScriptInjectionForTab = 8;

    installedListener?.();
    await Promise.resolve();
    await Promise.resolve();

    expect(scriptInjectionCalls).toBe(2);
    failScriptInjectionForTab = undefined;
  });

  test("asks the declarative content script to open its picker", async () => {
    nativeCalls = 0;
    openPickerCalls = 0;
    nativeResponseOverride = undefined;

    await actionListener?.({ id: 7, url: "https://example.com/login" });

    expect(openPickerCalls).toBe(1);
    expect(lastOpenPickerFrame).toBe(0);
    expect(nativeCalls).toBe(0);
  });

  test("opens the picker in one deterministic credential frame", async () => {
    openPickerCalls = 0;
    frameProbeResults = [
      { frameId: 7, result: true },
      { frameId: 0, result: true },
    ];

    await actionListener?.({ id: 7, url: "https://example.com/login" });

    expect(openPickerCalls).toBe(1);
    expect(lastOpenPickerFrame).toBe(0);
    frameProbeResults = [{ frameId: 0, result: true }];
  });

  test("injects the declared content script when an existing tab has not loaded it", async () => {
    openPickerCalls = 0;
    scriptInjectionCalls = 0;
    failOpenPickerOnce = true;

    await actionListener?.({ id: 7, url: "https://example.com/login" });

    expect(openPickerCalls).toBe(2);
    expect(scriptInjectionCalls).toBe(2);
  });
});
