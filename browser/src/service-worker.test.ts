import { describe, expect, test } from "bun:test";

type MessageListener = (
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response: unknown) => void,
) => boolean | void;

let messageListener: MessageListener | undefined;
let actionListener: ((tab: chrome.tabs.Tab) => void | Promise<void>) | undefined;
let nativeCalls = 0;
let fillCalls = 0;
let currentDocumentId = "login-document";
let openPickerCalls = 0;
let nativeResponseOverride:
  | ((request: Record<string, unknown>) => unknown)
  | undefined;

const chromeMock = {
  runtime: {
    id: "extension-id",
    onMessage: {
      addListener(listener: MessageListener) {
        messageListener = listener;
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
            credentials: [{ id: "opaque", title: "Example", username: "user" }],
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
    async sendMessage(
      _tabId: number,
      message: unknown,
      options?: { documentId?: string },
    ) {
      if (
        message &&
        typeof message === "object" &&
        (message as { type?: string }).type === "fd0.openPicker"
      ) {
        openPickerCalls += 1;
        return { ok: true };
      }
      if (options?.documentId !== currentDocumentId) {
        throw new Error("Receiving end does not exist");
      }
      fillCalls += 1;
      return { ok: true, passwordFilled: true };
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
    currentDocumentId = "login-document";
    const response = new Promise<unknown>((resolve) => {
      const keepAlive = messageListener?.(
        {
          type: "fd0.selectCredential",
          origin: "https://example.com",
          credentialId: "opaque",
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
      error: "This page changed before fd0 could fill it.",
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
      error: "This page changed before fd0 could fill it.",
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

    expect(await response).toEqual({ ok: true });
    expect(nativeCalls).toBe(1);
    expect(fillCalls).toBe(1);
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
        credentials: [{ id: "opaque", title: "Example", username: "user" }],
      },
    });
    expect(nativeCalls).toBe(1);
  });

  test("rejects metadata requests from subframes", async () => {
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
      ok: false,
      error: "fd0 only fills the top frame of HTTPS pages.",
    });
    expect(nativeCalls).toBe(0);
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
      error: "fd0 could not find logins for this site.",
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
      error: "Update fd0 and reload this extension.",
    });
    expect(nativeCalls).toBe(1);
    nativeResponseOverride = undefined;
  });
});

describe("toolbar action", () => {
  test("asks the declarative content script to open its picker", async () => {
    nativeCalls = 0;
    openPickerCalls = 0;
    nativeResponseOverride = undefined;

    await actionListener?.({ id: 7, url: "https://example.com/login" });

    expect(openPickerCalls).toBe(1);
    expect(nativeCalls).toBe(0);
  });
});
