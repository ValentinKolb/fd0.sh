import { fillLogin } from "./form";
import {
  installLoginController,
  type LoginController,
  type LoginLookup,
} from "./login-controller";
import {
  mountLoginNotice,
  type LoginNotice,
} from "./picker";

type FillRequest = {
  type: "fd0.fill";
  credential: {
    username?: string;
    password: string;
  };
};

type OpenPickerRequest = {
  type: "fd0.openPicker";
};

type ShowNoticeRequest = {
  type: "fd0.showNotice";
  message: string;
  tone?: "neutral" | "error";
};

type PingRequest = {
  type: "fd0.ping";
};

type SelectionResponse = {
  ok: boolean;
  error?: string;
};

type MatchesResponse = {
  ok: boolean;
  result?: LoginLookup;
  error?: string;
};

type FD0ContentGlobal = typeof globalThis & {
  __fd0LoginController?: LoginController;
  __fd0LoginNotice?: LoginNotice;
};

const contentGlobal = globalThis as FD0ContentGlobal;
contentGlobal.__fd0LoginController?.dispose();
contentGlobal.__fd0LoginController = installLoginController(
  document,
  async () => {
    const response = await chrome.runtime.sendMessage<MatchesResponse>({
      type: "fd0.requestMatches",
    });
    if (!response?.ok || !response.result) {
      throw new Error(response?.error || "fd0 could not find logins for this site.");
    }
    return response.result;
  },
  async (origin, credentialId) => {
    const response = await chrome.runtime.sendMessage<SelectionResponse>({
      type: "fd0.selectCredential",
      origin,
      credentialId,
    });
    if (!response?.ok) {
      throw new Error(response?.error || "fd0 could not fill this login.");
    }
  },
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;
  if (isPingRequest(message)) {
    sendResponse({ ok: true });
    return;
  }
  if (isFillRequest(message)) {
    try {
      sendResponse({ ok: true, ...fillLogin(document, message.credential) });
    } catch {
      sendResponse({ ok: false });
    }
    return;
  }
  if (isShowNoticeRequest(message)) {
    contentGlobal.__fd0LoginNotice?.close();
    contentGlobal.__fd0LoginNotice = mountLoginNotice(
      document,
      message.message,
      message.tone,
    );
    sendResponse({ ok: true });
    return;
  }
  if (isOpenPickerRequest(message)) {
    void contentGlobal.__fd0LoginController?.open().then((ok) => sendResponse({ ok }));
    return true;
  }
});

function isFillRequest(message: unknown): message is FillRequest {
  if (!message || typeof message !== "object") return false;
  const request = message as Partial<FillRequest>;
  return (
    request.type === "fd0.fill" &&
    Boolean(request.credential) &&
    typeof request.credential?.password === "string" &&
    (request.credential.username === undefined ||
      typeof request.credential.username === "string")
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
