export {};

const nativeHost = "sh.fd0.browser";

type NativeError = {
  code: string;
  message: string;
};

type NativeResponse<T> = {
  id?: string;
  ok: boolean;
  result?: T;
  error?: NativeError;
};

type Match = {
  id: string;
  title: string;
  username?: string;
};

type MatchesResult = {
  credentials: Match[];
};

type LoginCredential = {
  username?: string;
  password: string;
};

type FillResult = {
  ok: boolean;
  usernameFilled?: boolean;
  passwordFilled?: boolean;
};

type SelectionRequest = {
  type: "fd0.selectCredential";
  origin: string;
  credentialId: string;
};

type MatchesRequest = {
  type: "fd0.requestMatches";
};

type SelectionResponse = {
  ok: boolean;
  error?: string;
};

type MatchesResponse = {
  ok: boolean;
  result?: {
    origin: string;
    credentials: Match[];
  };
  error?: string;
};

chrome.action.onClicked.addListener(async (tab) => {
  if (tab.id === undefined) return;
  const tabId = tab.id;
  try {
    const opened = await chrome.tabs.sendMessage<{ ok?: boolean }>(tabId, {
      type: "fd0.openPicker",
    });
    await showStatus(
      tabId,
      opened?.ok ? "✓" : "0",
      opened?.ok ? "#18794e" : "#6b7280",
      opened?.ok ? "Choose an fd0 login" : "No fd0 login form is available",
    );
  } catch {
    await showStatus(
      tabId,
      "!",
      "#b91c1c",
      "Reload this HTTPS page before using fd0",
    );
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;
  if (isMatchesRequest(message)) {
    void handleMatches(sender)
      .then(sendResponse)
      .catch((error: unknown) =>
        sendResponse({
          ok: false,
          error: errorMessage(error, "fd0 could not find logins for this site."),
        } satisfies MatchesResponse),
      );
    return true;
  }
  if (isSelectionRequest(message)) {
    void handleSelection(message, sender)
      .then(sendResponse)
      .catch((error: unknown) =>
        sendResponse({
          ok: false,
          error: errorMessage(error, "fd0 could not fill this login."),
        } satisfies SelectionResponse),
      );
    return true;
  }
});

async function handleMatches(
  sender: chrome.runtime.MessageSender,
): Promise<MatchesResponse> {
  const origin = senderHTTPSOrigin(sender);
  const matches = await nativeRequest({
    id: crypto.randomUUID(),
    operation: "matches",
    origin,
  });
  if (!isMatchesResult(matches)) {
    throw protocolError();
  }
  return {
    ok: true,
    result: {
      origin,
      credentials: matches.credentials,
    },
  };
}

async function handleSelection(
  request: SelectionRequest,
  sender: chrome.runtime.MessageSender,
): Promise<SelectionResponse> {
  const tabId = sender.tab?.id;
  const documentId = sender.documentId;
  const senderOrigin = senderHTTPSOrigin(sender);
  if (
    tabId === undefined ||
    !documentId ||
    senderOrigin !== request.origin
  ) {
    throw {
      code: "origin_changed",
      message: "This page changed before fd0 could fill it.",
    } satisfies NativeError;
  }

  const credential = await nativeRequest({
    id: crypto.randomUUID(),
    operation: "reveal",
    origin: senderOrigin,
    credentialId: request.credentialId,
  });
  if (!isLoginCredential(credential)) {
    throw protocolError();
  }
  let filled: FillResult;
  try {
    filled = await chrome.tabs.sendMessage<FillResult>(
      tabId,
      {
        type: "fd0.fill",
        credential,
      },
      { documentId },
    );
  } catch {
    throw {
      code: "origin_changed",
      message: "This page changed before fd0 could fill it.",
    } satisfies NativeError;
  }

  if (!filled?.ok || !filled.passwordFilled) {
    throw {
      code: "form_missing",
      message: "No visible login form was found.",
    } satisfies NativeError;
  }
  await showStatus(tabId, "✓", "#18794e", "Filled login with fd0");
  return { ok: true };
}

function isSelectionRequest(message: unknown): message is SelectionRequest {
  if (!message || typeof message !== "object") return false;
  const request = message as Partial<SelectionRequest>;
  return (
    request.type === "fd0.selectCredential" &&
    typeof request.origin === "string" &&
    typeof request.credentialId === "string" &&
    request.credentialId.length > 0
  );
}

function isMatchesRequest(message: unknown): message is MatchesRequest {
  return Boolean(
    message &&
      typeof message === "object" &&
      (message as Partial<MatchesRequest>).type === "fd0.requestMatches",
  );
}

function senderHTTPSOrigin(sender: chrome.runtime.MessageSender): string {
  const origin = httpsOrigin(sender.url ?? sender.tab?.url ?? "");
  if (sender.frameId !== 0 || !origin) {
    throw {
      code: "origin_changed",
      message: "fd0 only fills the top frame of HTTPS pages.",
    } satisfies NativeError;
  }
  return origin;
}

function httpsOrigin(rawURL: string): string | undefined {
  try {
    const url = new URL(rawURL);
    return url.protocol === "https:" ? url.origin : undefined;
  } catch {
    return undefined;
  }
}

async function nativeRequest(request: Record<string, unknown>): Promise<unknown> {
  let response: NativeResponse<unknown>;
  try {
    response = await chrome.runtime.sendNativeMessage<NativeResponse<unknown>>(
      nativeHost,
      request,
    );
  } catch {
    throw {
      code: "unavailable",
      message: "fd0 browser integration is not available",
    } satisfies NativeError;
  }
  if (
    !response ||
    response.id !== request.id ||
    !response.ok ||
    response.result === undefined
  ) {
    if (
      response?.id === request.id &&
      response.error &&
      isNativeError(response.error)
    ) {
      throw response.error;
    }
    throw (
      {
        code: "request_failed",
        message: "fd0 could not complete this request",
      } satisfies NativeError
    );
  }
  return response.result;
}

function isMatchesResult(value: unknown): value is MatchesResult {
  if (!value || typeof value !== "object") return false;
  const credentials = (value as Partial<MatchesResult>).credentials;
  return (
    Array.isArray(credentials) &&
    credentials.every(
      (credential) =>
        credential &&
        typeof credential === "object" &&
        typeof credential.id === "string" &&
        credential.id.length > 0 &&
        typeof credential.title === "string" &&
        (credential.username === undefined ||
          typeof credential.username === "string"),
    )
  );
}

function isLoginCredential(value: unknown): value is LoginCredential {
  if (!value || typeof value !== "object") return false;
  const credential = value as Partial<LoginCredential>;
  return (
    typeof credential.password === "string" &&
    (credential.username === undefined ||
      typeof credential.username === "string")
  );
}

function isNativeError(value: unknown): value is NativeError {
  if (!value || typeof value !== "object") return false;
  const error = value as Partial<NativeError>;
  return typeof error.code === "string" && typeof error.message === "string";
}

function protocolError(): NativeError {
  return {
    code: "invalid_response",
    message: "Update fd0 and reload this extension.",
  };
}

function errorMessage(error: unknown, fallback: string): string {
  return isNativeError(error) &&
    error.code !== "request_failed" &&
    error.message
    ? error.message
    : fallback;
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
