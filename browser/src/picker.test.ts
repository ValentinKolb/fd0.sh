import { describe, expect, test } from "bun:test";
import { Window } from "happy-dom";

import {
  mountLoginNotice,
  mountLoginPicker,
  mountLoginPrompt,
  mountLoginTrigger,
  type LoginMatch,
} from "./picker";

const matches: LoginMatch[] = [
  { id: "first", title: "Primary", username: "first@example.com" },
  { id: "second", title: "Work", username: "work@example.com" },
];

function testPage(): {
  window: Window;
  document: Document;
  anchor: HTMLInputElement;
} {
  const window = new Window({ url: "https://example.com/login" });
  const document = window.document as unknown as Document;
  const anchor = document.createElement("input");
  anchor.type = "text";
  anchor.getBoundingClientRect = () =>
    ({
      x: 40,
      y: 40,
      top: 40,
      left: 40,
      right: 340,
      bottom: 80,
      width: 300,
      height: 40,
      toJSON: () => ({}),
    }) as DOMRect;
  document.body.append(anchor);
  return { window, document, anchor };
}

describe("login picker", () => {
  test("renders untrusted metadata as text and selects a login", async () => {
    const { document, anchor } = testPage();
    let selected = "";
    const picker = mountLoginPicker(
      document,
      anchor,
      [
        matches[0],
        { id: "unsafe", title: "<img src=x onerror=alert(1)>", username: "<b>user</b>" },
      ],
      async (credentialId) => {
        selected = credentialId;
      },
    );

    expect(picker.root.querySelector("img")).toBeNull();
    const options = picker.root.querySelectorAll<HTMLButtonElement>(".option");
    expect(options).toHaveLength(2);
    options[1].click();
    await Promise.resolve();

    expect(selected).toBe("unsafe");
    expect(picker.host.isConnected).toBe(false);
  });

  test("supports keyboard selection and wraps between options", async () => {
    const { window, document, anchor } = testPage();
    let selected = "";
    const picker = mountLoginPicker(document, anchor, matches, async (credentialId) => {
      selected = credentialId;
    });
    const options = picker.root.querySelectorAll<HTMLButtonElement>(".option");

    options[0].dispatchEvent(
      new window.KeyboardEvent("keydown", {
        key: "ArrowUp",
        bubbles: true,
      }) as unknown as Event,
    );
    expect(options[1].getAttribute("aria-selected")).toBe("true");
    options[1].dispatchEvent(
      new window.KeyboardEvent("keydown", {
        key: "Enter",
        bubbles: true,
      }) as unknown as Event,
    );
    await Promise.resolve();

    expect(selected).toBe("second");
    expect(picker.host.isConnected).toBe(false);
  });

  test("keeps the picker open and announces a friendly selection error", async () => {
    const { document, anchor } = testPage();
    const picker = mountLoginPicker(document, anchor, matches, async () => {
      throw new Error("Unlock fd0 to fill this login.");
    });
    const option = picker.root.querySelector<HTMLButtonElement>(".option");
    option?.click();
    await Promise.resolve();
    await Promise.resolve();

    expect(picker.host.isConnected).toBe(true);
    expect(picker.root.querySelector(".status")?.textContent).toBe(
      "Unlock fd0 to fill this login.",
    );
    expect(option?.disabled).toBe(false);
    picker.close();
  });

  test("closes on Escape and restores focus to the form", () => {
    const { window, document, anchor } = testPage();
    const picker = mountLoginPicker(document, anchor, matches, async () => {});
    const option = picker.root.querySelector<HTMLButtonElement>(".option");
    option?.dispatchEvent(
      new window.KeyboardEvent("keydown", {
        key: "Escape",
        bubbles: true,
      }) as unknown as Event,
    );

    expect(picker.host.isConnected).toBe(false);
    expect(document.activeElement).toBe(anchor);
  });
});

describe("login notice", () => {
  test("renders status text without adding page markup", () => {
    const { document } = testPage();
    const notice = mountLoginNotice(document, "<b>Unlock fd0</b>", "error");

    expect(notice.host.isConnected).toBe(true);
    expect(notice.host.querySelector("b")).toBeNull();
    notice.close();
    expect(notice.host.isConnected).toBe(false);
  });
});

describe("login trigger", () => {
  test("reopens fd0 without exposing a page-owned click target", () => {
    const { document, anchor } = testPage();
    let activations = 0;
    const trigger = mountLoginTrigger(document, anchor, () => {
      activations += 1;
    });

    trigger.root.querySelector<HTMLButtonElement>("button")?.click();

    expect(activations).toBe(1);
    expect(trigger.host.isConnected).toBe(true);
    expect(trigger.host.querySelector("button")).toBeNull();
    trigger.close();
  });

  test("shows a busy state while fd0 is opening", () => {
    const { document, anchor } = testPage();
    const trigger = mountLoginTrigger(document, anchor, () => {});

    trigger.setBusy(true);
    expect(
      trigger.root.querySelector<HTMLButtonElement>("button")?.getAttribute("aria-busy"),
    ).toBe("true");
    expect(trigger.root.querySelector<HTMLButtonElement>("button")?.disabled).toBe(true);
    trigger.close();
  });
});

describe("login prompt", () => {
  test("shows a retry action for a locked vault", () => {
    const { document, anchor } = testPage();
    let retries = 0;
    const prompt = mountLoginPrompt(
      document,
      anchor,
      "Vault locked",
      "Unlock fd0 in the desktop app, then try again.",
      () => {
        retries += 1;
      },
    );

    expect(prompt.root.querySelector(".heading")?.textContent).toBe("Vault locked");
    prompt.root.querySelector<HTMLButtonElement>(".retry")?.click();
    expect(retries).toBe(1);
    expect(prompt.host.isConnected).toBe(false);
  });
});
