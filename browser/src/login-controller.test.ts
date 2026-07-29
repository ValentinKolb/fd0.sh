import { describe, expect, test } from "bun:test";
import { Window } from "happy-dom";

import { installLoginController } from "./login-controller";

function loginPage(): {
  window: Window;
  document: Document;
  username: HTMLInputElement;
  password: HTMLInputElement;
} {
  const window = new Window({ url: "https://example.com/login" });
  const document = window.document as unknown as Document;
  const username = document.createElement("input");
  username.autocomplete = "username";
  const password = document.createElement("input");
  password.type = "password";
  password.autocomplete = "current-password";
  for (const input of [username, password]) {
    input.style.display = "block";
    input.style.visibility = "visible";
    input.style.opacity = "1";
    input.getBoundingClientRect = () =>
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
    document.body.append(input);
  }
  Object.assign(globalThis, {
    Node: window.Node,
    getComputedStyle: window.getComputedStyle.bind(window),
  });
  return { window, document, username, password };
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
}

describe("login controller", () => {
  test("opens fd0 automatically when a matching login field receives focus", async () => {
    const { window, document, username } = loginPage();
    let lookups = 0;
    const controller = installLoginController(
      document,
      async () => {
        lookups += 1;
        return {
          origin: "https://example.com",
          credentials: [{ id: "opaque", title: "Example", username: "user" }],
        };
      },
      async () => {},
    );

    username.dispatchEvent(
      new window.FocusEvent("focusin", { bubbles: true }) as unknown as Event,
    );
    await settle();

    expect(lookups).toBe(1);
    expect(document.querySelectorAll("[data-fd0-login-picker]")).toHaveLength(1);
    expect(document.querySelectorAll("[data-fd0-login-trigger]")).toHaveLength(1);
    controller.dispose();
    await window.close();
  });

  test("stays quiet when the current origin has no fd0 login", async () => {
    const { window, document, password } = loginPage();
    const controller = installLoginController(
      document,
      async () => ({ origin: "https://example.com", credentials: [] }),
      async () => {},
    );

    password.dispatchEvent(
      new window.FocusEvent("focusin", { bubbles: true }) as unknown as Event,
    );
    await settle();

    expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
    expect(document.querySelector("[data-fd0-login-trigger]")).toBeNull();
    controller.dispose();
    await window.close();
  });

  test("keeps a retry affordance when fd0 is locked", async () => {
    const { window, document, username } = loginPage();
    const controller = installLoginController(
      document,
      async () => {
        throw new Error("Unlock fd0 to fill this login.");
      },
      async () => {},
    );

    username.dispatchEvent(
      new window.FocusEvent("focusin", { bubbles: true }) as unknown as Event,
    );
    await settle();

    expect(document.querySelector("[data-fd0-login-picker]")).toBeNull();
    expect(document.querySelector("[data-fd0-login-trigger]")).not.toBeNull();
    controller.dispose();
    await window.close();
  });

  test("shows a locked state after an explicit retry and succeeds after unlock", async () => {
    const { window, document, username } = loginPage();
    let unlocked = false;
    const controller = installLoginController(
      document,
      async () => {
        if (!unlocked) throw new Error("Unlock fd0 to fill this login.");
        return {
          origin: "https://example.com",
          credentials: [{ id: "opaque", title: "Example", username: "user" }],
        };
      },
      async () => {},
    );

    username.dispatchEvent(
      new window.FocusEvent("focusin", { bubbles: true }) as unknown as Event,
    );
    await settle();
    expect(document.querySelector("[data-fd0-login-trigger]")).not.toBeNull();
    await controller.open();
    await settle();

    const promptHost = document.querySelector<HTMLElement>("[data-fd0-login-prompt]");
    expect(promptHost).not.toBeNull();
    unlocked = true;
    await controller.open();
    await settle();

    expect(document.querySelector("[data-fd0-login-prompt]")).toBeNull();
    expect(document.querySelector("[data-fd0-login-picker]")).not.toBeNull();
    controller.dispose();
    await window.close();
  });
});
