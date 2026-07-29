import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium, type BrowserContext, type Worker } from "playwright";

const root = join(import.meta.dir, "..");
const profile = await mkdtemp(join(tmpdir(), "fd0-browser-profile-"));
const certificateDirectory = await mkdtemp(join(tmpdir(), "fd0-browser-cert-"));
const keyPath = join(certificateDirectory, "key.pem");
const certificatePath = join(certificateDirectory, "certificate.pem");
const smokeTimeout = 20_000;
const loginPage = `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>fd0 browser smoke</title></head>
  <body>
    <form>
      <label>Username <input id="username" autocomplete="username"></label>
      <label>Password <input type="password" autocomplete="current-password"></label>
      <button type="submit">Sign in</button>
    </form>
  </body>
</html>`;

let context: BrowserContext | undefined;
let server: ReturnType<typeof Bun.serve> | undefined;

try {
  createCertificate(keyPath, certificatePath);
  server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    tls: {
      key: await readFile(keyPath),
      cert: await readFile(certificatePath),
    },
    fetch() {
      return new Response(loginPage, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    },
  });

  context = await chromium.launchPersistentContext(profile, {
    channel: "chromium",
    headless: true,
    ignoreHTTPSErrors: true,
    args: [
      `--disable-extensions-except=${join(root, "dist")}`,
      `--load-extension=${join(root, "dist")}`,
    ],
  });

  const worker = await extensionWorker(context);
  const page = await context.newPage();
  const origin = `https://127.0.0.1:${server.port}`;
  await page.goto(origin, { waitUntil: "domcontentloaded" });

  const discoveredTabId = await waitFor(async () =>
    worker.evaluate(async (expectedOrigin) => {
      const tabs = await chrome.tabs.query({});
      return tabs.find((tab) => tab.url?.startsWith(expectedOrigin))?.id;
    }, origin),
  );
  if (typeof discoveredTabId !== "number") {
    throw new Error("extension smoke could not resolve the login tab");
  }
  const tabId = discoveredTabId;
  await waitFor(() =>
    worker.evaluate(async (id) => {
      try {
        const response = (await chrome.tabs.sendMessage(id, {
          type: "fd0.ping",
        })) as { ok?: boolean };
        return response.ok === true;
      } catch {
        return false;
      }
    }, tabId),
  );

  await worker.evaluate(async (id) => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await chrome.scripting.executeScript({
        target: { tabId: id, frameIds: [0] },
        files: ["content.js"],
      });
    }
  }, tabId);
  await page.locator("#username").focus();
  await waitFor(
    () =>
      page.evaluate(
        () => document.querySelectorAll("[data-fd0-login-trigger]").length,
      ),
    (count) => count === 1,
  );

  console.log("fd0 browser extension smoke passed");
} finally {
  await context?.close();
  server?.stop(true);
  await Promise.all([
    rm(profile, { recursive: true, force: true }),
    rm(certificateDirectory, { recursive: true, force: true }),
  ]);
}

function createCertificate(keyPath: string, certificatePath: string): void {
  const result = spawnSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      keyPath,
      "-out",
      certificatePath,
      "-days",
      "1",
      "-subj",
      "/CN=127.0.0.1",
      "-addext",
      "subjectAltName=IP:127.0.0.1",
    ],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(result.stderr || "could not create smoke-test certificate");
  }
}

async function extensionWorker(context: BrowserContext): Promise<Worker> {
  return (
    context.serviceWorkers()[0] ??
    (await context.waitForEvent("serviceworker", { timeout: smokeTimeout }))
  );
}

async function waitFor<T>(
  read: () => Promise<T>,
  ready: (value: T) => boolean = Boolean,
): Promise<T> {
  const deadline = Date.now() + smokeTimeout;
  let lastValue: T;
  do {
    lastValue = await read();
    if (ready(lastValue)) return lastValue;
    await Bun.sleep(100);
  } while (Date.now() < deadline);
  throw new Error(`extension smoke timed out; last value: ${String(lastValue!)}`);
}
