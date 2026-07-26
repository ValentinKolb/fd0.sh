/**
 * Marketing screenshots for the website.
 *
 * Deliberately NOT named *.e2e.ts: playwright.config.ts matches that pattern,
 * and this needs a hand-seeded vault of fictional demo data that no CI machine
 * has. It is a tool, not a test.
 *
 * Seed the vault first (fictional data only — never a real one), then:
 *   bunx playwright test --config=/dev/null tests/shots.capture.ts
 * or point testMatch at it explicitly.
 */
import { expect, test, _electron as electron, type Page } from "@playwright/test";
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";

const require = createRequire(import.meta.url);
const electronPath = require("electron") as string;
const desktopRoot = resolve(import.meta.dirname, "..");
const repoRoot = resolve(desktopRoot, "..");
const buildDir = join(repoRoot, ".build", "desktop");
const shotHome = "/tmp/fd0-shots/home";
const outDir = join(repoRoot, "website", "public", "shots");

const environment: NodeJS.ProcessEnv = {
  ...process.env,
  NODE_ENV: "test",
  FD0_HOME: shotHome,
  FD0_SSH_SOCK: join(shotHome, "a.sock"),
  FD0_AGENT_BIN: join(buildDir, "fd0-agent"),
  FD0_BIN: join(buildDir, "fd0"),
  FD0_DESKTOP_BRIDGE_BIN: join(buildDir, "fd0-desktop-bridge"),
  FD0_DESKTOP_MODE: "isolated",
  FD0_DESKTOP_USER_DATA: join(shotHome, "desktop-ui"),
  FD0_AGENT_SYNC_DISABLED: "1",
  FD0_SSH_CONFIG_PATH: join(shotHome, "render", "ssh", "fd0.conf"),
  FD0_KUBE_CONFIG_PATH: join(shotHome, "render", "kube", "config.fd0"),
  FD0_KUBE_USER_CONFIG: join(shotHome, "render", "kube", "config"),
  FD0_TALOS_CONFIG_PATH: join(shotHome, "render", "talos", "config.fd0"),
  FD0_TALOS_USER_CONFIG: join(shotHome, "render", "talos", "config"),
};

/** Retina-ish canvas: the site renders these at half size. */
const SIZE = { width: 1440, height: 900 };

async function shot(page: Page, name: string): Promise<void> {
  await page.waitForTimeout(350); // let transitions settle
  await page.screenshot({ path: join(outDir, `${name}.png`) });
}

test("captures marketing screenshots", async () => {
  mkdirSync(outDir, { recursive: true });
  const app = await electron.launch({
    executablePath: electronPath,
    args: [join(desktopRoot, "out", "main", "index.js")],
    env: environment,
  });
  try {
    const page = await app.firstWindow();
    await app.evaluate(({ BrowserWindow }, size) => {
      const window = BrowserWindow.getAllWindows()[0]!;
      window.setSize(size.width, size.height);
    }, SIZE);

    // Unlock.
    await expect(page.locator(".auth-card")).toBeVisible({ timeout: 20_000 });
    await shot(page, "unlock");
    const passphrase = page.getByLabel("Passphrase", { exact: true });
    await passphrase.click();
    // Clear first: the field can carry text from a previous launch, and typing
    // would otherwise append to it.
    await passphrase.press("Meta+a");
    await passphrase.press("Backspace");
    await passphrase.pressSequentially("screenshot-demo-passphrase");
    await expect(passphrase).toHaveValue("screenshot-demo-passphrase");
    await page.getByRole("button", { name: /^Unlock$/ }).click();
    try {
      await expect(page.locator(".app")).toBeVisible({ timeout: 20_000 });
    } catch {
      throw new Error(`unlock did not land. body: ${await page.locator("body").innerText()}`);
    }

    // The main three-pane view with an item open.
    await page.locator(".item-row").filter({ hasText: "Cloudflare" }).first().click();
    await expect(page.locator(".detail-pane")).toBeVisible();
    await shot(page, "vault");

    // Command palette.
    await page.keyboard.press("Meta+k");
    await expect(page.locator(".palette")).toBeVisible();
    await page.locator(".palette-input input").fill("clou");
    await shot(page, "palette");
    await page.keyboard.press("Escape");

    // SSH hosts — the part no other password manager has.
    await page.getByRole("button", { name: "SSH", exact: true }).click();
    await expect(page.locator(".item-row").first()).toBeVisible();
    await page.locator(".item-row").first().click();
    await shot(page, "ssh");

    // Generator.
    await page.getByRole("button", { name: "Password generator", exact: true }).click();
    await expect(page.locator(".generator-panel")).toBeVisible();
    await shot(page, "generator");
  } finally {
    await app.close();
  }
});
