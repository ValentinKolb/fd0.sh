import { expect, test, _electron as electron, type Locator, type Page } from "@playwright/test";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const require = createRequire(import.meta.url);
const electronPath = require("electron") as string;
const desktopRoot = resolve(import.meta.dirname, "..");
const repoRoot = resolve(desktopRoot, "..");
const buildDir = join(repoRoot, ".build", "desktop");
const testHome = join(tmpdir(), `fd0-desktop-e2e-${process.pid}`);
const testSock = join(tmpdir(), `fd0-desktop-e2e-ssh-${process.pid}.sock`);
const recoveryPath = join(tmpdir(), `fd0-desktop-e2e-recovery-${process.pid}.cbor`);
const attachmentPath = join(tmpdir(), `fd0-desktop-e2e-attachment-${process.pid}.txt`);
const restoreHome = join(tmpdir(), `fd0-desktop-e2e-restore-${process.pid}`);
const restoreSock = join(tmpdir(), `fd0-desktop-e2e-restore-ssh-${process.pid}.sock`);
const environment: NodeJS.ProcessEnv = {
  ...process.env,
  NODE_ENV: "test",
  FD0_HOME: testHome,
  FD0_SSH_SOCK: testSock,
  FD0_AGENT_BIN: join(buildDir, "fd0-agent"),
  FD0_BIN: join(buildDir, "fd0"),
  FD0_DESKTOP_BRIDGE_BIN: join(buildDir, "fd0-desktop-bridge"),
  FD0_DESKTOP_MODE: "isolated",
  FD0_DESKTOP_USER_DATA: join(testHome, "desktop-ui"),
  FD0_AGENT_SYNC_DISABLED: "1",
};

function run(command: string, args: string[]): void {
  const result = spawnSync(command, args, { cwd: repoRoot, env: environment, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${command} failed:\n${result.stdout}\n${result.stderr}`);
  }
}

async function dragWithPointer(page: Page, source: Locator, target: Locator): Promise<void> {
  await source.scrollIntoViewIfNeeded();
  await target.scrollIntoViewIfNeeded();
  const sourceBox = await source.boundingBox();
  if (!sourceBox) throw new Error("Drag source is not visible");
  const start = { x: sourceBox.x + sourceBox.width / 2, y: sourceBox.y + sourceBox.height / 2 };
  await page.mouse.move(start.x, start.y);
  await page.mouse.down();
  await page.mouse.move(start.x + 10, start.y + 8, { steps: 3 });
  await expect(target).toHaveCSS("height", "38px");
  const targetBox = await target.boundingBox();
  if (!targetBox) throw new Error("Drag target is not visible");
  const end = { x: targetBox.x + targetBox.width / 2, y: targetBox.y + targetBox.height / 2 };
  await page.mouse.move(end.x, end.y, { steps: 8 });
  await page.mouse.up();
}

test.beforeAll(() => {
  run(join(buildDir, "fd0-desktop-dev-seed"), []);
});

test.afterAll(() => {
  if (existsSync(join(buildDir, "fd0"))) {
    spawnSync(join(buildDir, "fd0"), ["agent", "stop"], { cwd: repoRoot, env: environment });
  }
  const marker = join(testHome, ".desktop-isolated");
  if (existsSync(marker) && readFileSync(marker, "utf8") === "fd0-desktop-isolated-v1\n") {
    rmSync(testHome, { recursive: true });
  }
  rmSync(testSock, { force: true });
  rmSync(recoveryPath, { force: true });
  rmSync(attachmentPath, { force: true });
  rmSync(restoreSock, { force: true });
  if (existsSync(join(restoreHome, ".desktop-isolated")) && readFileSync(join(restoreHome, ".desktop-isolated"), "utf8") === "fd0-desktop-isolated-v1\n") {
    rmSync(restoreHome, { recursive: true });
  }
});

test("runs the isolated desktop vault end to end", async () => {
  const app = await electron.launch({
    executablePath: electronPath,
    args: [join(desktopRoot, "out", "main", "index.js")],
    env: environment,
  });
  const errors: string[] = [];
  try {
    const page = await app.firstWindow();
    expect(page.url()).toBe("fd0-app://app/index.html");
    page.on("console", (message) => {
      if (message.type() === "error") errors.push(message.text());
    });
    page.on("pageerror", (error) => errors.push(error.message));
    await page.waitForTimeout(500);
    if ((await page.getByRole("button", { name: /Passwords/ }).count()) === 0) {
      throw new Error(`Desktop UI did not initialize. Body: ${await page.locator("body").innerText()} Errors: ${errors.join(" | ")}`);
    }
    await expect(page.getByRole("button", { name: /Passwords/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /^GitHub valentin@example.com/ })).toBeVisible();
    await expect(page.getByText("fd0", { exact: true }).first()).toBeVisible();
    const security = await app.evaluate(({ BrowserWindow }) => {
      const window = BrowserWindow.getAllWindows()[0]!;
      const preferences = window.webContents.getLastWebPreferences();
      return {
        contextIsolation: preferences.contextIsolation,
        nodeIntegration: preferences.nodeIntegration,
        sandbox: preferences.sandbox,
      };
    });
    expect(security).toEqual({
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    });
    expect(await page.evaluate(() => ({
      require: typeof (window as unknown as { require?: unknown }).require,
      process: typeof (window as unknown as { process?: unknown }).process,
      development: window.fd0.development,
    }))).toEqual({ require: "undefined", process: "undefined", development: true });
    expect(await page.evaluate(() => window.fd0.status())).toMatchObject({
      unlocked: true,
      idleTimeoutMillis: 60 * 60_000,
      maxLifetimeMillis: 12 * 60 * 60_000,
    });

    const typeTriggerGap = await page.locator(".type-picker-button").evaluate((button) => {
      const count = button.querySelector(".sidebar-count")!.getBoundingClientRect();
      const chevron = button.querySelector("svg:last-child")!.getBoundingClientRect();
      return chevron.left - count.right;
    });
    expect(typeTriggerGap).toBeGreaterThanOrEqual(6);
    await page.locator(".type-picker-button").click();
    const selectedType = page.getByRole("option", { name: /Passwords/ });
    await expect(selectedType.locator("svg")).toHaveCount(1);
    expect(await selectedType.locator("svg").evaluate((icon) => getComputedStyle(icon).color)).toBe("rgb(255, 176, 0)");
    await selectedType.click();

    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]!.setSize(860, 600));
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]!.setSize(1180, 780));

    await page.getByRole("button", { name: "Password generator" }).click();
    await expect(page.getByRole("heading", { name: "Password generator" })).toBeVisible();
    await page.getByRole("radio", { name: "Memorable" }).click();
    await expect.poll(async () => page.locator(".generated-value code").innerText()).toMatch(/-/);
    await page.getByRole("radio", { name: "PIN" }).click();
    await page.getByLabel("Digits").fill("8");
    await expect.poll(async () => page.locator(".generated-value code").innerText()).toMatch(/^\d{8}$/);
    await page.getByRole("button", { name: "Support" }).click();
    await expect(page.getByRole("heading", { name: "Support" })).toBeVisible();
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
    await page.locator(".type-picker-button").click();
    await page.getByRole("option", { name: /Passwords/ }).click();

    const personalVault = page.locator(".vault-row").filter({ hasText: "Personal" });
    await personalVault.hover();
    await personalVault.getByRole("button", { name: "Actions for Personal" }).click();
    const vaultMenuInset = await page.locator(".vault-context-menu").evaluate((menu) => {
      const sidebar = document.querySelector(".sidebar")!.getBoundingClientRect();
      const bounds = menu.getBoundingClientRect();
      return sidebar.right - bounds.right;
    });
    expect(vaultMenuInset).toBeGreaterThanOrEqual(10);
    await page.getByRole("menuitem", { name: "Share vault…" }).click();
    const accessDialog = page.getByRole("dialog", { name: "Access to Personal" });
    await expect(accessDialog).toBeVisible();
    await page.screenshot({ path: test.info().outputPath("fd0-share-access.png") });
    await app.evaluate(({ dialog }) => {
      const state = globalThis as typeof globalThis & { __fd0Prompts?: string[] };
      state.__fd0Prompts = [];
      Object.defineProperty(dialog, "showMessageBox", {
        configurable: true,
        value: async (...args: unknown[]) => {
          const options = args.at(-1) as { message?: string };
          state.__fd0Prompts?.push(options.message ?? "");
          return { response: 1, checkboxChecked: false };
        },
      });
    });
    const bennyContact = accessDialog.locator(".access-row").filter({ hasText: "Benny" });
    await bennyContact.getByRole("button", { name: "Add", exact: true }).click();
    await expect(page.getByText("Shared Personal with Benny.", { exact: true })).toBeVisible();
    expect(await app.evaluate(() => {
      const state = globalThis as typeof globalThis & { __fd0Prompts?: string[] };
      return state.__fd0Prompts?.at(-1);
    })).toBe("Give Benny access to Personal?");
    await expect(accessDialog.locator(".access-row").filter({ hasText: "Benny" }).getByRole("button", { name: "Remove" })).toBeVisible();

    await accessDialog.getByRole("button", { name: "New contact" }).click();
    await expect(page.getByRole("heading", { name: "Add a new contact" })).toBeVisible();
    await page.getByLabel("Identity card URL").fill(readFileSync(join(testHome, ".desktop-demo-contact-card"), "utf8").trim());
    await page.getByLabel("Contact name").fill("Carol");
    await page.getByRole("button", { name: "Review card" }).click();
    await expect(page.getByText("Safety number", { exact: true })).toBeVisible();
    await page.screenshot({ path: test.info().outputPath("fd0-share-card-review.png") });
    await page.getByRole("button", { name: "Trust and share…" }).click();
    await expect(page.getByText("Trusted Carol and shared Personal.", { exact: true })).toBeVisible();
    const carolMember = accessDialog.locator(".access-row").filter({ hasText: "Carol" });
    await expect(carolMember.getByRole("button", { name: "Remove" })).toBeVisible();
    await carolMember.getByRole("button", { name: "Remove" }).click();
    await expect(page.getByText("Removed Carol from Personal.", { exact: true })).toBeVisible();
    await expect(accessDialog.locator(".access-row").filter({ hasText: "Carol" }).getByRole("button", { name: "Remove" })).toHaveCount(0);
    await accessDialog.getByRole("button", { name: "Done" }).click();

    await page.locator(".type-picker-button").click();
    await page.getByRole("option", { name: /SSH/ }).click();
    await expect(page.getByRole("button", { name: /^fd0 administrator@/ })).toBeVisible();
    await expect(page.getByText("talos-gw", { exact: true })).toBeVisible();

    await page.locator(".type-picker-button").click();
    await page.getByRole("option", { name: /Secrets/ }).click();
    await expect(page.getByText("GHCR_TOKEN", { exact: true })).toBeVisible();
    await page.getByText("Show all", { exact: true }).click();
    await expect(page.getByRole("checkbox", { name: "Show all" })).toBeChecked();
    await expect(page.getByText("GitHub", { exact: true })).toBeVisible();
    await expect(page.getByText("Generic stored record", { exact: true })).toBeVisible();

    await page.locator(".type-picker-button").click();
    await page.getByRole("option", { name: /Passwords/ }).click();
    await page.getByRole("button", { name: /^GitHub valentin@example.com/ }).click();
    await expect(page.locator(".detail-actions > button, .detail-actions > .action-menu")).toHaveCount(2);
    await expect(page.locator(".field-value").filter({ hasText: "valentin@example.com" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Show password in large type" })).toBeVisible();
    await page.getByRole("button", { name: "More actions" }).click();
    await page.getByRole("menuitem", { name: "Show in large type" }).click();
    const largeType = page.getByRole("dialog", { name: "password" });
    await expect(largeType).toBeVisible();
    await expect(largeType.locator(".large-type-character")).toHaveCount(Array.from("d3v-Vault!GitHub-2026").length);
    await largeType.getByRole("button", { name: "Close large type" }).click();
    await page.getByRole("button", { name: "Reveal password" }).click();
    await expect(page.getByText("d3v-Vault!GitHub-2026", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Remove from favorites" })).toBeVisible();
    await page.getByRole("button", { name: "Remove from favorites" }).click();
    await expect(page.getByRole("button", { name: "Add to favorites" })).toBeVisible();
    await page.getByRole("button", { name: "Add to favorites" }).click();
    await expect(page.getByRole("button", { name: "Remove from favorites" })).toBeVisible();

    await app.evaluate(({ dialog }, path) => {
      Object.defineProperty(dialog, "showSaveDialog", {
        configurable: true,
        value: async () => ({ canceled: false, filePath: path }),
      });
    }, attachmentPath);
    await page.getByRole("button", { name: "Save backup file" }).click();
    await expect(page.getByText("Attachment saved.", { exact: true })).toBeVisible();
    expect(readFileSync(attachmentPath, "utf8")).toBe("fd0 desktop recovery demo\n");
    expect(statSync(attachmentPath).mode & 0o777).toBe(0o600);

    await page.getByRole("button", { name: "More actions" }).click();
    await page.getByRole("menuitem", { name: "Edit item" }).click();
    let passEditor = page.getByRole("dialog", { name: "Edit password" });
    await expect(passEditor).toBeVisible();
    expect((await passEditor.boundingBox())!.height).toBeGreaterThanOrEqual(730);
    await expect(passEditor.getByRole("button", { name: "Save changes" })).toBeVisible();

    const rootAddField = passEditor.locator(".editor-fields > .add-field-control");
    await rootAddField.getByRole("button", { name: "Add field" }).click();
    await passEditor.getByLabel("text value").last().fill("production");
    await passEditor.getByLabel("Field name").last().fill("environment");
    await rootAddField.getByLabel("New field type").selectOption("section");
    await rootAddField.getByRole("button", { name: "Add field" }).click();
    await passEditor.getByLabel("Field name").last().fill("Operations");

    const environmentField = passEditor.locator('.pass-field-editor[data-field-name="environment"]');
    const operationsField = passEditor.locator('.pass-field-editor[data-field-name="Operations"]');
    const emptyOperationsSlot = operationsField.locator('.section-children .pass-field-drop-slot[data-drop-index="0"]');
    await dragWithPointer(page, environmentField.locator(".pass-field-drag-handle"), emptyOperationsSlot);
    await expect(operationsField.locator('.section-children .pass-field-editor[data-field-name="environment"]')).toBeVisible();

    const rootFirstSlot = passEditor.locator('.editor-fields > .pass-field-list > .pass-field-drop-slot[data-drop-parent="root"][data-drop-index="0"]');
    const operationsHandle = operationsField.locator(":scope > .pass-field-drag-handle");
    await operationsHandle.focus();
    await page.keyboard.press("Space");
    await page.keyboard.press("ArrowUp");
    await expect(rootFirstSlot).toHaveAttribute("data-dnd-over", "true");
    await page.screenshot({ path: test.info().outputPath("fd0-edit-password-dragging.png") });
    await page.keyboard.press("Enter");
    await expect(passEditor.locator(".editor-fields > .pass-field-list > .pass-field-editor").first()).toHaveAttribute("data-field-name", "Operations");

    const passwordField = passEditor.locator('.pass-field-editor[data-field-name="password"]');
    await passwordField.getByRole("button", { name: "Password generator options" }).click();
    const inlineGenerator = passwordField.getByRole("group", { name: "Password generator options" });
    await expect(inlineGenerator).toBeVisible();
    expect(await inlineGenerator.evaluate((element) => getComputedStyle(element).position)).toBe("static");
    await page.screenshot({ path: test.info().outputPath("fd0-edit-password-generator.png") });
    await inlineGenerator.getByRole("button", { name: "Cancel" }).click();

    await passEditor.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Changes saved.", { exact: true })).toBeVisible();
    await expect(page.getByText("production", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "More actions" }).click();
    await page.getByRole("menuitem", { name: "Edit item" }).click();
    passEditor = page.getByRole("dialog", { name: "Edit password" });
    await expect(passEditor.locator(".editor-fields > .pass-field-list > .pass-field-editor").first()).toHaveAttribute("data-field-name", "Operations");
    await expect(passEditor.locator('.pass-field-editor[data-field-name="Operations"] .section-children .pass-field-editor[data-field-name="environment"]')).toBeVisible();
    await page.screenshot({ path: test.info().outputPath("fd0-edit-password-reordered.png") });
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]!.setSize(860, 600));
    expect((await passEditor.boundingBox())!.height).toBeGreaterThanOrEqual(550);
    await expect(passEditor.getByRole("button", { name: "Save changes" })).toBeVisible();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    await page.screenshot({ path: test.info().outputPath("fd0-edit-password-small.png") });
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0]!.setSize(1180, 780));
    await passEditor.getByRole("button", { name: "Close" }).click();

    await page.getByRole("button", { name: "Add", exact: true }).click();
    let newItemDialog = page.getByRole("dialog", { name: "New item" });
    await newItemDialog.locator(".add-kind-picker > button").click();
    for (const label of ["Password", "Secret", "SSH host", "SSH key", "Kubernetes", "Talos"]) {
      await expect(newItemDialog.getByRole("menuitemradio", { name: new RegExp(`^${label}`) })).toBeVisible();
    }
    await newItemDialog.getByRole("menuitemradio", { name: /^SSH host/ }).click();
    const sshFieldGeometry = await newItemDialog.evaluate((dialog) => {
      const host = dialog.querySelector<HTMLInputElement>('input[placeholder="server.example.com"]')!.getBoundingClientRect();
      const user = dialog.querySelector<HTMLInputElement>('input[autocomplete="username"]')!.getBoundingClientRect();
      const port = dialog.querySelector<HTMLInputElement>('input[type="number"]')!.getBoundingClientRect();
      const userLabel = dialog.querySelector<HTMLInputElement>('input[autocomplete="username"]')!.closest("label")!.querySelector("span")!.getBoundingClientRect();
      return { labelGap: userLabel.top - host.bottom, aligned: Math.abs(user.top - port.top) };
    });
    expect(sshFieldGeometry.labelGap).toBeGreaterThanOrEqual(14);
    expect(sshFieldGeometry.aligned).toBeLessThanOrEqual(1);
    await page.screenshot({ path: test.info().outputPath("fd0-add-ssh-spacing.png") });
    await newItemDialog.locator(".add-kind-picker > button").click();
    await newItemDialog.getByRole("menuitemradio", { name: /^Password/ }).click();
    await newItemDialog.getByLabel("Title", { exact: true }).fill("DESKTOP_E2E_LOGIN");
    const vaultSelectInset = await newItemDialog.locator(".add-vault-control .select-control").evaluate((control) => {
      const bounds = control.getBoundingClientRect();
      const chevron = control.querySelector("svg")!.getBoundingClientRect();
      return bounds.right - chevron.right;
    });
    expect(vaultSelectInset).toBeGreaterThanOrEqual(10);
    await page.screenshot({ path: test.info().outputPath("fd0-add-item.png") });
    await newItemDialog.getByRole("button", { name: "Password generator options" }).click();
    const embeddedGenerator = newItemDialog.getByRole("dialog", { name: "Password generator options" });
    await expect(embeddedGenerator.getByLabel("Length")).toBeVisible();
    await expect(embeddedGenerator.getByText("Uppercase", { exact: true })).toBeVisible();
    await expect(embeddedGenerator.getByText("Numbers", { exact: true })).toBeVisible();
    await expect(embeddedGenerator.getByText("Symbols", { exact: true })).toBeVisible();
    await embeddedGenerator.getByRole("radio", { name: "Memorable" }).click();
    await expect(embeddedGenerator.getByRole("slider", { name: "Words", exact: true })).toBeVisible();
    await expect(embeddedGenerator.getByLabel("Separator")).toBeVisible();
    await expect(embeddedGenerator.getByText("Capitalize words", { exact: true })).toBeVisible();
    await expect(embeddedGenerator.getByText("Add number", { exact: true })).toBeVisible();
    await expect(embeddedGenerator.getByText("Add symbol", { exact: true })).toBeVisible();
    await embeddedGenerator.getByRole("radio", { name: "PIN" }).click();
    await embeddedGenerator.getByLabel("Digits").fill("8");
    await page.screenshot({ path: test.info().outputPath("fd0-add-item-generator.png") });
    await embeddedGenerator.getByRole("button", { name: "Use" }).click();
    await expect(newItemDialog.getByLabel("Password", { exact: true })).toHaveValue(/^\d{8}$/);
    await newItemDialog.getByRole("button", { name: "Save item" }).click();
    await expect(page.getByText("Item saved.", { exact: true })).toBeVisible();
    await expect(page.locator(".detail-title h1")).toHaveText("DESKTOP_E2E_LOGIN");
    await expect(page.locator(".field-label").filter({ hasText: /^password$/ })).toHaveCount(1);

    await page.getByRole("button", { name: "Add", exact: true }).click();
    newItemDialog = page.getByRole("dialog", { name: "New item" });
    await newItemDialog.locator(".add-kind-picker > button").click();
    await newItemDialog.getByRole("menuitemradio", { name: /Secret/ }).click();
    await newItemDialog.getByLabel("Name", { exact: true }).fill("DESKTOP_E2E_SECRET");
    await newItemDialog.getByLabel("Value", { exact: true }).fill("isolated-value");
    await newItemDialog.getByRole("button", { name: "Save item" }).click();
    await expect(page.getByText("Item saved.", { exact: true })).toBeVisible();
    await expect(page.locator(".detail-title h1")).toHaveText("DESKTOP_E2E_SECRET");

    await page.getByRole("button", { name: "Add", exact: true }).click();
    newItemDialog = page.getByRole("dialog", { name: "New item" });
    await newItemDialog.locator(".add-kind-picker > button").click();
    await newItemDialog.getByRole("menuitemradio", { name: /Secret/ }).click();
    await newItemDialog.getByLabel("Name", { exact: true }).fill("DESKTOP_E2E_SECRET");
    await newItemDialog.getByLabel("Value", { exact: true }).fill("must-not-overwrite");
    await newItemDialog.getByRole("button", { name: "Save item" }).click();
    await expect(page.getByText(/already exists in this vault/)).toBeVisible();
    await page.keyboard.press("Escape");

    await page.locator(".type-picker-button").click();
    await page.getByRole("option", { name: /Secrets/ }).click();
    await page.getByText("Show all", { exact: true }).click();
    await expect(page.getByRole("checkbox", { name: "Show all" })).not.toBeChecked();
    await expect(page.getByRole("button", { name: /^DESKTOP_E2E_SECRET General/ })).toBeVisible();
    await expect(page.locator(".detail-title h1")).toHaveText("DESKTOP_E2E_SECRET");
    await page.getByRole("button", { name: "More actions" }).click();
    await page.getByRole("menuitem", { name: "Edit item" }).click();
    await expect(page.getByRole("dialog", { name: "Edit secret" })).toBeVisible();
    await page.getByLabel("Name", { exact: true }).fill("DESKTOP_E2E_RENAMED");
    await page.getByLabel("Value", { exact: true }).fill("isolated-value-updated");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("Changes saved.", { exact: true })).toBeVisible();
    await expect(page.locator(".detail-title h1")).toHaveText("DESKTOP_E2E_RENAMED");
    await expect(page.getByText("DESKTOP_E2E_SECRET", { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Reveal Value" }).click();
    await expect(page.getByText("isolated-value-updated", { exact: true })).toBeVisible();

    await page.locator(".type-picker-button").click();
    await page.getByRole("option", { name: /SSH/ }).click();
    await page.getByRole("button", { name: /^talos-gw root@/ }).click();
    await expect(page.locator(".detail-title h1")).toHaveText("talos-gw");
    await page.getByRole("button", { name: "More actions" }).click();
    await page.getByRole("menuitem", { name: "Edit item" }).click();
    await expect(page.getByRole("dialog", { name: "Edit SSH host" })).toBeVisible();
    await page.getByLabel("Alias", { exact: true }).fill("talos-gw-renamed");
    await page.getByLabel("Notes", { exact: true }).fill("Edited safely in fd0 Desktop");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.locator(".detail-title h1")).toHaveText("talos-gw-renamed");
    await expect(page.getByText("talos-gw", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Edited safely in fd0 Desktop", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Settings" }).click();
    await app.evaluate(({ dialog }, path) => {
      Object.defineProperty(dialog, "showSaveDialog", {
        configurable: true,
        value: async () => ({ canceled: false, filePath: path }),
      });
    }, recoveryPath);
    await page.getByRole("button", { name: "Export…" }).click();
    await page.getByLabel("Recovery passphrase", { exact: true }).fill("fd0-e2e-recovery-passphrase");
    await page.getByLabel("Confirm recovery passphrase", { exact: true }).fill("fd0-e2e-recovery-passphrase");
    await page.getByRole("button", { name: "Choose location…" }).click();
    await expect(page.getByText("Recovery file saved.", { exact: true })).toBeVisible();
    expect(existsSync(recoveryPath)).toBe(true);
    expect(statSync(recoveryPath).mode & 0o777).toBe(0o600);

    await page.locator(".type-picker-button").click();
    await page.getByRole("option", { name: /Passwords/ }).click();

    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: test.info().outputPath("fd0-desktop.png") });

    await page.getByRole("button", { name: "Lock fd0" }).click();
    await expect(page.getByRole("heading", { name: "Unlock fd0" })).toBeVisible();
    const passphraseInput = page.getByLabel("Passphrase", { exact: true });
    await passphraseInput.fill("fd0-desktop-dev");
    await expect(passphraseInput).toHaveAttribute("type", "password");
    await page.getByRole("button", { name: "Show passphrase" }).click();
    await expect(passphraseInput).toHaveAttribute("type", "text");
    await expect(passphraseInput).toHaveValue("fd0-desktop-dev");
    await page.getByRole("button", { name: "Hide passphrase" }).click();
    await expect(passphraseInput).toHaveAttribute("type", "password");
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(page.locator(".type-picker-button")).toBeVisible();
    await page.keyboard.press(process.platform === "darwin" ? "Meta+f" : "Control+f");
    await expect(page.getByLabel("Search vault")).toBeFocused();

    const visualState = await page.evaluate(() => ({
      appColor: getComputedStyle(document.querySelector(".app")!).color,
      sidebarColor: getComputedStyle(document.querySelector(".sidebar-item")!).color,
      opacity: getComputedStyle(document.querySelector(".app")!).opacity,
      fonts: document.fonts.status,
    }));
    expect(visualState).toEqual({
      appColor: "rgb(241, 239, 233)",
      sidebarColor: "rgb(136, 143, 137)",
      opacity: "1",
      fonts: "loaded",
    });
    await page.getByRole("button", { name: /^GitHub valentin@example.com/ }).click();
    await page.getByRole("button", { name: "Reveal password" }).click();
    await expect(page.getByText("d3v-Vault!GitHub-2026", { exact: true })).toBeVisible();
    await app.evaluate(({ powerMonitor }) => powerMonitor.emit("suspend"));
    await expect(page.getByRole("heading", { name: "Unlock fd0" })).toBeVisible();
    await expect(page.getByText("d3v-Vault!GitHub-2026", { exact: true })).toHaveCount(0);
    expect(errors).toEqual([]);
  } finally {
    await app.close();
  }
});

test("restores an identity without contacting the production fd0 instance", async () => {
  expect(existsSync(recoveryPath)).toBe(true);
  mkdirSync(restoreHome, { recursive: true, mode: 0o700 });
  writeFileSync(join(restoreHome, ".desktop-isolated"), "fd0-desktop-isolated-v1\n", { mode: 0o600 });
  const restoreEnvironment: NodeJS.ProcessEnv = {
    ...environment,
    FD0_HOME: restoreHome,
    FD0_SSH_SOCK: restoreSock,
    FD0_DESKTOP_USER_DATA: join(restoreHome, "desktop-ui"),
  };
  const app = await electron.launch({
    executablePath: electronPath,
    args: [join(desktopRoot, "out", "main", "index.js")],
    env: restoreEnvironment,
  });
  try {
    const page = await app.firstWindow();
    await expect(page.getByRole("heading", { name: "Protect your passwords with fd0" })).toBeVisible();
    await page.getByRole("button", { name: "Restore", exact: true }).click();
    await app.evaluate(({ dialog }, path) => {
      Object.defineProperty(dialog, "showOpenDialog", {
        configurable: true,
        value: async () => ({ canceled: false, filePaths: [path] }),
      });
    }, recoveryPath);
    const recoveryPassphrase = page.getByLabel("Recovery passphrase", { exact: true });
    const localPassphrase = page.getByLabel("New passphrase for this device", { exact: true });
    const localConfirmation = page.getByLabel("Confirm new passphrase", { exact: true });
    await recoveryPassphrase.fill("fd0-e2e-recovery-passphrase");
    await localPassphrase.fill("fd0-e2e-local-passphrase");
    await localConfirmation.fill("fd0-e2e-local-passphrase");
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    expect(await recoveryPassphrase.inputValue()).toBe("fd0-e2e-recovery-passphrase");
    expect(await localPassphrase.inputValue()).toBe("fd0-e2e-local-passphrase");
    expect(await localConfirmation.inputValue()).toBe("fd0-e2e-local-passphrase");
    await page.getByRole("button", { name: "Choose recovery file and restore" }).click();
    await expect(page.locator(".type-picker-button")).toBeVisible();
    await expect(page.getByText("No matching items", { exact: true })).toBeVisible();
    const log = readFileSync(join(restoreHome, "agent.log"), "utf8");
    expect(log).toContain("automatic sync disabled by environment");
    expect(log).not.toContain("on-unlock sync enabled");
  } finally {
    await app.close();
    spawnSync(join(buildDir, "fd0"), ["agent", "stop"], { cwd: repoRoot, env: restoreEnvironment });
  }
});
