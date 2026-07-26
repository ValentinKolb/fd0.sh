import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { cliBin, devEnv, devHome, devUserData, repoRoot } from "./paths";
import { run } from "./process";

const marker = join(devHome, ".desktop-isolated");
if (!existsSync(marker) || readFileSync(marker, "utf8") !== "fd0-desktop-isolated-v1\n") {
  throw new Error(`Refusing to reset unmarked directory: ${devHome}`);
}
const uiMarker = join(devUserData, ".desktop-ui-isolated");
if (existsSync(devUserData) && (!existsSync(uiMarker) || readFileSync(uiMarker, "utf8") !== "fd0-desktop-ui-isolated-v1\n")) {
  throw new Error(`Refusing to reset unmarked directory: ${devUserData}`);
}
if (existsSync(cliBin)) {
  try {
    run(cliBin, ["agent", "stop"], { cwd: repoRoot, env: devEnv });
  } catch {
    // The isolated agent may already be stopped. The marker still gates removal.
  }
}
rmSync(devHome, { recursive: true, force: false });
if (existsSync(devUserData)) {
  rmSync(devUserData, { recursive: true, force: false });
}
console.log(`Reset isolated fd0 Desktop data at ${devHome}`);
