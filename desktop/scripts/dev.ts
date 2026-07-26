import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot, seedBin, devEnv, devUserData } from "./paths";
import { run, runInteractive } from "./process";

run("bun", ["run", "scripts/build-go.ts"], { cwd: import.meta.dirname + "/.." });
run(seedBin, [], { cwd: repoRoot, env: devEnv });

const uiMarker = join(devUserData, ".desktop-ui-isolated");
mkdirSync(devUserData, { recursive: true, mode: 0o700 });
if (existsSync(uiMarker) && readFileSync(uiMarker, "utf8") !== "fd0-desktop-ui-isolated-v1\n") {
  throw new Error(`Invalid isolated desktop UI marker at ${uiMarker}`);
}
if (!existsSync(uiMarker)) writeFileSync(uiMarker, "fd0-desktop-ui-isolated-v1\n", { mode: 0o600 });

const code = await runInteractive("bunx", ["electron-vite", "dev"], {
  cwd: import.meta.dirname + "/..",
  env: devEnv,
});
process.exitCode = code;
