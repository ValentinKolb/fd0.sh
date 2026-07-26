import { join } from "node:path";
import { run } from "./process";

const desktopRoot = join(import.meta.dirname, "..");

run("bun", ["run", "build"], { cwd: desktopRoot });
run("bunx", ["electron-builder", "--dir"], { cwd: desktopRoot });

if (process.platform === "darwin") {
  const outputDirectory = process.arch === "arm64" ? "mac-arm64" : "mac";
  const app = join(desktopRoot, "dist", outputDirectory, "fd0.app");
  run("codesign", ["--force", "--deep", "--sign", "-", "--timestamp=none", app], {
    cwd: desktopRoot,
  });
  run("codesign", ["--verify", "--deep", "--strict", app], { cwd: desktopRoot });
}
