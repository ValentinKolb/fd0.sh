import { run } from "./process";

const desktopRoot = import.meta.dirname + "/..";
run("bun", ["run", "scripts/build-go.ts"], { cwd: desktopRoot });
run("bunx", ["electron-vite", "build"], { cwd: desktopRoot });
