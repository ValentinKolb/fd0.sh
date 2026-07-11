import { mkdirSync } from "node:fs";
import { agentBin, bridgeBin, buildDir, cliBin, repoRoot, seedBin } from "./paths";
import { run } from "./process";

mkdirSync(buildDir, { recursive: true, mode: 0o700 });

const flavor = process.env.FD0_DESKTOP_FLAVOR === "standard" ? "standard" : "yubikey";
const tags = flavor === "yubikey" ? "netgo,yubikey" : "netgo";
const version = process.env.FD0_DESKTOP_VERSION?.trim();

for (const [output, pkg, versioned, desktopManaged] of [
  [agentBin, "./cmd/fd0-agent", true, false],
  [bridgeBin, "./cmd/fd0-desktop-bridge", false, false],
  [cliBin, "./cmd/fd0", true, true],
  [seedBin, "./cmd/fd0-desktop-dev-seed", false, false],
] as const) {
  const args = ["build", "-trimpath", `-tags=${tags}`];
  const ldflags = ["-s", "-w"];
  if (versioned && version) ldflags.push("-X", `main.version=${version}`);
  if (desktopManaged) ldflags.push("-X", "main.distribution=desktop");
  args.push("-ldflags", ldflags.join(" "));
  args.push("-o", output, pkg);
  run("go", args, { cwd: repoRoot });
}
