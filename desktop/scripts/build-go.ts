import { copyFileSync, existsSync, mkdirSync, realpathSync } from "node:fs";
import { basename, join } from "node:path";
import {
  agentBin,
  bridgeBin,
  buildDir,
  cliBin,
  releaseVerifierBin,
  repoRoot,
  runtimeDir,
  seedBin,
} from "./paths";
import { run } from "./process";

mkdirSync(buildDir, { recursive: true, mode: 0o700 });
mkdirSync(runtimeDir, { recursive: true, mode: 0o700 });

const flavor = process.env.FD0_DESKTOP_FLAVOR === "standard" ? "standard" : "yubikey";
const tags = flavor === "yubikey" ? "netgo,yubikey" : "netgo";
const version = process.env.FD0_DESKTOP_VERSION?.trim();

for (const [output, pkg, versioned, desktopManaged] of [
  [agentBin, "./cmd/fd0-agent", true, false],
  [bridgeBin, "./cmd/fd0-desktop-bridge", false, false],
  [cliBin, "./cmd/fd0", true, true],
  [seedBin, "./cmd/fd0-desktop-dev-seed", false, false],
  [releaseVerifierBin, "./cmd/fd0-release-verify", false, false],
] as const) {
  const args = ["build", "-trimpath", `-tags=${tags}`];
  const ldflags = ["-s", "-w"];
  if (versioned && version) ldflags.push("-X", `main.version=${version}`);
  if (desktopManaged) ldflags.push("-X", "main.distribution=desktop");
  args.push("-ldflags", ldflags.join(" "));
  args.push("-o", output, pkg);
  run("go", args, { cwd: repoRoot });
}

if (process.platform === "linux" && flavor === "yubikey") {
  const configured = process.env.FD0_DESKTOP_PCSC_LIB?.trim();
  const candidates = [
    configured,
    "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1",
    "/usr/lib/aarch64-linux-gnu/libpcsclite.so.1",
    "/usr/lib64/libpcsclite.so.1",
  ].filter((value): value is string => Boolean(value));
  const source = candidates.find(existsSync);
  if (!source) {
    throw new Error("YubiKey desktop builds require libpcsclite.so.1; set FD0_DESKTOP_PCSC_LIB");
  }
  copyFileSync(realpathSync(source), join(runtimeDir, "libpcsclite.so.1"));

  const licenseCandidates = [
    "/usr/share/doc/libpcsclite1/copyright",
    "/usr/share/licenses/pcsc-lite/LICENSE",
  ];
  const license = licenseCandidates.find(existsSync);
  if (!license) throw new Error(`License metadata is missing for ${basename(source)}`);
  copyFileSync(license, join(runtimeDir, "libpcsclite-LICENSE.txt"));
}
