import { spawnSync } from "node:child_process";
import { mkdir, readFile, readdir, rm, utimes } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, "dist-store");
const manifest = JSON.parse(
  await readFile(join(dist, "manifest.json"), "utf8"),
) as { name?: string; version?: string; key?: string };

if (manifest.name !== "fd0" || !manifest.version || manifest.key) {
  throw new Error("store manifest must be named fd0 and must not contain a development key");
}

const artifactDirectory = join(root, "..", ".build", "browser-store");
const artifact = join(
  artifactDirectory,
  `fd0-chrome-${manifest.version}.zip`,
);
await mkdir(artifactDirectory, { recursive: true });
await rm(artifact, { force: true });

const zipEpoch = new Date("1980-01-01T00:00:00.000Z");
const normalizeTimestamps = async (directory: string): Promise<void> => {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await normalizeTimestamps(path);
    await utimes(path, zipEpoch, zipEpoch);
  }
};
await normalizeTimestamps(dist);
await utimes(dist, zipEpoch, zipEpoch);

const zipped = spawnSync("zip", ["-X", "-q", "-r", artifact, "."], {
  cwd: dist,
  encoding: "utf8",
});
if (zipped.status !== 0) {
  throw new Error(zipped.stderr || "could not create Chrome Web Store ZIP");
}

const listed = spawnSync("unzip", ["-Z1", artifact], { encoding: "utf8" });
if (listed.status !== 0) {
  throw new Error(listed.stderr || "could not inspect Chrome Web Store ZIP");
}
const entries = listed.stdout.trim().split("\n").filter(Boolean).sort();
const expected = [
  "content.js",
  "icons/",
  "icons/icon-128.png",
  "icons/icon-16.png",
  "icons/icon-32.png",
  "icons/icon-48.png",
  "manifest.json",
  "service-worker.js",
].sort();
if (JSON.stringify(entries) !== JSON.stringify(expected)) {
  throw new Error(`unexpected store package contents:\n${entries.join("\n")}`);
}

const payload = await Bun.file(artifact).arrayBuffer();
const digest = new Bun.CryptoHasher("sha256").update(payload).digest("hex");
console.log(`packaged ${artifact}`);
console.log(`sha256 ${digest}`);
