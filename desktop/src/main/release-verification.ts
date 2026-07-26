const desktopTagPattern = /^desktop-v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;

type Semver = {
  core: [number, number, number];
  prerelease: string[];
};

export type DesktopRelease = {
  tag: string;
  version: string;
  feedURL: string;
};

function parseSemver(value: string): Semver {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(value);
  if (!match) throw new Error(`Invalid semantic version: ${value}`);
  return {
    core: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4]?.split(".") ?? [],
  };
}

export function compareSemver(left: string, right: string): number {
  const a = parseSemver(left);
  const b = parseSemver(right);
  for (let index = 0; index < 3; index += 1) {
    const difference = a.core[index]! - b.core[index]!;
    if (difference !== 0) return Math.sign(difference);
  }
  if (a.prerelease.length === 0 || b.prerelease.length === 0) {
    return Math.sign(b.prerelease.length - a.prerelease.length);
  }
  const count = Math.max(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < count; index += 1) {
    const leftID = a.prerelease[index];
    const rightID = b.prerelease[index];
    if (leftID === undefined) return -1;
    if (rightID === undefined) return 1;
    if (leftID === rightID) continue;
    const leftNumeric = /^\d+$/.test(leftID);
    const rightNumeric = /^\d+$/.test(rightID);
    if (leftNumeric && rightNumeric) return Number(leftID) < Number(rightID) ? -1 : 1;
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftID < rightID ? -1 : 1;
  }
  return 0;
}

export function selectDesktopRelease(payload: unknown, allowPrerelease: boolean): DesktopRelease | null {
  if (!Array.isArray(payload)) throw new Error("GitHub release lookup returned invalid data");
  const releases = payload.flatMap((candidate): DesktopRelease[] => {
    if (!candidate || typeof candidate !== "object") return [];
    const value = candidate as Record<string, unknown>;
    if (value.draft !== false || typeof value.tag_name !== "string") return [];
    const match = desktopTagPattern.exec(value.tag_name);
    if (!match || (!allowPrerelease && value.prerelease !== false)) return [];
    return [{
      tag: value.tag_name,
      version: match[1]!,
      feedURL: `https://github.com/k2b-dev/fd0.sh/releases/download/${encodeURIComponent(value.tag_name)}/`,
    }];
  });
  releases.sort((left, right) => compareSemver(right.version, left.version));
  return releases[0] ?? null;
}

export function desktopReleaseIdentity(tag: string): string {
  if (!desktopTagPattern.test(tag)) throw new Error(`Invalid fd0 Desktop release tag: ${tag}`);
  const identity = `https://github.com/k2b-dev/fd0.sh/.github/workflows/release-desktop.yml@refs/tags/${tag}`;
  return `^${identity.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`;
}

export function requireSelectedNewerRelease(
  selected: DesktopRelease | null,
  downloadedVersion: string,
  currentVersion: string,
): DesktopRelease {
  if (
    !selected
    || selected.version !== downloadedVersion
    || compareSemver(downloadedVersion, currentVersion) <= 0
  ) {
    throw new Error("Downloaded update does not match the selected newer release");
  }
  return selected;
}

export function linuxDesktopAssetName(version: string, architecture: string): string {
  parseSemver(version);
  if (architecture !== "x64" && architecture !== "arm64") {
    throw new Error(`Unsupported update architecture: ${architecture}`);
  }
  return `fd0-desktop_${version}_linux_${architecture}.AppImage`;
}

export function checksumForAsset(manifest: string, assetName: string): string {
  const matches: string[] = [];
  for (const line of manifest.split(/\r?\n/)) {
    const match = /^([a-fA-F0-9]{64})\s+\*?(.+)$/.exec(line.trim());
    if (match?.[2] === assetName) matches.push(match[1]!.toLowerCase());
  }
  if (matches.length !== 1) {
    throw new Error(
      matches.length === 0
        ? `${assetName} is not listed in the authenticated release manifest`
        : `${assetName} has duplicate entries in the authenticated release manifest`,
    );
  }
  return matches[0]!;
}
