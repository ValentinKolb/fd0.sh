type GitHubRelease = {
  tag_name?: unknown;
  draft?: unknown;
  prerelease?: unknown;
};

export type DesktopReleaseFeedItem = {
  tag_name: string;
  draft: false;
  prerelease: false;
};

const desktopStableTag = /^desktop-v[0-9]+\.[0-9]+\.[0-9]+$/;
const pageSize = 100;
const maxPages = 20;
const cacheLifetimeMs = 10 * 60_000;
let cached: { expiresAt: number; releases: DesktopReleaseFeedItem[] } | null = null;

export async function fetchStableDesktopReleases(
  fetcher: typeof fetch = fetch,
  now = Date.now(),
): Promise<DesktopReleaseFeedItem[]> {
  if (cached && cached.expiresAt > now) return cached.releases;

  const releases: DesktopReleaseFeedItem[] = [];
  for (let page = 1; page <= maxPages; page++) {
    const response = await fetcher(
      `https://api.github.com/repos/k2b-dev/fd0.sh/releases?per_page=${pageSize}&page=${page}`,
      {
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "fd0.sh/desktop-release-feed",
          "X-GitHub-Api-Version": "2022-11-28",
          ...(process.env.GITHUB_TOKEN
            ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
            : {}),
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!response.ok) {
      if (cached) return cached.releases;
      throw new Error(`GitHub release lookup failed with HTTP ${response.status}`);
    }
    const pageItems = await response.json();
    if (!Array.isArray(pageItems)) throw new Error("GitHub release lookup returned invalid data");
    for (const candidate of pageItems as GitHubRelease[]) {
      if (
        candidate.draft === false
        && candidate.prerelease === false
        && typeof candidate.tag_name === "string"
        && desktopStableTag.test(candidate.tag_name)
      ) {
        releases.push({
          tag_name: candidate.tag_name,
          draft: false,
          prerelease: false,
        });
      }
    }
    if (pageItems.length < pageSize) break;
  }
  cached = { expiresAt: now + cacheLifetimeMs, releases };
  return releases;
}

export function resetDesktopReleaseCacheForTest(): void {
  cached = null;
}
