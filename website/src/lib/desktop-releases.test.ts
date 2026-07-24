import { afterEach, describe, expect, test } from "bun:test";
import {
  fetchStableDesktopReleases,
  resetDesktopReleaseCacheForTest,
} from "./desktop-releases";

afterEach(resetDesktopReleaseCacheForTest);

describe("desktop release feed", () => {
  test("paginates and exposes only stable desktop releases", async () => {
    const first = Array.from({ length: 100 }, (_, index) => ({
      tag_name: index === 99 ? "desktop-v1.2.3" : `client-v1.0.${index}`,
      draft: false,
      prerelease: false,
    }));
    const pages = [first, [
      { tag_name: "desktop-v2.0.0-beta.1", draft: false, prerelease: true },
      { tag_name: "desktop-v1.3.0", draft: true, prerelease: false },
      { tag_name: "desktop-v1.2.4", draft: false, prerelease: false },
    ]];
    const urls: string[] = [];
    const fetcher = (async (url: string | URL | Request) => {
      urls.push(String(url));
      return Response.json(pages[urls.length - 1] ?? []);
    }) as typeof fetch;

    await expect(fetchStableDesktopReleases(fetcher, 1)).resolves.toEqual([
      { tag_name: "desktop-v1.2.3", draft: false, prerelease: false },
      { tag_name: "desktop-v1.2.4", draft: false, prerelease: false },
    ]);
    expect(urls).toHaveLength(2);
  });

  test("serves stale data when GitHub is temporarily unavailable", async () => {
    const healthy = (async () => Response.json([
      { tag_name: "desktop-v1.0.0", draft: false, prerelease: false },
    ])) as typeof fetch;
    await fetchStableDesktopReleases(healthy, 1);

    const offline = (async () => new Response("", { status: 503 })) as typeof fetch;
    await expect(fetchStableDesktopReleases(offline, 20 * 60_000)).resolves.toHaveLength(1);
  });
});
