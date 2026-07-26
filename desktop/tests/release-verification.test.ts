import { describe, expect, test } from "bun:test";
import {
  checksumForAsset,
  compareSemver,
  desktopReleaseIdentity,
  linuxDesktopAssetName,
  requireSelectedNewerRelease,
  selectDesktopRelease,
} from "../src/main/release-verification";

describe("desktop release selection", () => {
  test("selects the highest valid stable release independent of API order", () => {
    const release = selectDesktopRelease([
      { tag_name: "desktop-v1.2.0", draft: false, prerelease: false },
      { tag_name: "client-v9.0.0", draft: false, prerelease: false },
      { tag_name: "desktop-v1.10.0", draft: false, prerelease: false },
      { tag_name: "desktop-v2.0.0-beta.1", draft: false, prerelease: true },
    ], false);
    expect(release?.tag).toBe("desktop-v1.10.0");
  });

  test("rejects drafts and prereleases from the stable channel", () => {
    const release = selectDesktopRelease([
      { tag_name: "desktop-v9.0.0", draft: true, prerelease: false },
      { tag_name: "desktop-v8.0.0-beta.1", draft: false, prerelease: true },
      { tag_name: "desktop-v1.2.3", draft: false, prerelease: false },
    ], false);
    expect(release?.tag).toBe("desktop-v1.2.3");
  });

  test("selects a desktop release beyond the first 30 mixed releases", () => {
    const releases = Array.from({ length: 80 }, (_, index) => ({
      tag_name: `client-v1.0.${index}`,
      draft: false,
      prerelease: false,
    }));
    releases.push({ tag_name: "desktop-v3.4.5", draft: false, prerelease: false });
    expect(selectDesktopRelease(releases, false)?.tag).toBe("desktop-v3.4.5");
  });

  test("implements semver prerelease precedence", () => {
    expect(compareSemver("1.0.0-beta.2", "1.0.0-beta.10")).toBeLessThan(0);
    expect(compareSemver("1.0.0-beta.10", "1.0.0")).toBeLessThan(0);
    expect(compareSemver("2.0.0", "1.99.99")).toBeGreaterThan(0);
  });
});

describe("desktop release authentication", () => {
  test("binds the certificate identity to the exact workflow and tag", () => {
    expect(desktopReleaseIdentity("desktop-v1.2.3")).toBe(
      "^https://github\\.com/k2b-dev/fd0\\.sh/\\.github/workflows/release-desktop\\.yml@refs/tags/desktop-v1\\.2\\.3$",
    );
    expect(() => desktopReleaseIdentity("desktop-v1.2.3/../../main")).toThrow();
  });

  test("reads only an exact sha256 manifest entry", () => {
    const hash = "a".repeat(64);
    expect(checksumForAsset(`${hash}  fd0.AppImage\n`, "fd0.AppImage")).toBe(hash);
    expect(() => checksumForAsset(`${hash}  fd0.AppImage.old\n`, "fd0.AppImage")).toThrow();
    expect(() => checksumForAsset(
      `${hash}  fd0.AppImage\n${"b".repeat(64)}  fd0.AppImage\n`,
      "fd0.AppImage",
    )).toThrow("duplicate");
  });

  test("requires the downloaded version to match a selected upgrade", () => {
    const selected = {
      tag: "desktop-v1.2.0",
      version: "1.2.0",
      feedURL: "https://example.test/",
    };
    expect(requireSelectedNewerRelease(selected, "1.2.0", "1.1.0")).toBe(selected);
    expect(() => requireSelectedNewerRelease(selected, "1.3.0", "1.1.0")).toThrow();
    expect(() => requireSelectedNewerRelease(selected, "1.2.0", "1.2.0")).toThrow();
    expect(() => requireSelectedNewerRelease(selected, "1.1.0", "1.2.0")).toThrow();
  });

  test("binds Linux update assets to supported architectures", () => {
    expect(linuxDesktopAssetName("1.2.3", "arm64"))
      .toBe("fd0-desktop_1.2.3_linux_arm64.AppImage");
    expect(linuxDesktopAssetName("1.2.3", "x64"))
      .toBe("fd0-desktop_1.2.3_linux_x64.AppImage");
    expect(() => linuxDesktopAssetName("1.2.3", "ia32")).toThrow("Unsupported");
    expect(() => linuxDesktopAssetName("../../payload", "x64")).toThrow("Invalid semantic version");
  });
});
