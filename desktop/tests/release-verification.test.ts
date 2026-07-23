import { describe, expect, test } from "bun:test";
import {
  checksumForAsset,
  compareSemver,
  desktopReleaseIdentity,
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

  test("implements semver prerelease precedence", () => {
    expect(compareSemver("1.0.0-beta.2", "1.0.0-beta.10")).toBeLessThan(0);
    expect(compareSemver("1.0.0-beta.10", "1.0.0")).toBeLessThan(0);
    expect(compareSemver("2.0.0", "1.99.99")).toBeGreaterThan(0);
  });
});

describe("desktop release authentication", () => {
  test("binds the certificate identity to the exact workflow and tag", () => {
    expect(desktopReleaseIdentity("desktop-v1.2.3")).toBe(
      "^https://github\\.com/ValentinKolb/fd0\\.sh/\\.github/workflows/release-desktop\\.yml@refs/tags/desktop-v1\\.2\\.3$",
    );
    expect(() => desktopReleaseIdentity("desktop-v1.2.3/../../main")).toThrow();
  });

  test("reads only an exact sha256 manifest entry", () => {
    const hash = "a".repeat(64);
    expect(checksumForAsset(`${hash}  fd0.AppImage\n`, "fd0.AppImage")).toBe(hash);
    expect(() => checksumForAsset(`${hash}  fd0.AppImage.old\n`, "fd0.AppImage")).toThrow();
  });
});
