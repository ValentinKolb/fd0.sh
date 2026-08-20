export type SupportLinkTarget = "browser" | "browserDocs" | "docs" | "issues";

const supportLinks: Record<SupportLinkTarget, string> = {
  browser: "https://chromewebstore.google.com/detail/fd0/kcbjlgbkgoabcdflpnohkknfbegcigel",
  browserDocs: "https://fd0.sh/docs/browser",
  docs: "https://fd0.sh/docs",
  issues: "https://github.com/k2b-dev/fd0.sh/issues",
};

export function supportLink(target: SupportLinkTarget): string {
  const url = supportLinks[target];
  if (!url) throw new Error("Unknown support link");
  return url;
}

export function trustedItemURL(value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2_048) {
    throw new Error("This item does not contain a valid website");
  }
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new Error("Only credential-free HTTPS websites can be opened");
  }
  return parsed.toString();
}
