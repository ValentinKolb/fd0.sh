import type { SFTPPreview } from "../../../shared/contracts";

export type SFTPBreadcrumb = {
  label: string;
  path: string;
};

export type SFTPPreviewContent =
  | { kind: "text"; value: string }
  | { kind: "hex"; value: string };

export function remoteJoin(parent: string, child: string): string {
  return `${parent.replace(/\/+$/, "")}/${child}`.replace(/\/+/g, "/") || "/";
}

export function remoteParent(value: string): string {
  const clean = value.replace(/\/+$/, "") || "/";
  if (clean === "/") return "/";
  const index = clean.lastIndexOf("/");
  return index <= 0 ? "/" : clean.slice(0, index);
}

export function remoteBreadcrumbs(value: string): SFTPBreadcrumb[] {
  const parts = value.split("/").filter(Boolean);
  return [
    { label: "/", path: "/" },
    ...parts.map((label, index) => ({
      label,
      path: `/${parts.slice(0, index + 1).join("/")}`,
    })),
  ];
}

export function sftpErrorNeedsReconnect(error: unknown): boolean {
  const code = typeof error === "object" && error !== null && "code" in error
    ? (error as { code?: unknown }).code
    : undefined;
  return ["connection_failed", "disconnected", "vault_locked", "host_unverified"].includes(String(code));
}

export function decodeSFTPPreview(preview: SFTPPreview): SFTPPreviewContent {
  const bytes = Uint8Array.from(atob(preview.contentBase64), (value) => value.charCodeAt(0));
  if (!looksLikeText(bytes)) return { kind: "hex", value: formatHex(bytes) };
  return { kind: "text", value: new TextDecoder().decode(bytes) };
}

function looksLikeText(bytes: Uint8Array): boolean {
  if (bytes.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return false;
  }
  let controls = 0;
  for (const value of bytes) {
    if (value < 32 && value !== 9 && value !== 10 && value !== 13) controls += 1;
  }
  return bytes.length === 0 || controls / bytes.length < 0.02;
}

function formatHex(bytes: Uint8Array): string {
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const row = bytes.slice(offset, offset + 16);
    const hex = [...row].map((value) => value.toString(16).padStart(2, "0")).join(" ");
    const ascii = [...row]
      .map((value) => value >= 32 && value <= 126 ? String.fromCharCode(value) : ".")
      .join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  |${ascii}|`);
  }
  return lines.join("\n");
}
