import type { FieldView } from "../../../shared/contracts";

/** "1 item" / "2 items" — the old code always wrote "N items". */
export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function flattenFieldViews(field: FieldView): FieldView[] {
  return [field, ...(field.children ?? []).flatMap(flattenFieldViews)];
}

/** "2 minutes ago" for recent times, an absolute date beyond a week. */
export function relativeDate(raw: string): string {
  const date = new Date(raw);
  if (Number.isNaN(date.valueOf())) return raw;
  const seconds = Math.round((date.valueOf() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, "hour");
  const days = Math.round(hours / 24);
  if (Math.abs(days) < 7) return formatter.format(days, "day");
  return date.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

export function absoluteDate(raw: string): string {
  const date = new Date(raw);
  if (Number.isNaN(date.valueOf())) return raw;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** Stable initials for an item or person avatar. */
export function initials(value: string): string {
  const cleaned = value.trim();
  if (!cleaned) return "?";
  const words = cleaned.split(/[\s._/-]+/).filter(Boolean);
  if (words.length === 1) return words[0]!.slice(0, 2).toUpperCase();
  return `${words[0]![0]}${words[1]![0]}`.toUpperCase();
}

/** Strips scheme and trailing slash so a URL reads as a domain in a list. */
export function prettyURL(value: string): string {
  return value.replace(/^https?:\/\//, "").replace(/\/$/, "");
}
