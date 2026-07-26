import type { PassField } from "../../../shared/contracts";
import { NOTES_FIELD } from "./notes";

/**
 * Which top-level fields the editor shows in its login card.
 *
 * These names mirror the preference lists the CLI already uses
 * (internal/cli/pass.go `preferredPassField`, internal/desktopbridge
 * `passTextField`), so the desktop and the CLI always agree on what "the
 * password" of an item is. Order matters: earlier names win.
 */
const USERNAME_NAMES = ["username", "user", "email", "login"];
const SECRET_NAMES = ["password", "pass"];

export type RecognisedFields = {
  /** Index into the top-level field array, or -1. */
  username: number;
  secret: number;
};

function matchIndex(fields: PassField[], type: PassField["type"], names: string[]): number {
  for (const wanted of names) {
    const index = fields.findIndex(
      (field) => field.type === type && field.name.toLowerCase() === wanted,
    );
    if (index >= 0) return index;
  }
  return -1;
}

/**
 * Finds the login fields the card should show.
 *
 * The card is a VIEW, not a container: it only ever claims fields that sit at
 * the top level. A password nested inside a section stays in that section,
 * because moving it would silently rearrange structure the user built. And
 * renaming a field out of these lists simply drops it out of the card into the
 * ordinary field list, which is a visible consequence rather than a lie.
 */
export function recognise(fields: PassField[]): RecognisedFields {
  return {
    username: matchIndex(fields, "text", USERNAME_NAMES),
    secret: matchIndex(fields, "secret", SECRET_NAMES),
  };
}

/** True when this top-level index is shown in the login card or is the note. */
export function isClaimed(fields: PassField[], index: number, recognised: RecognisedFields): boolean {
  if (index === recognised.username || index === recognised.secret) return true;
  const field = fields[index];
  return Boolean(field && field.type === "text" && field.name.toLowerCase() === NOTES_FIELD);
}
