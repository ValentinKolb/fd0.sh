import type { PassField } from "../../../shared/contracts";

/**
 * The reserved name of an item's free-text note.
 *
 * Notes are an ordinary top-level text field, not a new schema concept. That is
 * deliberate: a new top-level key is silently dropped when an older client
 * writes the item back, and a new field *type* makes an older client refuse to
 * decode the item at all. A plain text field round-trips through every client
 * that has ever existed. Everything that makes it feel first-class — one per
 * item, a fixed name, its own editor — is enforced here and in the UI.
 */
export const NOTES_FIELD = "notes";

function isNotes(field: PassField): boolean {
  return field.type === "text" && field.name.toLowerCase() === NOTES_FIELD;
}

/** Reads the item's note. Only a top-level field counts; a note inside a section belongs to that section. */
export function readNotes(fields: PassField[]): string {
  const field = fields.find(isNotes);
  return typeof field?.value === "string" ? field.value : "";
}

/** Returns the fields with the reserved note removed, for rendering the rest. */
export function withoutNotes(fields: PassField[]): PassField[] {
  const index = fields.findIndex(isNotes);
  return index < 0 ? fields : [...fields.slice(0, index), ...fields.slice(index + 1)];
}

/** Writes the note, appending it last. An empty note removes the field entirely. */
export function writeNotes(fields: PassField[], notes: string): PassField[] {
  const trimmed = notes.replace(/[ \t\r\n]+$/, "");
  const rest = withoutNotes(fields);
  return trimmed ? [...rest, { type: "text", name: NOTES_FIELD, value: trimmed }] : rest;
}
