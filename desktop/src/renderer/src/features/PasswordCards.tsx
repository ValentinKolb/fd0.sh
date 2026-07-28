import { For, Index, Show, createEffect, createMemo, createSignal, onCleanup, type JSX } from "solid-js";
import {
  IconAdjustmentsHorizontal,
  IconDotsVertical,
  IconGripVertical,
  IconMinus,
  IconPaperclip,
  IconTrash,
} from "@tabler/icons-solidjs";
import { dnd, type DndController } from "@valentinkolb/stdlib/solid";
import type { PassField } from "../../../shared/contracts";
import { errorText } from "../lib/errors";
import { formatBytes } from "../lib/format";
import { recognise, isClaimed } from "../lib/recognise";
import { Button, IconButton } from "../ui/Button";
import { Input, SecretInput, Select, Textarea } from "../ui/Fields";
import { EditorAdd, EditorCard, EditorCardHeader, EditorRow } from "../ui/EditorCard";
import { MenuButton, type MenuSection } from "../ui/Menu";
import { Popover } from "../ui/Popover";
import { isTopOverlay, popOverlay, pushOverlay } from "../ui/overlayStack";
import { PasswordGeneratorPopover } from "../components/PasswordGenerator";
import {
  canMovePassFieldTree,
  canReorderPassFieldTree,
  countPassFields,
  movePassFieldTree,
  movePassFieldTreeToParent,
  type PassFieldDropLane,
} from "../components/passEditorTree";

export const MAX_FIELDS = 128;
const MAX_DEPTH = 4;

const fieldTypes = [
  { value: "text", label: "Text", hint: "Plain text such as a username" },
  { value: "secret", label: "Secret", hint: "Hidden until revealed" },
  { value: "totp", label: "One-time code", hint: "A rotating 6 or 8 digit code" },
  { value: "passkey", label: "Passkey", hint: "Stored passkey data" },
  { value: "file", label: "File", hint: "A small attachment" },
];

type DragMeta = { path: number[]; label: string };
type DropMeta = { parentPath: number[]; index: number; label: string; lane: PassFieldDropLane };
type Controller = DndController<DragMeta, DropMeta, null>;

const fieldUIID = Symbol("fd0-pass-field-ui-id");
type IdentifiedPassField = PassField & { [fieldUIID]?: string };

/**
 * Pass fields have no persisted ID, but immutable edits still need a stable
 * renderer identity. The symbol is enumerable so immutable object spreads keep
 * it, while JSON and structured cloning ignore symbol-keyed properties; it
 * never enters IPC or the vault schema.
 */
function passFieldUIID(field: PassField): string {
  const identified = field as IdentifiedPassField;
  if (identified[fieldUIID]) return identified[fieldUIID];
  const id = crypto.randomUUID();
  Object.defineProperty(identified, fieldUIID, { value: id, configurable: true, enumerable: true });
  return id;
}

function carryPassFieldUIID(current: PassField, next: PassField): PassField {
  const identified = next as IdentifiedPassField;
  if (!identified[fieldUIID]) {
    Object.defineProperty(identified, fieldUIID, { value: passFieldUIID(current), configurable: true, enumerable: true });
  }
  return next;
}

function passFieldIndex(fields: PassField[], id: string): number {
  return fields.findIndex((field) => passFieldUIID(field) === id);
}

const stringValue = (field: PassField): string => (typeof field.value === "string" ? field.value : "");
const objectValue = (field: PassField): Record<string, unknown> =>
  typeof field.value === "object" && field.value ? (field.value as Record<string, unknown>) : {};

type SectionDestination = { path: number[]; label: string };

function sectionDestinations(fields: PassField[], parentPath: number[] = [], parents: string[] = []): SectionDestination[] {
  return fields.flatMap((field, index) => {
    if (field.type !== "section") return [];
    const path = [...parentPath, index];
    const names = [...parents, field.name || "Untitled section"];
    return [
      { path, label: names.join(" / ") },
      ...sectionDestinations(field.fields ?? [], path, names),
    ];
  });
}

function passFieldListAtPath(fields: PassField[], parentPath: number[]): PassField[] | null {
  let current = fields;
  for (const index of parentPath) {
    const section = current[index];
    if (!section || section.type !== "section") return null;
    current = section.fields ?? [];
  }
  return current;
}

function samePassFieldPath(left: number[], right: number[]): boolean {
  return left.length === right.length && left.every((part, index) => part === right[index]);
}

/**
 * The password editor, built as grouped cards.
 *
 * Three ideas carry it. The directly editable name sits quietly above the
 * value inside one cell. Related rows share a card, so the count of visible
 * boxes stays low. And adding happens inside the card the new field belongs
 * to, rather than at one global button.
 */
export function PasswordCards(props: {
  fields: PassField[];
  urls: string[];
  notes: string;
  onFields(fields: PassField[]): void;
  onURLs(urls: string[]): void;
  onNotes(notes: string): void;
  onError(message: string): void;
  onValidity(id: string, valid: boolean): void;
}): JSX.Element {
  const controller = dnd.create<DragMeta, DropMeta, null>({
    collisionDetector: ({ droppables }) => {
      const hits = droppables.filter((entry) => entry.containsPointer);
      if (hits.length === 0) return null;
      return hits.reduce((closest, entry) => (entry.distance < closest.distance ? entry : closest)).id;
    },
    onDrop: ({ active, over }) => {
      if (!over) return;
      if (!canReorderPassFieldTree(props.fields, active.meta.path, over.meta.parentPath, over.meta.index, over.meta.lane)) return;
      const next = movePassFieldTree(props.fields, active.meta.path, over.meta.parentPath, over.meta.index);
      if (next !== props.fields) props.onFields(next);
    },
    announcements: {
      dragStart: (active) => `Picked up ${active.meta.label}. Use arrow keys to choose a sibling position, then press Enter to reorder.`,
      dragOver: (active, over) => (over ? `Reorder ${active.meta.label} ${over.meta.label}.` : `No valid sibling position for ${active.meta.label}.`),
      drop: (active, over) => (over ? `Reordered ${active.meta.label} ${over.meta.label}.` : `Reorder cancelled for ${active.meta.label}.`),
      cancel: (active) => `Reorder cancelled for ${active.meta.label}.`,
    },
  });

  /**
   * While a drag is armed it is the topmost thing Escape can dismiss.
   *
   * The dnd controller cancels on Escape but lets the key keep travelling, so
   * the editor's own handler saw it too and closed the whole modal mid-move.
   * Joining the overlay stack puts the drag ahead of the modal in that queue.
   */
  createEffect(() => {
    if (!controller.isDragging()) return;
    const token = pushOverlay();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || !isTopOverlay(token)) return;
      event.preventDefault();
      event.stopPropagation();
      controller.cancel();
    };
    document.addEventListener("keydown", onKeyDown, true);
    onCleanup(() => {
      document.removeEventListener("keydown", onKeyDown, true);
      popOverlay(token);
    });
  });

  const recognised = createMemo(() => recognise(props.fields));
  const count = () => countPassFields(props.fields);
  const atLimit = () => count() >= MAX_FIELDS;

  /** Top-level fields the login card and the notes card do not already show. */
  const loose = createMemo(() =>
    props.fields
      .map((field, index) => ({ field, index }))
      .filter((entry) => entry.field.type !== "section" && !isClaimed(props.fields, entry.index, recognised()))
      .map((entry) => passFieldUIID(entry.field)),
  );
  const sections = createMemo(() =>
    props.fields.filter((field) => field.type === "section").map(passFieldUIID),
  );
  const looseEndIndex = () => {
    const id = loose().at(-1);
    return id ? passFieldIndex(props.fields, id) + 1 : props.fields.length;
  };
  const sectionEndIndex = () => {
    const id = sections().at(-1);
    return id ? passFieldIndex(props.fields, id) + 1 : props.fields.length;
  };

  function update(index: number, next: PassField | null): void {
    const copy = [...props.fields];
    if (next === null) copy.splice(index, 1);
    else copy[index] = carryPassFieldUIID(copy[index]!, next);
    props.onFields(copy);
  }

  function append(field: PassField): void {
    props.onFields([...props.fields, field]);
  }

  function moveToParent(sourcePath: number[], targetParentPath: number[]): void {
    const next = movePassFieldTreeToParent(props.fields, sourcePath, targetParentPath);
    if (next !== props.fields) props.onFields(next);
  }

  const username = () => (recognised().username >= 0 ? props.fields[recognised().username] : undefined);
  const secret = () => (recognised().secret >= 0 ? props.fields[recognised().secret] : undefined);
  const hasLoginCard = () => Boolean(username() || secret() || props.urls.length > 0);

  return (
    <div class="editor-stack" classList={{ dragging: controller.isDragging() }}>
      <Show when={hasLoginCard()}>
        <EditorCard>
          <Show when={username()}>
            {(field) => (
              <EditorRow
                label={<FieldNameInput field={field()} onChange={(next) => update(recognised().username, next)} />}
                actions={
                  <FieldMenu
                    field={field()}
                    path={[recognised().username]}
                    allFields={() => props.fields}
                    onMove={moveToParent}
                    onChange={(next) => update(recognised().username, next)}
                  />
                }
              >
                <Input
                  class="editor-value"
                  aria-label={field().name}
                  value={stringValue(field())}
                  onInput={(event) => update(recognised().username, { ...field(), value: event.currentTarget.value })}
                />
              </EditorRow>
            )}
          </Show>

          <Show when={secret()}>
            {(field) => (
              <SecretRow
                field={field()}
                onChange={(next) => update(recognised().secret, next)}
                menu={
                  <FieldMenu
                    field={field()}
                    path={[recognised().secret]}
                    allFields={() => props.fields}
                    onMove={moveToParent}
                    onChange={(next) => update(recognised().secret, next)}
                  />
                }
              />
            )}
          </Show>

          {/* urls is a first-class array in the schema, so more than one is
              normal rather than an edge case. */}
          <Index each={props.urls}>
            {(url, index) => (
              <EditorRow
                label={index === 0 ? "Website" : "Website (alternative)"}
                actions={
                  <Show when={props.urls.length > 1}>
                    <IconButton
                      label={`Remove ${url() || "this website"}`}
                      size="sm"
                      class="is-danger"
                      onClick={() => props.onURLs(props.urls.filter((_, position) => position !== index))}
                    >
                      <IconMinus size={15} />
                    </IconButton>
                  </Show>
                }
              >
                <Input
                  class="editor-value"
                  type="url"
                  aria-label={index === 0 ? "Website" : `Website ${index + 1}`}
                  placeholder="https://"
                  value={url()}
                  onInput={(event) =>
                    props.onURLs(props.urls.map((entry, position) => (position === index ? event.currentTarget.value : entry)))
                  }
                />
              </EditorRow>
            )}
          </Index>

          <EditorAdd label="another website" onClick={() => props.onURLs([...props.urls, ""])} />
        </EditorCard>
      </Show>

      <Show when={loose().length > 0}>
        <EditorCard>
          <For each={loose()}>
            {(id) => {
              const index = () => passFieldIndex(props.fields, id);
              return (
                <>
                  <DropSlot
                    controller={controller}
                    parentPath={[]}
                    parentLabel="the field list"
                    index={index()}
                    lane="field"
                    slotKey={id}
                    allFields={() => props.fields}
                  />
                  <FieldRow
                    field={props.fields[index()]!}
                    path={[index()]}
                    controller={controller}
                    allFields={() => props.fields}
                    onMove={moveToParent}
                    onChange={(next) => update(index(), next)}
                    onError={props.onError}
                    onValidity={props.onValidity}
                  />
                </>
              );
            }}
          </For>
          {/* The position after the last row. */}
          <DropSlot
            controller={controller}
            parentPath={[]}
            parentLabel="the field list"
            index={looseEndIndex()}
            lane="field"
            slotKey="end"
            allFields={() => props.fields}
          />
        </EditorCard>
      </Show>

      <For each={sections()}>
        {(id) => {
          const index = () => passFieldIndex(props.fields, id);
          return (
            <>
              <DropSlot
                controller={controller}
                parentPath={[]}
                parentLabel="the section list"
                index={index()}
                lane="section"
                slotKey={id}
                allFields={() => props.fields}
              />
              <SectionCard
                field={props.fields[index()]!}
                path={[index()]}
                controller={controller}
                allFields={() => props.fields}
                atLimit={atLimit()}
                onMove={moveToParent}
                onChange={(next) => update(index(), next)}
                onError={props.onError}
                onValidity={props.onValidity}
              />
            </>
          );
        }}
      </For>
      <Show when={sections().length > 0}>
        <DropSlot
          controller={controller}
          parentPath={[]}
          parentLabel="the section list"
          index={sectionEndIndex()}
          lane="section"
          slotKey="end"
          allFields={() => props.fields}
        />
      </Show>

      <div class="editor-stack-actions">
        <AddFieldButton label="Add field" disabled={atLimit()} depth={0} onAdd={append} />
        <Button size="sm" disabled={atLimit()} onClick={() => append(newPassField("section"))}>
          Add section
        </Button>
        <span class="editor-count" classList={{ "is-warning": atLimit() }}>
          {count()} of {MAX_FIELDS}
        </span>
      </div>

      <EditorCard>
        <EditorRow label="Notes">
          <Textarea
            class="editor-value editor-notes"
            aria-label="Notes"
            rows={3}
            placeholder="Anything worth remembering about this item…"
            value={props.notes}
            onInput={(event) => props.onNotes(event.currentTarget.value)}
          />
        </EditorRow>
      </EditorCard>
    </div>
  );
}

function FieldNameInput(props: {
  field: PassField;
  label?: string;
  section?: boolean;
  onChange(next: PassField): void;
}): JSX.Element {
  const [draft, setDraft] = createSignal(props.field.name);
  let input: HTMLInputElement | undefined;

  createEffect(() => {
    const name = props.field.name;
    if (document.activeElement !== input) setDraft(name);
  });

  const commit = (): void => {
    if (draft() !== props.field.name) props.onChange({ ...props.field, name: draft() });
  };

  return (
    <Input
      ref={input}
      class={props.section ? "editor-name-input editor-section-name" : "editor-name-input"}
      aria-label={props.label ?? "Field name"}
      value={draft()}
      onInput={(event) => setDraft(event.currentTarget.value)}
      onBlur={commit}
      onKeyDown={(event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commit();
          event.currentTarget.blur();
          return;
        }
        if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          setDraft(props.field.name);
          event.currentTarget.blur();
        }
      }}
    />
  );
}

/** A secret row: reveal and generate sit where the value is, not in a menu. */
function SecretRow(props: {
  field: PassField;
  onChange(next: PassField): void;
  menu?: JSX.Element;
  /** Absent in the login card, where the row's position is derived, not chosen. */
  gutter?: JSX.Element;
}): JSX.Element {
  const [open, setOpen] = createSignal(false);
  const [anchor, setAnchor] = createSignal<HTMLButtonElement>();
  return (
    <>
      <EditorRow
        label={<FieldNameInput field={props.field} onChange={props.onChange} />}
        gutter={props.gutter}
        actions={
          <>
            <IconButton ref={setAnchor} label="Generate a value" size="sm" aria-expanded={open()} onClick={() => setOpen((value) => !value)}>
              <IconAdjustmentsHorizontal size={15} />
            </IconButton>
            {props.menu}
          </>
        }
      >
        <SecretInput
          class="editor-value"
          what="value"
          aria-label={props.field.name}
          value={stringValue(props.field)}
          onInput={(event) => props.onChange({ ...props.field, value: event.currentTarget.value })}
        />
      </EditorRow>
      <Popover anchor={anchor()} open={open()} onClose={() => setOpen(false)} align="end" role="dialog" label="Password generator">
        <PasswordGeneratorPopover
          inline
          onClose={() => setOpen(false)}
          onUse={(value) => {
            props.onChange({ ...props.field, value });
            setOpen(false);
          }}
        />
      </Popover>
    </>
  );
}

/** Structure, type and removal actions that do not belong in the value cell. */
function FieldMenu(props: {
  field: PassField;
  path: number[];
  allFields(): PassField[];
  allowRetype?: boolean;
  onMove(sourcePath: number[], targetParentPath: number[]): void;
  onChange(next: PassField | null): void;
}): JSX.Element {
  const destinations = createMemo(() => {
    const fields = props.allFields();
    const options: SectionDestination[] = props.path.length > 1 ? [{ path: [], label: "top level" }] : [];
    options.push(...sectionDestinations(fields));
    return options.filter((destination) => {
      if (samePassFieldPath(destination.path, props.path.slice(0, -1))) return false;
      const target = passFieldListAtPath(fields, destination.path);
      return target && canMovePassFieldTree(fields, props.path, destination.path, target.length);
    });
  });
  const sections = createMemo<MenuSection[]>(() => {
    const result: MenuSection[] = [];
    if (props.allowRetype !== false) {
      result.push({
        id: "type",
        items: fieldTypes
          .filter((type) => type.value !== props.field.type)
          .map((type) => ({
            id: `type-${type.value}`,
            label: `Change to ${type.label.toLowerCase()}`,
            run: () => props.onChange({ ...props.field, type: type.value as PassField["type"], value: "" }),
          })),
      });
    }
    if (destinations().length > 0) {
      result.push({
        id: "move",
        items: destinations().map((destination) => ({
          id: `move-${destination.path.join(".") || "root"}`,
          label: `Move to ${destination.label}`,
          run: () => props.onMove(props.path, destination.path),
        })),
      });
    }
    result.push({
      id: "danger",
      items: [{
        id: "remove",
        label: props.field.type === "section" ? "Remove section" : "Remove field",
        icon: IconTrash,
        danger: true,
        run: () => props.onChange(null),
      }],
    });
    return result;
  });

  return (
    <MenuButton label={`Options for ${props.field.name || "this field"}`} sections={sections()} class="icon-button-sm">
      <IconDotsVertical size={15} />
    </MenuButton>
  );
}

function FieldRow(props: {
  field: PassField;
  path: number[];
  controller: Controller;
  allFields(): PassField[];
  onMove(sourcePath: number[], targetParentPath: number[]): void;
  onChange(next: PassField | null): void;
  onError(message: string): void;
  onValidity(id: string, valid: boolean): void;
}): JSX.Element {
  const draggable = props.controller.draggable;
  const validationID = crypto.randomUUID();
  const [passkeyDraft, setPasskeyDraft] = createSignal(JSON.stringify(props.field.value ?? {}, null, 2));
  const [passkeyError, setPasskeyError] = createSignal("");
  const [totpURI, setTOTPURI] = createSignal("");
  const [totpStatus, setTOTPStatus] = createSignal("");
  const [totpError, setTOTPError] = createSignal("");
  const [totpBusy, setTOTPBusy] = createSignal(false);
  let totpRequest = 0;

  const handle = (
    <button
      class="editor-drag"
      type="button"
      data-drag-handle
      aria-label={`Move ${props.field.name || props.field.type}`}
      title="Drag to move, or press Space for keyboard controls"
    >
      <IconGripVertical size={15} />
    </button>
  );

  async function chooseFile(): Promise<void> {
    try {
      const file = await window.fd0.pickAttachment();
      if (file) props.onChange({ ...props.field, value: file });
    } catch (cause) {
      props.onError(errorText(cause));
    }
  }

  async function importTOTPURI(uri: string): Promise<void> {
    const request = ++totpRequest;
    setTOTPBusy(true);
    setTOTPError("");
    try {
      const value = await window.fd0.parseTOTPURI(uri);
      if (request !== totpRequest) return;
      props.onChange({ ...props.field, value });
      props.onValidity(validationID, true);
      setTOTPURI("");
      setTOTPStatus([value.issuer, value.account].filter(Boolean).join(" · ") || "TOTP account added");
    } catch (cause) {
      if (request !== totpRequest) return;
      setTOTPStatus("");
      setTOTPError(errorText(cause));
      props.onValidity(validationID, false);
    } finally {
      if (request === totpRequest) setTOTPBusy(false);
    }
  }

  return (
    <div
      ref={(element) =>
        draggable(element, () => ({
          id: `field:${props.path.join(".")}`,
          meta: { path: [...props.path], label: props.field.name || props.field.type },
          focusable: false,
          keyboard: true,
          handleSelector: "[data-drag-handle]",
        }))
      }
      data-field-name={props.field.name}
    >
      <Show when={props.field.type === "secret"}>
        <SecretRow
          field={props.field}
          onChange={props.onChange}
          gutter={handle}
          menu={
            <FieldMenu
              field={props.field}
              path={props.path}
              allFields={props.allFields}
              onMove={props.onMove}
              onChange={props.onChange}
            />
          }
        />
      </Show>

      <Show when={props.field.type === "text"}>
        <EditorRow
          label={<FieldNameInput field={props.field} onChange={props.onChange} />}
          gutter={handle}
          actions={
            <FieldMenu
              field={props.field}
              path={props.path}
              allFields={props.allFields}
              onMove={props.onMove}
              onChange={props.onChange}
            />
          }
        >
          <Input
            class="editor-value"
            aria-label={props.field.name}
            value={stringValue(props.field)}
            onInput={(event) => props.onChange({ ...props.field, value: event.currentTarget.value })}
          />
        </EditorRow>
      </Show>

      <Show when={props.field.type === "totp"}>
        <EditorRow
          label={<FieldNameInput field={props.field} onChange={props.onChange} />}
          gutter={handle}
          actions={
            <FieldMenu
              field={props.field}
              path={props.path}
              allFields={props.allFields}
              onMove={props.onMove}
              onChange={props.onChange}
            />
          }
        >
          <div class="editor-subgrid">
            <label class="editor-subgrid-full">
              <span>Setup link</span>
              <Input
                aria-label="TOTP setup link"
                placeholder="Paste an otpauth:// link"
                spellcheck={false}
                value={totpURI()}
                onInput={(event) => {
                  const next = event.currentTarget.value.trim();
                  setTOTPURI(next);
                  setTOTPStatus("");
                  if (!next) {
                    totpRequest += 1;
                    setTOTPBusy(false);
                    setTOTPError("");
                    props.onValidity(validationID, true);
                    return;
                  }
                  if (next.toLocaleLowerCase().startsWith("otpauth://")) {
                    void importTOTPURI(next);
                  } else {
                    // A response for an earlier pasted link must never replace
                    // a value after the user has started correcting the input.
                    totpRequest += 1;
                    setTOTPBusy(false);
                  }
                }}
                onBlur={(event) => {
                  const value = event.currentTarget.value.trim();
                  if (value && !value.toLocaleLowerCase().startsWith("otpauth://")) {
                    void importTOTPURI(value);
                  }
                }}
              />
              <Show when={totpBusy()}>
                <small class="field-message">Reading setup link…</small>
              </Show>
              <Show when={totpStatus()}>
                <small class="field-message is-success">{totpStatus()}</small>
              </Show>
              <Show when={totpError()}>
                <small class="field-message is-error" role="alert">{totpError()}</small>
              </Show>
            </label>
            <label>
              <span>Secret</span>
              <SecretInput
                what="one-time code secret"
                value={String(objectValue(props.field).secret ?? "")}
                onInput={(event) =>
                  props.onChange({
                    ...props.field,
                    value: { ...objectValue(props.field), secret: event.currentTarget.value.toUpperCase().replace(/\s/g, "") },
                  })
                }
              />
            </label>
            <label>
              <span>Digits</span>
              <Select
                label="Digits"
                value={String(objectValue(props.field).digits ?? 6)}
                onChange={(value) => props.onChange({ ...props.field, value: { ...objectValue(props.field), digits: Number(value) } })}
                options={[
                  { value: "6", label: "6" },
                  { value: "8", label: "8" },
                ]}
              />
            </label>
            <label>
              <span>Algorithm</span>
              <Select
                label="Algorithm"
                value={String(objectValue(props.field).algorithm ?? "SHA1")}
                onChange={(value) =>
                  props.onChange({ ...props.field, value: { ...objectValue(props.field), algorithm: value } })
                }
                options={[
                  { value: "SHA1", label: "SHA-1" },
                  { value: "SHA256", label: "SHA-256" },
                  { value: "SHA512", label: "SHA-512" },
                ]}
              />
            </label>
            <label>
              <span>Period</span>
              <Input
                aria-label="TOTP period in seconds"
                type="number"
                min="10"
                max="300"
                value={Number(objectValue(props.field).period ?? 30)}
                onInput={(event) =>
                  props.onChange({
                    ...props.field,
                    value: { ...objectValue(props.field), period: Number(event.currentTarget.value) },
                  })
                }
              />
            </label>
          </div>
        </EditorRow>
      </Show>

      <Show when={props.field.type === "passkey"}>
        <EditorRow
          label={<FieldNameInput field={props.field} onChange={props.onChange} />}
          gutter={handle}
          actions={
            <FieldMenu
              field={props.field}
              path={props.path}
              allFields={props.allFields}
              onMove={props.onMove}
              onChange={props.onChange}
            />
          }
        >
          <Textarea
            class="editor-value editor-json"
            aria-label="Passkey data"
            rows={3}
            spellcheck={false}
            aria-invalid={Boolean(passkeyError())}
            value={passkeyDraft()}
            onInput={(event) => {
              const draft = event.currentTarget.value;
              setPasskeyDraft(draft);
              try {
                props.onChange({ ...props.field, value: JSON.parse(draft) });
                setPasskeyError("");
                props.onValidity(validationID, true);
              } catch {
                setPasskeyError("This needs to be valid JSON before the item can be saved.");
                props.onValidity(validationID, false);
              }
            }}
          />
          <Show when={passkeyError()}>
            <p class="field-message is-error" role="alert">
              {passkeyError()}
            </p>
          </Show>
        </EditorRow>
      </Show>

      <Show when={props.field.type === "file"}>
        <EditorRow
          label={<FieldNameInput field={props.field} onChange={props.onChange} />}
          gutter={handle}
          actions={
            <FieldMenu
              field={props.field}
              path={props.path}
              allFields={props.allFields}
              onMove={props.onMove}
              onChange={props.onChange}
            />
          }
        >
          <div class="editor-file">
            <IconPaperclip size={15} aria-hidden="true" />
            <span class="editor-file-name">{String(objectValue(props.field).name ?? "No file chosen")}</span>
            <Show when={typeof objectValue(props.field).size === "number"}>
              <small>{formatBytes(objectValue(props.field).size as number)}</small>
            </Show>
            <Button size="sm" onClick={() => void chooseFile()}>
              {objectValue(props.field).name ? "Replace…" : "Choose…"}
            </Button>
          </div>
        </EditorRow>
      </Show>
    </div>
  );
}

/**
 * A position a dragged field can land on.
 *
 * The cards have no visible slots between rows, so these collapse to nothing
 * until a drag starts. They must still occupy real height while dragging: a
 * zero-height element never contains the pointer, so the collision detector
 * would find no target and the drop would be silently discarded.
 */
function DropSlot(props: {
  controller: Controller;
  parentPath: number[];
  parentLabel: string;
  index: number;
  lane: PassFieldDropLane;
  slotKey: string;
  allFields(): PassField[];
}): JSX.Element {
  const droppable = props.controller.droppable;
  const activePath = (): number[] | null => {
    const id = props.controller.activeId();
    if (typeof id !== "string" || !id.startsWith("field:")) return null;
    const parts = id.slice("field:".length).split(".");
    const path = parts.map(Number);
    return path.every(Number.isInteger) ? path : null;
  };
  // Dragging only changes order inside the current visual lane. Hierarchy
  // changes are explicit menu actions, so an imprecise drop cannot nest data.
  const disabled = () => {
    const source = activePath();
    if (!source) return false;
    return !canReorderPassFieldTree(props.allFields(), source, props.parentPath, props.index, props.lane);
  };
  return (
    <div
      class="editor-drop-slot"
      ref={(element) =>
        droppable(element, () => ({
          id: `slot:${props.lane}:${props.parentPath.join(".")}:${props.slotKey}`,
          meta: {
            parentPath: [...props.parentPath],
            index: props.index,
            label: `to position ${props.index + 1} in ${props.parentLabel}`,
            lane: props.lane,
          },
          disabled: disabled(),
        }))
      }
      data-drop-parent={props.parentPath.join(".")}
      data-drop-index={props.index}
      data-drop-disabled={disabled()}
    />
  );
}

function SectionCard(props: {
  field: PassField;
  path: number[];
  controller: Controller;
  allFields(): PassField[];
  atLimit: boolean;
  onMove(sourcePath: number[], targetParentPath: number[]): void;
  onChange(next: PassField | null): void;
  onError(message: string): void;
  onValidity(id: string, valid: boolean): void;
}): JSX.Element {
  const draggable = props.controller.draggable;
  const children = () => props.field.fields ?? [];
  const childIDs = createMemo(() => children().map(passFieldUIID));

  return (
    <div class="editor-section">
      {/* The handle sits beside the card, not inside it: dragging moves the
          whole section, and the content stays clean. */}
      <div
        class="editor-section-gutter"
        ref={(element) =>
          draggable(element, () => ({
            id: `field:${props.path.join(".")}`,
            meta: { path: [...props.path], label: props.field.name || "section" },
            focusable: false,
            keyboard: true,
            handleSelector: "[data-drag-handle]",
          }))
        }
      >
        <button
          class="editor-drag"
          type="button"
          data-drag-handle
          aria-label={`Move ${props.field.name || "section"}`}
          title="Drag to move, or press Space for keyboard controls"
        >
          <IconGripVertical size={15} />
        </button>
      </div>

      <EditorCard>
        <EditorCardHeader
          actions={
            <FieldMenu
              field={props.field}
              path={props.path}
              allFields={props.allFields}
              allowRetype={false}
              onMove={props.onMove}
              onChange={props.onChange}
            />
          }
        >
          <FieldNameInput field={props.field} section label="Section name" onChange={props.onChange} />
        </EditorCardHeader>

        <For each={childIDs()}>
          {(id) => {
            const index = () => passFieldIndex(children(), id);
            const child = () => children()[index()]!;
            const onChange = (next: PassField | null): void => {
              const copy = [...children()];
              if (next === null) copy.splice(index(), 1);
              else copy[index()] = carryPassFieldUIID(copy[index()]!, next);
              props.onChange({ ...props.field, fields: copy });
            };
            return (
              <>
                <DropSlot
                  controller={props.controller}
                  parentPath={props.path}
                  parentLabel={props.field.name || "the section"}
                  index={index()}
                  lane="mixed"
                  slotKey={id}
                  allFields={props.allFields}
                />
                <Show
                  when={child().type === "section"}
                  fallback={
                    <FieldRow
                      field={child()}
                      path={[...props.path, index()]}
                      controller={props.controller}
                      allFields={props.allFields}
                      onMove={props.onMove}
                      onChange={onChange}
                      onError={props.onError}
                      onValidity={props.onValidity}
                    />
                  }
                >
                  <SectionCard
                    field={child()}
                    path={[...props.path, index()]}
                    controller={props.controller}
                    allFields={props.allFields}
                    atLimit={props.atLimit}
                    onMove={props.onMove}
                    onChange={onChange}
                    onError={props.onError}
                    onValidity={props.onValidity}
                  />
                </Show>
              </>
            );
          }}
        </For>
        {/* An empty section still needs one target, or nothing could move in. */}
        <DropSlot
          controller={props.controller}
          parentPath={props.path}
          parentLabel={props.field.name || "the section"}
          index={children().length}
          lane="mixed"
          slotKey="end"
          allFields={props.allFields}
        />

        <AddFieldButton
          label="Add field"
          disabled={props.atLimit}
          depth={props.path.length}
          onAdd={(field) => props.onChange({ ...props.field, fields: [...children(), field] })}
        />
      </EditorCard>
    </div>
  );
}

/** The `+` that replaces slash commands: a button whose menu picks the type. */
function AddFieldButton(props: { label: string; disabled?: boolean; depth: number; onAdd(field: PassField): void }): JSX.Element {
  const [open, setOpen] = createSignal(false);
  const [anchor, setAnchor] = createSignal<HTMLButtonElement>();
  const options = () => (props.depth < MAX_DEPTH - 1 ? [...fieldTypes, { value: "section", label: "Section", hint: "Groups fields together" }] : fieldTypes);

  return (
    <>
      <button
        ref={setAnchor}
        class="editor-add"
        type="button"
        disabled={props.disabled}
        aria-expanded={open()}
        onClick={() => setOpen((value) => !value)}
      >
        <span aria-hidden="true">＋</span>
        {props.label}
      </button>
      <Popover anchor={anchor()} open={open()} onClose={() => setOpen(false)} align="start" role="menu" label="Field type" class="menu">
        <For each={options()}>
          {(type) => (
            <button
              type="button"
              role="menuitem"
              class="menu-item kind-option"
              onClick={() => {
                props.onAdd(newPassField(type.value as PassField["type"]));
                setOpen(false);
              }}
            >
              <span class="kind-option-copy">
                <strong>{type.label}</strong>
                <small>{type.hint}</small>
              </span>
            </button>
          )}
        </For>
      </Popover>
    </>
  );
}

/** A new field of the given type, with a sensible starting shape. */
export function newPassField(type: PassField["type"]): PassField {
  switch (type) {
    case "section":
      return { type, name: "New section", fields: [] };
    case "totp":
      return { type, name: "one-time code", value: { secret: "", digits: 6, period: 30, algorithm: "SHA1" } };
    case "passkey":
      return { type, name: "passkey", value: {} };
    case "file":
      return { type, name: "file", value: { name: "", mime: "", size: 0, sha256: "", data_b64: "" } };
    case "secret":
      return { type, name: "password", value: "" };
    default:
      return { type: "text", name: "field", value: "" };
  }
}
