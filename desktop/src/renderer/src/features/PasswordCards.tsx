import { For, Show, createEffect, createMemo, createSignal, onCleanup, type JSX } from "solid-js";
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
import { canMovePassFieldTree, countPassFields, movePassFieldTree } from "../components/passEditorTree";

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
type DropMeta = { parentPath: number[]; index: number; label: string };
type Controller = DndController<DragMeta, DropMeta, null>;

const stringValue = (field: PassField): string => (typeof field.value === "string" ? field.value : "");
const objectValue = (field: PassField): Record<string, unknown> =>
  typeof field.value === "object" && field.value ? (field.value as Record<string, unknown>) : {};

/**
 * The password editor, built as grouped cards.
 *
 * Three ideas carry it. The label sits above the value inside one cell, so a
 * field name is text rather than a control. Related rows share a card, so the
 * count of visible boxes stays low. And adding happens inside the card the new
 * field belongs to, rather than at one global button.
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
      const next = movePassFieldTree(props.fields, active.meta.path, over.meta.parentPath, over.meta.index);
      if (next !== props.fields) props.onFields(next);
    },
    announcements: {
      dragStart: (active) => `Picked up ${active.meta.label}. Use arrow keys to choose a position, then press Enter to drop.`,
      dragOver: (active, over) => (over ? `Move ${active.meta.label} ${over.meta.label}.` : `No valid position for ${active.meta.label}.`),
      drop: (active, over) => (over ? `Moved ${active.meta.label} ${over.meta.label}.` : `Move cancelled for ${active.meta.label}.`),
      cancel: (active) => `Move cancelled for ${active.meta.label}.`,
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
      .filter((entry) => entry.field.type !== "section" && !isClaimed(props.fields, entry.index, recognised())),
  );
  const sections = createMemo(() =>
    props.fields.map((field, index) => ({ field, index })).filter((entry) => entry.field.type === "section"),
  );

  function update(index: number, next: PassField | null): void {
    const copy = [...props.fields];
    if (next === null) copy.splice(index, 1);
    else copy[index] = next;
    props.onFields(copy);
  }

  function append(field: PassField): void {
    props.onFields([...props.fields, field]);
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
              <EditorRow label={field().name} actions={<FieldMenu field={field()} onChange={(next) => update(recognised().username, next)} />}>
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
                menu={<FieldMenu field={field()} onChange={(next) => update(recognised().secret, next)} />}
              />
            )}
          </Show>

          {/* urls is a first-class array in the schema, so more than one is
              normal rather than an edge case. */}
          <For each={props.urls}>
            {(url, index) => (
              <EditorRow
                label={index() === 0 ? "Website" : "Website (alternative)"}
                actions={
                  <Show when={props.urls.length > 1}>
                    <IconButton
                      label={`Remove ${url || "this website"}`}
                      size="sm"
                      class="is-danger"
                      onClick={() => props.onURLs(props.urls.filter((_, position) => position !== index()))}
                    >
                      <IconMinus size={15} />
                    </IconButton>
                  </Show>
                }
              >
                <Input
                  class="editor-value"
                  type="url"
                  aria-label={index() === 0 ? "Website" : `Website ${index() + 1}`}
                  placeholder="https://"
                  value={url}
                  onInput={(event) =>
                    props.onURLs(props.urls.map((entry, position) => (position === index() ? event.currentTarget.value : entry)))
                  }
                />
              </EditorRow>
            )}
          </For>

          <EditorAdd label="another website" onClick={() => props.onURLs([...props.urls, ""])} />
        </EditorCard>
      </Show>

      <Show when={loose().length > 0}>
        <EditorCard>
          <For each={loose()}>
            {(entry) => (
              <>
                <DropSlot
                  controller={controller}
                  parentPath={[]}
                  parentLabel="the field list"
                  index={entry.index}
                  allFields={() => props.fields}
                />
                <FieldRow
                  field={entry.field}
                  path={[entry.index]}
                  controller={controller}
                  allFields={() => props.fields}
                  onChange={(next) => update(entry.index, next)}
                  onError={props.onError}
                  onValidity={props.onValidity}
                />
              </>
            )}
          </For>
          {/* The position after the last row. */}
          <DropSlot
            controller={controller}
            parentPath={[]}
            parentLabel="the field list"
            index={props.fields.length}
            allFields={() => props.fields}
          />
        </EditorCard>
      </Show>

      <For each={sections()}>
        {(entry) => (
          <SectionCard
            field={entry.field}
            path={[entry.index]}
            controller={controller}
            allFields={() => props.fields}
            atLimit={atLimit()}
            onChange={(next) => update(entry.index, next)}
            onError={props.onError}
            onValidity={props.onValidity}
          />
        )}
      </For>

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

      <div class="editor-stack-actions">
        <AddFieldButton label="Add field" disabled={atLimit()} depth={0} onAdd={append} />
        <Button size="sm" disabled={atLimit()} onClick={() => append(newPassField("section"))}>
          Add section
        </Button>
        <span class="editor-count" classList={{ "is-warning": atLimit() }}>
          {count()} of {MAX_FIELDS}
        </span>
      </div>
    </div>
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
        label={props.field.name}
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

/** Rename, retype and remove live here so they never crowd the value. */
function FieldMenu(props: { field: PassField; onChange(next: PassField | null): void }): JSX.Element {
  const [renaming, setRenaming] = createSignal(false);
  const sections = createMemo<MenuSection[]>(() => [
    {
      id: "edit",
      items: [
        { id: "rename", label: "Rename…", run: () => setRenaming(true) },
        ...fieldTypes
          .filter((type) => type.value !== props.field.type)
          .map((type) => ({
            id: `type-${type.value}`,
            label: `Change to ${type.label.toLowerCase()}`,
            run: () => props.onChange({ ...props.field, type: type.value as PassField["type"], value: "" }),
          })),
      ],
    },
    {
      id: "danger",
      items: [{ id: "remove", label: "Remove field", icon: IconTrash, danger: true, run: () => props.onChange(null) }],
    },
  ]);

  return (
    <>
      <MenuButton label={`Options for ${props.field.name || "this field"}`} sections={sections()} class="icon-button-sm">
        <IconDotsVertical size={15} />
      </MenuButton>
      <Show when={renaming()}>
        <Input
          class="editor-rename"
          aria-label="Field name"
          autofocus
          value={props.field.name}
          onInput={(event) => props.onChange({ ...props.field, name: event.currentTarget.value })}
          onBlur={() => setRenaming(false)}
          onKeyDown={(event) => {
            // Enter confirms the rename and nothing else. Without preventDefault
            // it also submits the surrounding form, saving the whole item.
            if (event.key === "Enter") {
              event.preventDefault();
              setRenaming(false);
              return;
            }
            // Escape leaves the rename box, not the editor, so it must not reach
            // the modal's own Escape handler.
            if (event.key === "Escape") {
              event.preventDefault();
              event.stopPropagation();
              setRenaming(false);
            }
          }}
        />
      </Show>
    </>
  );
}

function FieldRow(props: {
  field: PassField;
  path: number[];
  controller: Controller;
  allFields(): PassField[];
  onChange(next: PassField | null): void;
  onError(message: string): void;
  onValidity(id: string, valid: boolean): void;
}): JSX.Element {
  const draggable = props.controller.draggable;
  const validationID = crypto.randomUUID();
  const [passkeyDraft, setPasskeyDraft] = createSignal(JSON.stringify(props.field.value ?? {}, null, 2));
  const [passkeyError, setPasskeyError] = createSignal("");

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
          menu={<FieldMenu field={props.field} onChange={props.onChange} />}
        />
      </Show>

      <Show when={props.field.type === "text"}>
        <EditorRow label={props.field.name} gutter={handle} actions={<FieldMenu field={props.field} onChange={props.onChange} />}>
          <Input
            class="editor-value"
            aria-label={props.field.name}
            value={stringValue(props.field)}
            onInput={(event) => props.onChange({ ...props.field, value: event.currentTarget.value })}
          />
        </EditorRow>
      </Show>

      <Show when={props.field.type === "totp"}>
        <EditorRow label={props.field.name} gutter={handle} actions={<FieldMenu field={props.field} onChange={props.onChange} />}>
          <div class="editor-subgrid">
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
          </div>
        </EditorRow>
      </Show>

      <Show when={props.field.type === "passkey"}>
        <EditorRow label={props.field.name} gutter={handle} actions={<FieldMenu field={props.field} onChange={props.onChange} />}>
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
        <EditorRow label={props.field.name} gutter={handle} actions={<FieldMenu field={props.field} onChange={props.onChange} />}>
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
  // A field cannot land inside itself, and a section cannot be nested past the
  // depth limit. Marking those slots disabled keeps them out of the running
  // rather than accepting a drop that movePassFieldTree would refuse anyway.
  const disabled = () => {
    const source = activePath();
    return source ? !canMovePassFieldTree(props.allFields(), source, props.parentPath, props.index) : false;
  };
  return (
    <div
      class="editor-drop-slot"
      ref={(element) =>
        droppable(element, () => ({
          id: `slot:${props.parentPath.join(".")}:${props.index}`,
          meta: {
            parentPath: [...props.parentPath],
            index: props.index,
            label: `to position ${props.index + 1} in ${props.parentLabel}`,
          },
          disabled: disabled(),
        }))
      }
      data-drop-parent={props.parentPath.join(".")}
      data-drop-index={props.index}
    />
  );
}

function SectionCard(props: {
  field: PassField;
  path: number[];
  controller: Controller;
  allFields(): PassField[];
  atLimit: boolean;
  onChange(next: PassField | null): void;
  onError(message: string): void;
  onValidity(id: string, valid: boolean): void;
}): JSX.Element {
  const draggable = props.controller.draggable;
  const children = () => props.field.fields ?? [];

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
            <IconButton label={`Remove ${props.field.name || "section"}`} size="sm" class="is-danger" onClick={() => props.onChange(null)}>
              <IconMinus size={15} />
            </IconButton>
          }
        >
          <Input
            class="editor-section-name"
            aria-label="Section name"
            value={props.field.name}
            onInput={(event) => props.onChange({ ...props.field, name: event.currentTarget.value })}
          />
        </EditorCardHeader>

        <For each={children()}>
          {(child, index) => (
            <>
              <DropSlot
                controller={props.controller}
                parentPath={props.path}
                parentLabel={props.field.name || "the section"}
                index={index()}
                allFields={props.allFields}
              />
              <FieldRow
                field={child}
                path={[...props.path, index()]}
                controller={props.controller}
                allFields={props.allFields}
                onChange={(next) => {
                  const copy = [...children()];
                  if (next === null) copy.splice(index(), 1);
                  else copy[index()] = next;
                  props.onChange({ ...props.field, fields: copy });
                }}
                onError={props.onError}
                onValidity={props.onValidity}
              />
            </>
          )}
        </For>
        {/* An empty section still needs one target, or nothing could move in. */}
        <DropSlot
          controller={props.controller}
          parentPath={props.path}
          parentLabel={props.field.name || "the section"}
          index={children().length}
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
