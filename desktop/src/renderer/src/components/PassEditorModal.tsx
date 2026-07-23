import { For, Show, createSignal, onCleanup, type Accessor, type JSX } from "solid-js";
import {
  IconAdjustmentsHorizontal,
  IconEye,
  IconEyeOff,
  IconFolder,
  IconGripVertical,
  IconPlus,
  IconTrash,
  IconX,
} from "@tabler/icons-solidjs";
import { dnd, type DndController } from "@valentinkolb/stdlib/solid";
import type { PassField, SavePassInput } from "../../../shared/contracts";
import { errorText } from "../errors";
import { IconButton, SelectControl } from "./Controls";
import { PasswordGeneratorPopover } from "./PasswordGenerator";
import { canMovePassFieldTree, countPassFields, movePassFieldTree, updatePassFieldTree } from "./passEditorTree";

type PassFieldDragMeta = {
  path: number[];
  label: string;
};

type PassFieldDropMeta = {
  parentPath: number[];
  index: number;
  label: string;
};

type PassFieldDnd = DndController<PassFieldDragMeta, PassFieldDropMeta, null>;

export function PassEditorModal(props: {
  input: SavePassInput;
  onClose(): void;
  onSaved(): Promise<void>;
}): JSX.Element {
  const [title, setTitle] = createSignal(props.input.item.title);
  const [url, setURL] = createSignal(props.input.item.urls?.[0] ?? "");
  const [fields, setFields] = createSignal<PassField[]>(structuredClone(props.input.item.fields ?? []));
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  const [invalidFields, setInvalidFields] = createSignal<Set<string>>(new Set());

  const fieldDnd = dnd.create<PassFieldDragMeta, PassFieldDropMeta, null>({
    collisionDetector: ({ droppables }) => {
      const hits = droppables.filter((entry) => entry.containsPointer);
      if (hits.length === 0) return null;
      return hits.reduce((closest, entry) => entry.distance < closest.distance ? entry : closest).id;
    },
    onDragStart: () => setError(""),
    onDrop: ({ active, over }) => {
      if (!over) return;
      const next = movePassFieldTree(fields(), active.meta.path, over.meta.parentPath, over.meta.index);
      if (next !== fields()) setFields(next);
    },
    announcements: {
      dragStart: (active) => `Picked up ${active.meta.label}. Use arrow keys to choose a position, then press Enter to drop.`,
      dragOver: (active, over) => over ? `Move ${active.meta.label} ${over.meta.label}.` : `No valid position for ${active.meta.label}.`,
      drop: (active, over) => over ? `Moved ${active.meta.label} ${over.meta.label}.` : `Move cancelled for ${active.meta.label}.`,
      cancel: (active) => `Move cancelled for ${active.meta.label}.`,
    },
  });

  function updateField(path: number[], next: PassField | null): void {
    setFields((current) => updatePassFieldTree(current, path, next));
  }

  async function save(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (invalidFields().size > 0) {
      setError("Fix invalid field data before saving.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await window.fd0.savePass({
        scopeId: props.input.scopeId,
        recordName: props.input.recordName,
        authorization: props.input.authorization,
        item: {
          ...props.input.item,
          title: title().trim(),
          urls: url().trim() ? [url().trim()] : [],
          fields: fields(),
        },
      });
      await props.onSaved();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="modal-backdrop" role="presentation" onPointerDown={(event) => event.target === event.currentTarget && props.onClose()}>
      <section class="modal pass-editor-modal" role="dialog" aria-modal="true" aria-labelledby="edit-pass-title">
        <header>
          <h1 id="edit-pass-title">Edit password</h1>
          <IconButton label="Close" onClick={props.onClose}><IconX size={18} /></IconButton>
        </header>
        <form onSubmit={save}>
          <div class="pass-editor-content">
            <div class="form-grid">
              <label><span>Title</span><input required value={title()} onInput={(event) => setTitle(event.currentTarget.value)} /></label>
              <label><span>Website</span><input type="url" value={url()} onInput={(event) => setURL(event.currentTarget.value)} /></label>
            </div>
            <div classList={{ "editor-fields": true, dragging: fieldDnd.isDragging() }}>
              <div class="editor-fields-heading"><span>Fields</span><small>{countPassFields(fields())} of 128</small></div>
              <PassFieldList
                fields={fields()}
                parentPath={[]}
                parentLabel="top level"
                controller={fieldDnd}
                allFields={fields}
                onChange={updateField}
                onError={setError}
                onValidity={(id, valid) => {
                  setInvalidFields((current) => {
                    const next = new Set(current);
                    if (valid) next.delete(id);
                    else next.add(id);
                    return next;
                  });
                }}
              />
              <AddFieldControl depth={0} onAdd={(field) => setFields((current) => [...current, field])} />
            </div>
            <Show when={error()}><div class="inline-error" role="alert">{error()}</div></Show>
          </div>
          <footer>
            <button class="secondary-button" type="button" onClick={props.onClose}>Cancel</button>
            <button class="primary-button" type="submit" disabled={busy()}>{busy() ? "Saving…" : "Save changes"}</button>
          </footer>
        </form>
      </section>
    </div>
  );
}

function PassFieldList(props: {
  fields: PassField[];
  parentPath: number[];
  parentLabel: string;
  controller: PassFieldDnd;
  allFields: Accessor<PassField[]>;
  onChange(path: number[], field: PassField | null): void;
  onError(message: string): void;
  onValidity(id: string, valid: boolean): void;
}): JSX.Element {
  return (
    <div class="pass-field-list" role="list" aria-label={`${props.parentLabel} fields`}>
      <For each={props.fields}>
        {(field, index) => (
          <>
            <PassFieldDropSlot
              parentPath={props.parentPath}
              parentLabel={props.parentLabel}
              index={index()}
              controller={props.controller}
              allFields={props.allFields}
            />
            <PassFieldEditor
              field={field}
              path={[...props.parentPath, index()]}
              controller={props.controller}
              allFields={props.allFields}
              onChange={props.onChange}
              onError={props.onError}
              onValidity={props.onValidity}
            />
          </>
        )}
      </For>
      <PassFieldDropSlot
        parentPath={props.parentPath}
        parentLabel={props.parentLabel}
        index={props.fields.length}
        empty={props.fields.length === 0}
        controller={props.controller}
        allFields={props.allFields}
      />
    </div>
  );
}

function PassFieldDropSlot(props: {
  parentPath: number[];
  parentLabel: string;
  index: number;
  empty?: boolean;
  controller: PassFieldDnd;
  allFields: Accessor<PassField[]>;
}): JSX.Element {
  const droppable = props.controller.droppable;
  const activePath = () => parseFieldDragID(props.controller.activeId());
  const disabled = () => {
    const sourcePath = activePath();
    return sourcePath ? !canMovePassFieldTree(props.allFields(), sourcePath, props.parentPath, props.index) : false;
  };
  return (
    <div
      ref={(element) => droppable(element, () => ({
        id: fieldDropID(props.parentPath, props.index),
        meta: {
          parentPath: [...props.parentPath],
          index: props.index,
          label: `at position ${props.index + 1} in ${props.parentLabel}`,
        },
        disabled: disabled(),
      }))}
      classList={{ "pass-field-drop-slot": true, empty: Boolean(props.empty) }}
      data-drop-parent={fieldPathKey(props.parentPath)}
      data-drop-index={props.index}
    >
      <span>Drop field here</span>
    </div>
  );
}

function PassFieldEditor(props: {
  field: PassField;
  path: number[];
  controller: PassFieldDnd;
  allFields: Accessor<PassField[]>;
  onChange(path: number[], field: PassField | null): void;
  onError(message: string): void;
  onValidity(id: string, valid: boolean): void;
}): JSX.Element {
  const draggable = props.controller.draggable;
  const valueObject = () => (typeof props.field.value === "object" && props.field.value ? props.field.value as Record<string, unknown> : {});
  const change = (next: PassField | null) => props.onChange(props.path, next);
  const updateValueKey = (key: string, value: unknown) => change({ ...props.field, value: { ...valueObject(), [key]: value } });
  const validationID = crypto.randomUUID();
  const [passkeyDraft, setPasskeyDraft] = createSignal(JSON.stringify(props.field.value ?? {}, null, 2));
  const [passkeyError, setPasskeyError] = createSignal("");
  const [valueVisible, setValueVisible] = createSignal(false);
  const [generatorOpen, setGeneratorOpen] = createSignal(false);

  onCleanup(() => props.onValidity(validationID, true));

  async function chooseFile(): Promise<void> {
    try {
      const file = await window.fd0.pickAttachment();
      if (file) change({ ...props.field, value: file });
    } catch (cause) {
      props.onError(errorText(cause));
    }
  }

  return (
    <div
      ref={(element) => draggable(element, () => ({
        id: fieldDragID(props.path),
        meta: { path: [...props.path], label: props.field.name || props.field.type },
        focusable: false,
        keyboard: true,
        handleSelector: "[data-drag-handle]",
      }))}
      classList={{ "pass-field-editor": true, section: props.field.type === "section" }}
      data-field-name={props.field.name}
      role="listitem"
    >
      <button class="pass-field-drag-handle" type="button" data-drag-handle aria-label={`Move ${props.field.name || props.field.type}`} title="Drag to move; press Space for keyboard controls">
        <IconGripVertical size={17} />
      </button>
      <div class="pass-field-content" onKeyDown={(event) => {
        if ([" ", "Enter", "Escape", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(event.key)) event.stopPropagation();
      }}>
        <div class="pass-field-head" data-dnd-preview>
          <input aria-label="Field name" value={props.field.name} onInput={(event) => change({ ...props.field, name: event.currentTarget.value })} />
          <span class="field-type-label">{props.field.type}</span>
          <IconButton label={`Remove ${props.field.name || "field"}`} onClick={() => change(null)}><IconTrash size={16} /></IconButton>
        </div>
        <Show when={props.field.type === "text" || props.field.type === "secret"}>
          <div class="editor-value-row">
            <Show
              when={props.field.type === "secret"}
              fallback={<input aria-label={`${props.field.name} value`} spellcheck={false} value={typeof props.field.value === "string" ? props.field.value : ""} onInput={(event) => change({ ...props.field, value: event.currentTarget.value })} />}
            >
              <div class="password-entry-control editor-password-entry">
                <input aria-label={`${props.field.name} value`} type={valueVisible() ? "text" : "password"} spellcheck={false} value={typeof props.field.value === "string" ? props.field.value : ""} onInput={(event) => change({ ...props.field, value: event.currentTarget.value })} />
                <button type="button" aria-label={valueVisible() ? "Hide field value" : "Show field value"} title={valueVisible() ? "Hide field value" : "Show field value"} onClick={() => setValueVisible((visible) => !visible)}>
                  {valueVisible() ? <IconEyeOff size={17} /> : <IconEye size={17} />}
                </button>
                <div class="password-generator-anchor">
                  <button type="button" aria-label="Password generator options" title="Password generator options" aria-expanded={generatorOpen()} onClick={() => setGeneratorOpen((open) => !open)}><IconAdjustmentsHorizontal size={17} /></button>
                </div>
              </div>
            </Show>
          </div>
          <Show when={props.field.type === "secret" && generatorOpen()}>
            <PasswordGeneratorPopover
              inline
              onClose={() => setGeneratorOpen(false)}
              onUse={(value) => {
                change({ ...props.field, value });
                setGeneratorOpen(false);
              }}
            />
          </Show>
        </Show>
        <Show when={props.field.type === "totp"}>
          <div class="totp-editor-grid">
            <label><span>Secret</span><input type="password" value={String(valueObject().secret ?? "")} onInput={(event) => updateValueKey("secret", event.currentTarget.value.toUpperCase().replace(/\s/g, ""))} /></label>
            <label><span>Issuer</span><input value={String(valueObject().issuer ?? "")} onInput={(event) => updateValueKey("issuer", event.currentTarget.value)} /></label>
            <label><span>Account</span><input value={String(valueObject().account ?? "")} onInput={(event) => updateValueKey("account", event.currentTarget.value)} /></label>
            <label><span>Digits</span><SelectControl value={String(valueObject().digits ?? 6)} onChange={(event) => updateValueKey("digits", Number(event.currentTarget.value))}><option value="6">6</option><option value="8">8</option></SelectControl></label>
          </div>
        </Show>
        <Show when={props.field.type === "passkey"}>
          <label class="json-editor"><span>Passkey data</span><textarea value={passkeyDraft()} onInput={(event) => {
            const draft = event.currentTarget.value;
            setPasskeyDraft(draft);
            try {
              change({ ...props.field, value: JSON.parse(draft) });
              setPasskeyError("");
              props.onValidity(validationID, true);
            } catch {
              setPasskeyError("Enter valid JSON.");
              props.onValidity(validationID, false);
            }
          }} /></label>
          <Show when={passkeyError()}><div class="inline-error">{passkeyError()}</div></Show>
        </Show>
        <Show when={props.field.type === "file"}>
          <div class="attachment-editor">
            <IconFolder size={18} />
            <span>{String(valueObject().name ?? "No file selected")}</span>
            <small>{typeof valueObject().size === "number" ? formatBytes(valueObject().size as number) : ""}</small>
            <button class="secondary-button" type="button" onClick={() => void chooseFile()}>{valueObject().name ? "Replace…" : "Choose…"}</button>
          </div>
        </Show>
        <Show when={props.field.type === "section"}>
          <div class="section-children">
            <PassFieldList
              fields={props.field.fields ?? []}
              parentPath={props.path}
              parentLabel={props.field.name || "section"}
              controller={props.controller}
              allFields={props.allFields}
              onChange={props.onChange}
              onError={props.onError}
              onValidity={props.onValidity}
            />
            <AddFieldControl depth={props.path.length} onAdd={(field) => change({ ...props.field, fields: [...(props.field.fields ?? []), field] })} />
          </div>
        </Show>
      </div>
    </div>
  );
}

function AddFieldControl(props: { depth: number; onAdd(field: PassField): void }): JSX.Element {
  const [type, setType] = createSignal<PassField["type"]>("text");
  return (
    <div class="add-field-control">
      <SelectControl aria-label="New field type" value={type()} onChange={(event) => setType(event.currentTarget.value as PassField["type"])}>
        <option value="text">Text</option>
        <option value="secret">Secret</option>
        <option value="totp">One-time password</option>
        <option value="passkey">Passkey data</option>
        <option value="file">Small file</option>
        <Show when={props.depth < 4}><option value="section">Section</option></Show>
      </SelectControl>
      <button class="secondary-button" type="button" onClick={() => props.onAdd(newPassField(type()))}><IconPlus size={15} />Add field</button>
    </div>
  );
}

function newPassField(type: PassField["type"]): PassField {
  switch (type) {
    case "section": return { type, name: "New section", fields: [] };
    case "totp": return { type, name: "one-time password", value: { secret: "", digits: 6, period: 30, algorithm: "SHA1" } };
    case "passkey": return { type, name: "passkey", value: {} };
    case "file": return { type, name: "file", value: { name: "", size: 0, sha256: "", data_b64: "" } };
    case "secret": return { type, name: "secret", value: "" };
    default: return { type: "text", name: "text", value: "" };
  }
}

function fieldDragID(path: number[]): string {
  return `pass-field:${path.join(".")}`;
}

function parseFieldDragID(id: string | null): number[] | null {
  if (!id?.startsWith("pass-field:")) return null;
  const value = id.slice("pass-field:".length);
  if (!value) return null;
  const path = value.split(".").map(Number);
  return path.every((part) => Number.isInteger(part) && part >= 0) ? path : null;
}

function fieldDropID(parentPath: number[], index: number): string {
  return `pass-drop:${fieldPathKey(parentPath)}:${index}`;
}

function fieldPathKey(path: number[]): string {
  return path.length === 0 ? "root" : path.join(".");
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}
