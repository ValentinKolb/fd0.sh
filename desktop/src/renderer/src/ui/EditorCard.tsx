import { Show, type JSX } from "solid-js";
import { IconPlus } from "@tabler/icons-solidjs";

/**
 * A group of related rows sharing one rounded container.
 *
 * The container is the grouping device, so a field no longer needs a box of its
 * own. Seven fields read as three blocks rather than seven cards.
 */
export function EditorCard(props: { class?: string; children: JSX.Element }): JSX.Element {
  return <div classList={{ "editor-card": true, [props.class ?? ""]: Boolean(props.class) }}>{props.children}</div>;
}

/**
 * One row: the label sits small and quiet ABOVE the value, in the same cell.
 *
 * That is the move that stops the editor reading as `{key: value}` rendered
 * into form controls — the name is text, not a control, so changing a value
 * never competes with renaming the field.
 */
export function EditorRow(props: {
  label: string;
  /** Rendered to the right of the value, e.g. reveal and generate. */
  actions?: JSX.Element;
  /** Shown in the left gutter; used for drag handles. */
  gutter?: JSX.Element;
  children: JSX.Element;
}): JSX.Element {
  return (
    <div class="editor-row">
      <Show when={props.gutter}>
        <span class="editor-row-gutter">{props.gutter}</span>
      </Show>
      <span class="editor-cell">
        <span class="editor-cell-label">{props.label}</span>
        {props.children}
      </span>
      <Show when={props.actions}>
        <span class="editor-row-actions">{props.actions}</span>
      </Show>
    </div>
  );
}

/** A card's own add control. Adding happens where the thing belongs. */
export function EditorAdd(props: { label: string; expanded?: boolean; onClick(): void }): JSX.Element {
  return (
    <button
      class="editor-add"
      type="button"
      aria-expanded={props.expanded}
      onClick={props.onClick}
    >
      <IconPlus size={14} aria-hidden="true" />
      {props.label}
    </button>
  );
}

/** A section card's title bar. */
export function EditorCardHeader(props: { children: JSX.Element; actions?: JSX.Element }): JSX.Element {
  return (
    <div class="editor-card-header">
      <span class="editor-card-title">{props.children}</span>
      <Show when={props.actions}>
        <span class="editor-row-actions">{props.actions}</span>
      </Show>
    </div>
  );
}
