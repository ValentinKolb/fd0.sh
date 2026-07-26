import { For, type JSX } from "solid-js";
import { Modal } from "../ui/Modal";
import { Kbd } from "../ui/Button";

const groups: Array<{ title: string; rows: Array<{ keys: string; what: string }> }> = [
  {
    title: "Everywhere",
    rows: [
      { keys: "mod+k", what: "Search items and run commands" },
      { keys: "mod+n", what: "New item" },
      { keys: "mod+shift+l", what: "Lock fd0" },
      { keys: "mod+,", what: "Settings" },
      { keys: "mod+/", what: "This shortcut list" },
      { keys: "esc", what: "Close the topmost dialog" },
    ],
  },
  {
    title: "Item list",
    rows: [
      { keys: "↑ ↓", what: "Move between items" },
      { keys: "enter", what: "Open the selected item" },
      { keys: "mod+c", what: "Copy the selected item's password" },
      { keys: "home", what: "Jump to the first item" },
      { keys: "end", what: "Jump to the last item" },
    ],
  },
  {
    title: "Search palette",
    rows: [
      { keys: "↑ ↓", what: "Move between results" },
      { keys: "enter", what: "Open the highlighted item" },
      { keys: "mod+enter", what: "Copy its password without opening it" },
    ],
  },
];

export function Shortcuts(props: { onClose(): void }): JSX.Element {
  return (
    <Modal
      title="Keyboard shortcuts"
      description="fd0 is fully operable without a mouse."
      size="small"
      onClose={props.onClose}
    >
      <div class="shortcut-groups">
        <For each={groups}>
          {(group) => (
            <section class="shortcut-group">
              <h2 class="section-heading">{group.title}</h2>
              <For each={group.rows}>
                {(row) => (
                  <div class="shortcut-row">
                    <span>{row.what}</span>
                    <Kbd keys={row.keys} />
                  </div>
                )}
              </For>
            </section>
          )}
        </For>
      </div>
    </Modal>
  );
}
