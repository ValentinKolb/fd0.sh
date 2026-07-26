import { For, Show, createSignal, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
import type { Component } from "solid-js";
import type { IconProps } from "@tabler/icons-solidjs";
import { Popover, listNavigation, type PopoverAlign } from "./Popover";

export type MenuItem = {
  id: string;
  label: string;
  icon?: Component<IconProps>;
  hint?: string;
  danger?: boolean;
  disabled?: boolean;
  /** Explains why the item is unavailable. Shown instead of silently hiding it. */
  disabledReason?: string;
  run(): void;
};

export type MenuSection = {
  id: string;
  items: MenuItem[];
};

/**
 * A trigger plus its menu. The menu portals out of any scrolling ancestor, so
 * it is never clipped by a modal body or an editor pane.
 */
export function MenuButton(props: {
  label: string;
  sections: MenuSection[];
  align?: PopoverAlign;
  class?: string;
  children: JSX.Element;
}): JSX.Element {
  const [open, setOpen] = createSignal(false);
  const [trigger, setTrigger] = createSignal<HTMLButtonElement>();

  return (
    <>
      <button
        ref={setTrigger}
        type="button"
        classList={{ "icon-button": true, "is-active": open(), [props.class ?? ""]: Boolean(props.class) }}
        aria-label={props.label}
        title={props.label}
        aria-haspopup="menu"
        aria-expanded={open()}
        onClick={() => setOpen((current) => !current)}
        onKeyDown={(event) => {
          if (event.key !== "ArrowDown" && event.key !== "Enter" && event.key !== " ") return;
          if (open()) return;
          event.preventDefault();
          setOpen(true);
          queueMicrotask(() => {
            document.querySelector<HTMLElement>('.popover [role="menuitem"]')?.focus();
          });
        }}
      >
        {props.children}
      </button>
      <Popover
        anchor={trigger()}
        open={open()}
        onClose={() => setOpen(false)}
        align={props.align ?? "end"}
        role="menu"
        label={props.label}
        class="menu"
      >
        <div onKeyDown={listNavigation({ onEscape: () => setOpen(false) })}>
          <For each={props.sections}>
            {(section, index) => (
              <>
                <Show when={index() > 0}>
                  <div class="menu-separator" role="separator" />
                </Show>
                <For each={section.items}>
                  {(item) => (
                    <button
                      type="button"
                      role="menuitem"
                      classList={{ "menu-item": true, "is-danger": item.danger }}
                      disabled={item.disabled}
                      title={item.disabled ? item.disabledReason : undefined}
                      onClick={() => {
                        setOpen(false);
                        item.run();
                      }}
                    >
                      <Show when={item.icon}>
                        {(icon) => <Dynamic component={icon()} size={16} strokeWidth={1.7} />}
                      </Show>
                      <span class="menu-item-label">{item.label}</span>
                      <Show when={item.disabled ? item.disabledReason : item.hint}>
                        <span class="menu-item-hint">{item.disabled ? item.disabledReason : item.hint}</span>
                      </Show>
                    </button>
                  )}
                </For>
              </>
            )}
          </For>
        </div>
      </Popover>
    </>
  );
}
