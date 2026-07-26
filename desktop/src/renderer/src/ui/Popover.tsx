import { Show, createEffect, createSignal, onCleanup, type JSX } from "solid-js";
import { Portal } from "solid-js/web";
import { isTopOverlay, popOverlay, pushOverlay } from "./overlayStack";

export type PopoverAlign = "start" | "end" | "center";

type PopoverProps = {
  /** The element the popover is anchored to. Positioning follows its rect. */
  anchor: HTMLElement | undefined;
  open: boolean;
  onClose(): void;
  /** Preferred side. Flips automatically when there is not enough room. */
  side?: "bottom" | "top";
  align?: PopoverAlign;
  /** Distance between anchor and popover, in px. */
  gap?: number;
  /** Sizes the popover to the anchor. Used by Select so the list lines up. */
  matchAnchorWidth?: boolean;
  class?: string;
  role?: "menu" | "listbox" | "dialog" | "group";
  label?: string;
  /** Return focus here when the popover closes. Defaults to the anchor. */
  returnFocus?: HTMLElement | undefined;
  children: JSX.Element;
};

/**
 * Popovers render into a portal on <body> with `position: fixed`.
 *
 * This is deliberate: any ancestor with `overflow: auto|hidden` clips absolutely
 * positioned descendants regardless of z-index. The modal body and the pass
 * editor are both scroll containers, so an in-flow popover loses its bottom
 * rows there — measured at 42px of the item-type menu, which removed "Talos"
 * from the list entirely. Portalling removes the whole class of bug.
 */
export function Popover(props: PopoverProps): JSX.Element {
  const [element, setElement] = createSignal<HTMLDivElement>();
  const [position, setPosition] = createSignal({ left: 0, top: 0, maxHeight: 0, ready: false });

  function place(): void {
    const anchor = props.anchor;
    const node = element();
    if (!anchor || !node) return;

    const gap = props.gap ?? 6;
    const margin = 8;
    const rect = anchor.getBoundingClientRect();
    if (props.matchAnchorWidth) node.style.minWidth = `${rect.width}px`;
    const width = node.offsetWidth;
    const height = node.offsetHeight;
    const viewportWidth = document.documentElement.clientWidth;
    const viewportHeight = document.documentElement.clientHeight;

    const spaceBelow = viewportHeight - rect.bottom - gap - margin;
    const spaceAbove = rect.top - gap - margin;
    const wantsTop = props.side === "top";
    // Flip only when the preferred side cannot hold the content and the other can do better.
    const placeAbove = wantsTop ? spaceAbove >= height || spaceAbove > spaceBelow : height > spaceBelow && spaceAbove > spaceBelow;

    const maxHeight = Math.max(120, placeAbove ? spaceAbove : spaceBelow);
    const top = placeAbove ? Math.max(margin, rect.top - gap - Math.min(height, maxHeight)) : rect.bottom + gap;

    const align = props.align ?? "start";
    let left = align === "end" ? rect.right - width : align === "center" ? rect.left + rect.width / 2 - width / 2 : rect.left;
    left = Math.min(left, viewportWidth - width - margin);
    left = Math.max(margin, left);

    setPosition({ left, top, maxHeight, ready: true });
  }

  createEffect(() => {
    if (!props.open) {
      setPosition((current) => ({ ...current, ready: false }));
      return;
    }
    const node = element();
    if (!node) return;

    const token = pushOverlay();
    place();
    // Content can change size after the first paint (async data, font swap).
    const observer = new ResizeObserver(place);
    observer.observe(node);

    const reposition = () => place();
    window.addEventListener("resize", reposition);
    // Capture phase so scrolling in any ancestor container repositions too.
    window.addEventListener("scroll", reposition, true);

    const onPointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (node.contains(target)) return;
      if (props.anchor?.contains(target)) return;
      props.onClose();
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || !isTopOverlay(token)) return;
      event.preventDefault();
      event.stopPropagation();
      props.onClose();
      (props.returnFocus ?? props.anchor)?.focus();
    };
    document.addEventListener("pointerdown", onPointerDown, true);
    document.addEventListener("keydown", onKeyDown, true);

    onCleanup(() => {
      popOverlay(token);
      observer.disconnect();
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
      document.removeEventListener("pointerdown", onPointerDown, true);
      document.removeEventListener("keydown", onKeyDown, true);
    });
  });

  return (
    <Show when={props.open}>
      <Portal>
        <div
          ref={setElement}
          class={`popover${props.class ? ` ${props.class}` : ""}`}
          role={props.role}
          aria-label={props.label}
          style={{
            left: `${position().left}px`,
            top: `${position().top}px`,
            "max-height": `${position().maxHeight}px`,
            // Hidden for the first frame so the pre-measurement position never paints.
            visibility: position().ready ? "visible" : "hidden",
          }}
        >
          {props.children}
        </div>
      </Portal>
    </Show>
  );
}

/**
 * Roving keyboard navigation for a list of items inside a popover.
 * Returns a keydown handler to spread onto the popover container.
 */
export function listNavigation(options: {
  itemSelector?: string;
  onEscape?: () => void;
}): (event: KeyboardEvent) => void {
  const selector = options.itemSelector ?? '[role="menuitem"], [role="menuitemradio"], [role="option"]';
  return (event: KeyboardEvent) => {
    const container = event.currentTarget;
    if (!(container instanceof HTMLElement)) return;
    const items = [...container.querySelectorAll<HTMLElement>(selector)].filter((item) => !item.hasAttribute("disabled"));
    if (items.length === 0) return;
    const index = items.indexOf(document.activeElement as HTMLElement);

    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      const next = index < 0 ? (step === 1 ? 0 : items.length - 1) : (index + step + items.length) % items.length;
      items[next]!.focus();
      return;
    }
    if (event.key === "Home") {
      event.preventDefault();
      items[0]!.focus();
      return;
    }
    if (event.key === "End") {
      event.preventDefault();
      items[items.length - 1]!.focus();
      return;
    }
    if (event.key === "Escape") options.onEscape?.();
  };
}
