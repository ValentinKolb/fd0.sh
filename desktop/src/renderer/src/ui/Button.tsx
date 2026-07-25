import { splitProps, type JSX } from "solid-js";

type Variant = "primary" | "default" | "quiet" | "danger";
type Size = "sm" | "md" | "lg";

type ButtonProps = JSX.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: Size;
  /** Renders the button at full container width. */
  block?: boolean;
};

/**
 * The single button in the app. Every previous variant (primary-button,
 * secondary-button, text-button, sidebar-item button, menu button, …) resolves
 * to this component so focus and disabled states are correct in one place.
 */
export function Button(props: ButtonProps): JSX.Element {
  const [local, rest] = splitProps(props, ["variant", "size", "block", "class", "children"]);
  return (
    <button
      type="button"
      {...rest}
      classList={{
        button: true,
        [`button-${local.variant ?? "default"}`]: true,
        [`button-${local.size ?? "md"}`]: true,
        "button-block": local.block,
        [local.class ?? ""]: Boolean(local.class),
      }}
    >
      {local.children}
    </button>
  );
}

type IconButtonProps = Omit<JSX.ButtonHTMLAttributes<HTMLButtonElement>, "aria-label"> & {
  label: string;
  size?: Size;
  /** Marks the control as the row's primary action, giving it a resting outline. */
  emphasis?: boolean;
  active?: boolean;
};

/** An icon-only control. Always carries both an accessible name and a tooltip. */
export function IconButton(props: IconButtonProps): JSX.Element {
  const [local, rest] = splitProps(props, ["label", "size", "emphasis", "active", "class", "children"]);
  return (
    <button
      type="button"
      aria-label={local.label}
      title={local.label}
      {...rest}
      classList={{
        "icon-button": true,
        [`icon-button-${local.size ?? "md"}`]: true,
        "icon-button-emphasis": local.emphasis,
        "is-active": local.active,
        [local.class ?? ""]: Boolean(local.class),
      }}
    >
      {local.children}
    </button>
  );
}

/** A keyboard shortcut chip. Renders platform-correct modifier glyphs. */
export function Kbd(props: { keys: string }): JSX.Element {
  const isMac = () => window.fd0?.platform === "darwin";
  const rendered = () =>
    props.keys
      .split("+")
      .map((key) => {
        const token = key.trim().toLowerCase();
        if (token === "mod") return isMac() ? "⌘" : "Ctrl";
        if (token === "shift") return isMac() ? "⇧" : "Shift";
        if (token === "alt") return isMac() ? "⌥" : "Alt";
        if (token === "enter") return "↵";
        if (token === "esc") return "Esc";
        return key.trim().toUpperCase();
      })
      .join(isMac() ? "" : "+");
  return <kbd class="kbd">{rendered()}</kbd>;
}
