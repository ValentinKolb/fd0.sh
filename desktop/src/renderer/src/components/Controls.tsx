import { splitProps, type JSX } from "solid-js";
import { IconChevronDown } from "@tabler/icons-solidjs";

export function IconButton(props: {
  label: string;
  class?: string;
  disabled?: boolean;
  onClick?: () => void;
  children: JSX.Element;
}): JSX.Element {
  return (
    <button
      class={`icon-button${props.class ? ` ${props.class}` : ""}`}
      type="button"
      aria-label={props.label}
      title={props.label}
      disabled={props.disabled}
      onClick={props.onClick}
    >
      {props.children}
    </button>
  );
}

type SelectControlProps = JSX.SelectHTMLAttributes<HTMLSelectElement> & {
  containerClass?: string;
};

export function SelectControl(props: SelectControlProps): JSX.Element {
  const [local, selectProps] = splitProps(props, ["children", "containerClass"]);
  return (
    <span class={`select-control${local.containerClass ? ` ${local.containerClass}` : ""}`}>
      <select {...selectProps}>{local.children}</select>
      <IconChevronDown size={15} aria-hidden="true" />
    </span>
  );
}
