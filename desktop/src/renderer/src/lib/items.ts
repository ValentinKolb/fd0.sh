import type { Component } from "solid-js";
import type { IconProps } from "@tabler/icons-solidjs";
import {
  IconBraces,
  IconHexagonLetterK,
  IconKey,
  IconLayoutGrid,
  IconServer,
  IconTerminal2,
} from "@tabler/icons-solidjs";
import type { ItemKind } from "../../../shared/contracts";
import type { TypeFilter } from "./store";

export type KindMeta = {
  id: TypeFilter;
  /** Plural, used for navigation and headings. */
  label: string;
  /** Singular, used in sentences and empty states. */
  singular: string;
  icon: Component<IconProps>;
  /** What this type is for, in the user's terms. */
  blurb: string;
};

export const kindMeta: Record<TypeFilter, KindMeta> = {
  all: { id: "all", label: "All items", singular: "item", icon: IconLayoutGrid, blurb: "Everything in your vaults" },
  password: { id: "password", label: "Passwords", singular: "password", icon: IconKey, blurb: "Logins, websites, and app accounts" },
  secret: { id: "secret", label: "Secrets", singular: "secret", icon: IconBraces, blurb: "API tokens and other protected values" },
  ssh: { id: "ssh", label: "SSH", singular: "SSH entry", icon: IconTerminal2, blurb: "Servers and keys you connect to" },
  kubernetes: { id: "kubernetes", label: "Kubernetes", singular: "cluster", icon: IconHexagonLetterK, blurb: "Cluster access from your kubeconfig" },
  talos: { id: "talos", label: "Talos", singular: "cluster", icon: IconServer, blurb: "Talos machine configuration" },
};

/** Types shown in the rail, in order. "all" is handled separately. */
export const railKinds: TypeFilter[] = ["password", "secret", "ssh", "kubernetes", "talos"];

export function kindIcon(kind: ItemKind): Component<IconProps> {
  return kindMeta[kind].icon;
}

/**
 * Whether fd0 can edit this item in the desktop app.
 *
 * Kubernetes and Talos contexts are imported wholesale from a config file and
 * SSH keys are generated, so there is no meaningful field-level editor for
 * them yet. The menu states this instead of silently omitting the entry.
 */
export function editability(kind: ItemKind, badge: string, raw: boolean): { canEdit: boolean; reason?: string } {
  if (raw) return { canEdit: false, reason: "Not editable while showing raw records" };
  if (kind === "password" || kind === "secret") return { canEdit: true };
  if (kind === "ssh") {
    return badge === "SSH HOST"
      ? { canEdit: true }
      : { canEdit: false, reason: "SSH keys cannot be edited after generation" };
  }
  if (kind === "kubernetes") return { canEdit: false, reason: "Re-import the kubeconfig to change this" };
  return { canEdit: false, reason: "Re-import the talosconfig to change this" };
}

/** Stable accent class per kind, used for avatars and glyph tints. */
export function kindTone(kind: ItemKind): string {
  return `tone-${kind}`;
}

/**
 * A stable colour for a vault, derived from its id.
 *
 * The previous implementation assigned colours by `index % 3`, so a vault's
 * swatch changed whenever another vault was added or removed, and implied a
 * status that did not exist. This is purely a recognition aid: the same vault
 * always gets the same swatch, and the swatch means nothing else.
 */
export function vaultTone(scopeId: string): string {
  let hash = 0;
  for (let index = 0; index < scopeId.length; index += 1) {
    hash = (hash * 31 + scopeId.charCodeAt(index)) >>> 0;
  }
  return `vault-tone-${hash % 6}`;
}
