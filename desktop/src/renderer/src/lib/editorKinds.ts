import type { Component } from "solid-js";
import type { IconProps } from "@tabler/icons-solidjs";
import { IconBraces, IconHexagonLetterK, IconKey, IconServer, IconTerminal2 } from "@tabler/icons-solidjs";

/**
 * What the editor can create or change.
 *
 * This is wider than `ItemKind` from the contracts: an SSH key and an SSH host
 * are one kind once stored, but they are created in completely different ways.
 */
export type EditorKind = "password" | "secret" | "ssh" | "ssh-key" | "kubernetes" | "talos";

export type EditorKindMeta = {
  id: EditorKind;
  label: string;
  description: string;
  icon: Component<IconProps>;
  tone: string;
};

export const itemKinds: EditorKindMeta[] = [
  { id: "password", label: "Password", description: "A login for a website or app", icon: IconKey, tone: "tone-password" },
  { id: "secret", label: "Secret", description: "An API token or any other protected value", icon: IconBraces, tone: "tone-secret" },
  { id: "ssh", label: "Server", description: "An SSH connection and its login details", icon: IconTerminal2, tone: "tone-ssh" },
  { id: "ssh-key", label: "SSH key", description: "Generate a new key pair for servers", icon: IconKey, tone: "tone-ssh" },
  { id: "kubernetes", label: "Kubernetes", description: "Import clusters from a kubeconfig file", icon: IconHexagonLetterK, tone: "tone-kubernetes" },
  { id: "talos", label: "Talos", description: "Import machines from a talosconfig file", icon: IconServer, tone: "tone-talos" },
];
