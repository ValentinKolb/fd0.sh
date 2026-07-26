import { For, Show, createSignal, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
import type { Component } from "solid-js";
import type { IconProps } from "@tabler/icons-solidjs";
import { IconDice5, IconHelp, IconHistory, IconLayoutGrid, IconSettings, IconStar } from "@tabler/icons-solidjs";
import { kindMeta, railKinds } from "../lib/items";
import { plural } from "../lib/format";
import { useVault, type MainView, type SmartView, type TypeFilter } from "../lib/store";

type RailEntry = {
  id: string;
  label: string;
  icon: Component<IconProps>;
  count?: number;
  hint?: string;
  active: boolean;
  onSelect(): void;
};

/**
 * The rail replaces the old type dropdown.
 *
 * Every item type is reachable in one click and always visible, so the product's
 * scope is legible at a glance. Counts live in the tooltip rather than on the
 * icon, which keeps the rail quiet while still answering "how many".
 */
export function Rail(): JSX.Element {
  const vault = useVault();

  const isItems = () => vault.mainView() === "items";
  const filters = () => vault.filters();

  function selectView(view: SmartView): void {
    vault.updateFilters({ view, type: "all" });
  }

  function selectType(type: TypeFilter): void {
    vault.updateFilters({ view: "all", type });
    vault.setRawSecrets(false);
  }

  function openPanel(view: MainView): void {
    vault.setMainView(view);
  }

  const smartEntries = (): RailEntry[] => [
    {
      id: "all",
      label: "All items",
      icon: IconLayoutGrid,
      count: vault.inventory().items.length,
      active: isItems() && filters().view === "all" && filters().type === "all",
      onSelect: () => selectView("all"),
    },
    {
      id: "favorites",
      label: "Favorites",
      icon: IconStar,
      count: vault.inventory().items.filter((item) => item.favorite).length,
      active: isItems() && filters().view === "favorites",
      onSelect: () => selectView("favorites"),
    },
  ];

  const typeEntries = (): RailEntry[] =>
    railKinds.map((kind) => {
      const meta = kindMeta[kind];
      return {
        id: kind,
        label: meta.label,
        icon: meta.icon,
        count: vault.inventory().counts[kind] ?? 0,
        hint: meta.blurb,
        active: isItems() && filters().view === "all" && filters().type === kind,
        onSelect: () => selectType(kind),
      };
    });

  const toolEntries = (): RailEntry[] => [
    {
      id: "generator",
      label: "Password generator",
      icon: IconDice5,
      active: vault.mainView() === "generator",
      onSelect: () => openPanel("generator"),
    },
    {
      id: "support",
      label: "Support",
      icon: IconHelp,
      hint: vault.needsRecovery() ? "Needs attention" : undefined,
      active: vault.mainView() === "support",
      onSelect: () => openPanel("support"),
    },
    {
      id: "settings",
      label: "Settings",
      icon: IconSettings,
      active: vault.mainView() === "settings",
      onSelect: () => openPanel("settings"),
    },
  ];

  return (
    <nav class="rail" aria-label="Sections">
      <div class="rail-group">
        <For each={smartEntries()}>{(entry) => <RailButton entry={entry} />}</For>
      </div>
      <div class="rail-separator" role="presentation" />
      <div class="rail-group">
        <For each={typeEntries()}>{(entry) => <RailButton entry={entry} />}</For>
      </div>
      <div class="rail-spacer" />
      <div class="rail-group">
        <For each={toolEntries()}>
          {(entry) => <RailButton entry={entry} alert={entry.id === "support" && vault.needsRecovery()} />}
        </For>
      </div>
    </nav>
  );
}

function RailButton(props: { entry: RailEntry; alert?: boolean }): JSX.Element {
  const [hovered, setHovered] = createSignal(false);
  const [focused, setFocused] = createSignal(false);
  const showTip = () => hovered() || focused();

  return (
    <div class="rail-slot">
      <button
        type="button"
        classList={{ "rail-button": true, "is-active": props.entry.active }}
        aria-label={props.entry.label}
        aria-current={props.entry.active ? "page" : undefined}
        onClick={props.entry.onSelect}
        onPointerEnter={() => setHovered(true)}
        onPointerLeave={() => setHovered(false)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
      >
        <Dynamic component={props.entry.icon} size={19} strokeWidth={1.6} />
        <Show when={props.alert}>
          <span class="rail-alert" aria-hidden="true" />
        </Show>
      </button>
      <Show when={showTip()}>
        <div class="rail-tooltip" role="tooltip">
          <strong>{props.entry.label}</strong>
          <Show when={props.entry.count !== undefined}>
            <span>{plural(props.entry.count!, "item")}</span>
          </Show>
          <Show when={props.entry.hint}>
            <small>{props.entry.hint}</small>
          </Show>
        </div>
      </Show>
    </div>
  );
}
