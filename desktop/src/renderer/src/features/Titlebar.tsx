import { For, Show, createSignal, type JSX } from "solid-js";
import {
  IconCheck,
  IconChevronDown,
  IconCloudCheck,
  IconCloudOff,
  IconLock,
  IconPlus,
  IconSearch,
  IconUsers,
} from "@tabler/icons-solidjs";
import { plural } from "../lib/format";
import { vaultTone } from "../lib/items";
import { useVault } from "../lib/store";
import { Button, IconButton, Kbd } from "../ui/Button";
import { Popover, listNavigation } from "../ui/Popover";

/**
 * The title bar carries the three things that are true of the whole window:
 * which vault you are looking at, how to find anything, and how to lock up.
 */
export function Titlebar(props: {
  onOpenPalette(): void;
  onCreateItem(): void;
  onCreateVault(): void;
  onShareVault(scopeId: string): void;
}): JSX.Element {
  const vault = useVault();

  return (
    <header class="titlebar">
      <div class="titlebar-lead">
        <div class="logo" aria-label="fd0">
          <strong>fd0</strong>
        </div>
        <VaultSwitcher onCreateVault={props.onCreateVault} onShareVault={props.onShareVault} />
      </div>

      {/* The search field is a button: it opens the palette rather than
          filtering in place, because the palette also runs commands. */}
      <button class="palette-trigger" type="button" onClick={props.onOpenPalette}>
        <IconSearch size={16} aria-hidden="true" />
        <span>Search items or type a command</span>
        <Kbd keys="mod+k" />
      </button>

      <div class="titlebar-trail">
        <SyncButton />
        <IconButton label="Lock fd0" onClick={() => void vault.lock()}>
          <IconLock size={17} />
        </IconButton>
        <Button variant="primary" onClick={props.onCreateItem}>
          <IconPlus size={16} />
          Add
        </Button>
      </div>
    </header>
  );
}

function SyncButton(): JSX.Element {
  const vault = useVault();
  const development = () => window.fd0.development;
  const synced = () => Boolean(vault.status()?.readiness?.firstSyncAt);

  const label = () => {
    if (vault.syncing()) return "Syncing…";
    if (development()) return "Local vault";
    return synced() ? "Synced" : "Not synced";
  };

  return (
    <button
      class="sync-button"
      classList={{ "is-warning": !development() && !synced() }}
      type="button"
      disabled={vault.syncing()}
      title={development() ? "Refresh this development vault" : "Sync your vault now"}
      onClick={() => void vault.sync()}
    >
      <Show when={development() || synced()} fallback={<IconCloudOff size={15} />}>
        <IconCloudCheck size={15} />
      </Show>
      <span class="sync-label">{label()}</span>
    </button>
  );
}

/**
 * Vault as a context switcher rather than a filter buried in a sidebar list.
 * "All vaults" is a first-class choice, so the user always has a way back out.
 */
function VaultSwitcher(props: { onCreateVault(): void; onShareVault(scopeId: string): void }): JSX.Element {
  const vault = useVault();
  const [open, setOpen] = createSignal(false);
  const [trigger, setTrigger] = createSignal<HTMLButtonElement>();

  const current = () => vault.inventory().scopes.find((scope) => scope.id === vault.filters().vault);
  const label = () => current()?.label ?? "All vaults";

  function choose(id: string): void {
    setOpen(false);
    vault.updateFilters({ vault: id });
  }

  return (
    <>
      <button
        ref={setTrigger}
        class="vault-switcher"
        type="button"
        aria-haspopup="menu"
        aria-expanded={open()}
        aria-label={`Vault: ${label()}. Change vault`}
        onClick={() => setOpen((value) => !value)}
      >
        <span classList={{ "vault-dot": true, [current() ? vaultTone(current()!.id) : "vault-tone-all"]: true }} aria-hidden="true" />
        <span class="vault-switcher-label">{label()}</span>
        <IconChevronDown size={14} aria-hidden="true" />
      </button>

      <Popover anchor={trigger()} open={open()} onClose={() => setOpen(false)} align="start" role="menu" label="Vaults" class="menu vault-menu">
        <div onKeyDown={listNavigation({ onEscape: () => setOpen(false) })}>
          <button type="button" role="menuitem" class="menu-item" onClick={() => choose("")}>
            <span class="menu-item-label">All vaults</span>
            <span class="menu-item-hint">{plural(vault.inventory().items.length, "item")}</span>
            <Show when={!vault.filters().vault}>
              <IconCheck size={15} />
            </Show>
          </button>

          <div class="menu-separator" role="separator" />

          <For each={vault.inventory().scopes}>
            {(scope) => (
              <div class="menu-row">
                <button type="button" role="menuitem" class="menu-item" onClick={() => choose(scope.id)}>
                  <span classList={{ "vault-dot": true, [vaultTone(scope.id)]: true }} aria-hidden="true" />
                  <span class="menu-item-label">{scope.label}</span>
                  <span class="menu-item-hint">{vault.vaultCounts().get(scope.id) ?? 0}</span>
                  <Show when={vault.filters().vault === scope.id}>
                    <IconCheck size={15} />
                  </Show>
                </button>
                <IconButton
                  label={`Manage access to ${scope.label}`}
                  size="sm"
                  onClick={() => {
                    setOpen(false);
                    props.onShareVault(scope.id);
                  }}
                >
                  <IconUsers size={15} />
                </IconButton>
              </div>
            )}
          </For>

          <div class="menu-separator" role="separator" />

          <button
            type="button"
            role="menuitem"
            class="menu-item"
            onClick={() => {
              setOpen(false);
              props.onCreateVault();
            }}
          >
            <IconPlus size={15} />
            <span class="menu-item-label">New vault…</span>
          </button>
        </div>
      </Popover>
    </>
  );
}
