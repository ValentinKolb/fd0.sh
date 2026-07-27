import { For, Show, createSignal, onMount, type JSX } from "solid-js";
import { Dynamic } from "solid-js/web";
import { IconRefresh, IconTrash } from "@tabler/icons-solidjs";
import type { DeletedItem } from "../../../shared/contracts";
import { initials } from "../lib/format";
import { kindIcon, kindTone } from "../lib/items";
import { useVault } from "../lib/store";
import { Button, IconButton } from "../ui/Button";

export function RecentlyDeleted(): JSX.Element {
  const vault = useVault();
  const [items, setItems] = createSignal<DeletedItem[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [restoring, setRestoring] = createSignal("");

  async function load(): Promise<void> {
    setLoading(true);
    try {
      setItems((await window.fd0.deletedItems()).items);
    } catch (cause) {
      vault.fail(cause, "fd0 could not load recently deleted items");
    } finally {
      setLoading(false);
    }
  }

  async function restore(entry: DeletedItem): Promise<void> {
    setRestoring(entry.item.id);
    try {
      const result = await window.fd0.restoreDeletedItem({
        scopeId: entry.item.scopeId,
        name: entry.item.recordName,
        seq: entry.restoreSeq,
      });
      if (!result.ok) return;
      await vault.refresh({ scopeId: entry.item.scopeId, name: entry.item.recordName });
      await load();
      vault.notify(`${entry.item.title} restored`);
    } catch (cause) {
      vault.fail(cause, `fd0 could not restore ${entry.item.title}`);
    } finally {
      setRestoring("");
    }
  }

  onMount(() => void load());

  return (
    <section class="panel deleted-view" aria-labelledby="deleted-title">
      <header class="panel-header deleted-header">
        <div>
          <h1 id="deleted-title">Recently deleted</h1>
          <p>Restore an item without rewriting its signed history.</p>
        </div>
        <IconButton label="Refresh deleted items" disabled={loading()} onClick={() => void load()}>
          <IconRefresh size={17} />
        </IconButton>
      </header>

      <Show when={!loading()} fallback={<div class="empty-state"><span>Loading deleted items…</span></div>}>
        <Show
          when={items().length > 0}
          fallback={
            <div class="empty-state">
              <span class="empty-glyph"><IconTrash size={20} /></span>
              <strong>Nothing has been deleted</strong>
              <span>Removed items you can restore will appear here.</span>
            </div>
          }
        >
          <div class="panel-column deleted-list">
            <For each={items()}>
              {(entry) => (
                <div class="deleted-row">
                  <span classList={{ "item-avatar": true, [kindTone(entry.item.kind)]: true }} aria-hidden="true">
                    <Show
                      when={entry.item.kind === "password"}
                      fallback={<Dynamic component={kindIcon(entry.item.kind)} size={16} />}
                    >
                      {initials(entry.item.title)}
                    </Show>
                  </span>
                  <span class="deleted-copy">
                    <strong>{entry.item.title}</strong>
                    <small>{entry.item.vault} · {entry.item.badge}</small>
                  </span>
                  <Button
                    size="sm"
                    disabled={restoring() === entry.item.id}
                    onClick={() => void restore(entry)}
                  >
                    {restoring() === entry.item.id ? "Restoring…" : "Restore…"}
                  </Button>
                </div>
              )}
            </For>
          </div>
        </Show>
      </Show>
    </section>
  );
}
