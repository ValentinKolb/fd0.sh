import { For, Show, createResource, createSignal, type JSX } from "solid-js";
import { IconChevronDown, IconHistory, IconRotate2, IconTrash } from "@tabler/icons-solidjs";
import type { ItemDetail, ItemHistoryEntry, ItemSummary } from "../../../shared/contracts";
import { absoluteDate, plural, relativeDate } from "../lib/format";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";

const PAGE_SIZE = 25;

/**
 * Past versions of an item, read from the scope's signed event chain.
 *
 * The chain is append-only and never compacted, so every version an item ever
 * had is still there and still verifiable. Restoring writes the old payload
 * back as a NEW version rather than rewinding anything, which is why the
 * current value stays in the list afterwards.
 */
export function ItemHistory(props: { item: ItemSummary }): JSX.Element {
  const vault = useVault();
  const [limit, setLimit] = createSignal(PAGE_SIZE);
  const [open, setOpen] = createSignal(false);
  const [preview, setPreview] = createSignal<{ entry: ItemHistoryEntry; detail: ItemDetail } | null>(null);

  const [page, { refetch }] = createResource(
    () => (open() ? { id: props.item.id, scopeId: props.item.scopeId, name: props.item.recordName, limit: limit() } : undefined),
    async (key) => {
      try {
        return await window.fd0.itemHistory({ scopeId: key.scopeId, name: key.name }, { limit: key.limit });
      } catch (cause) {
        vault.fail(cause, `fd0 could not read the history of ${props.item.title}`);
        // null, not an empty page: "no history" and "could not read history"
        // are different facts and must not share a message.
        return null;
      }
    },
  );

  async function openVersion(entry: ItemHistoryEntry): Promise<void> {
    try {
      const detail = await window.fd0.itemVersion({
        scopeId: props.item.scopeId,
        name: props.item.recordName,
        seq: entry.seq,
      });
      setPreview({ entry, detail });
    } catch (cause) {
      vault.fail(cause, "fd0 could not open that version");
    }
  }

  async function restore(entry: ItemHistoryEntry): Promise<void> {
    try {
      const result = await window.fd0.restoreItemVersion({
        scopeId: props.item.scopeId,
        name: props.item.recordName,
        seq: entry.seq,
      });
      if (!result.ok) {
        vault.notify("Nothing was restored");
        return;
      }
      setPreview(null);
      vault.notify(`${props.item.title} restored to an earlier version`);
      await vault.refresh();
      await vault.loadDetail(vault.selectedItem());
      void refetch();
    } catch (cause) {
      vault.fail(cause, `fd0 could not restore ${props.item.title}`);
    }
  }

  const shown = () => page()?.entries ?? [];
  const total = () => page()?.total ?? 0;

  return (
    <section class="history-section">
      <button
        class="history-toggle"
        type="button"
        aria-expanded={open()}
        onClick={() => setOpen((value) => !value)}
      >
        <IconHistory size={15} aria-hidden="true" />
        <span>History</span>
        <Show when={open() && total() > 0}>
          <span class="history-count">{plural(total(), "version")}</span>
        </Show>
        <IconChevronDown size={14} classList={{ "is-rotated": open() }} aria-hidden="true" />
      </button>

      <Show when={open()}>
        <Show
          when={!page.loading}
          fallback={<p class="inline-note">Reading this item's history…</p>}
        >
          <Show
            when={page() !== null}
            fallback={<p class="inline-note">fd0 could not read this item's history. The item itself is unaffected.</p>}
          >
          <Show
            when={shown().length > 0}
            fallback={<p class="inline-note">This item has only ever had its current value.</p>}
          >
            <ol class="history-list">
              <For each={shown()}>
                {(entry, index) => (
                  <li classList={{ "history-row": true, "is-current": index() === 0 }}>
                    <span class="history-marker" aria-hidden="true" />
                    <div class="history-copy">
                      <span class="history-title">
                        <Show when={entry.revision} fallback={`Version ${entry.seq}`}>
                          {(revision) => <>Revision {revision()}</>}
                        </Show>
                        <Show when={index() === 0}>
                          <span class="history-badge">current</span>
                        </Show>
                        <Show when={entry.tombstone}>
                          <span class="history-badge is-danger">
                            <IconTrash size={11} aria-hidden="true" />
                            deleted
                          </span>
                        </Show>
                      </span>
                      <span class="history-meta">
                        <Show when={entry.updatedAt} fallback={<>Position {entry.seq} in this vault's history</>}>
                          {(updated) => <span title={absoluteDate(updated())}>{relativeDate(updated())}</span>}
                        </Show>
                        {" · "}
                        {entry.author}
                        <Show when={entry.summary}>
                          {" · "}
                          {entry.summary}
                        </Show>
                      </span>
                    </div>
                    <Show when={!entry.tombstone && index() !== 0}>
                      <div class="history-actions">
                        <Button size="sm" onClick={() => void openVersion(entry)}>
                          View
                        </Button>
                        <Button size="sm" onClick={() => void restore(entry)}>
                          <IconRotate2 size={14} />
                          Restore
                        </Button>
                      </div>
                    </Show>
                  </li>
                )}
              </For>
            </ol>

            <Show when={page()?.truncated}>
              <p class="inline-note">
                This page stopped early to stay within one response. Load more to continue.
              </p>
            </Show>

            <Show when={total() > shown().length}>
              <Button size="sm" onClick={() => setLimit((value) => value + PAGE_SIZE)}>
                Show older versions ({total() - shown().length} more)
              </Button>
            </Show>
          </Show>
          </Show>
        </Show>
      </Show>

      <Show when={preview()}>
        {(current) => (
          <Modal
            title={
              current().entry.revision
                ? `${props.item.title} · revision ${current().entry.revision}`
                : `${props.item.title} · version ${current().entry.seq}`
            }
            description={
              current().entry.updatedAt
                ? `Saved ${relativeDate(current().entry.updatedAt!)} by ${current().entry.author}.`
                : `Saved by ${current().entry.author}.`
            }
            onClose={() => setPreview(null)}
            footer={
              <>
                <Button onClick={() => setPreview(null)}>Close</Button>
                <Button variant="primary" onClick={() => void restore(current().entry)}>
                  <IconRotate2 size={15} />
                  Restore this version
                </Button>
              </>
            }
          >
            <p class="inline-note">
              Secrets stay hidden here, exactly as they do on the item itself. Restore this version to use it.
            </p>
            <dl class="history-fields">
              <For each={current().detail.fields}>
                {(field) => (
                  <div class="history-field">
                    <dt>{field.name}</dt>
                    <dd classList={{ "is-secret": Boolean(field.sensitive) }}>
                      {field.sensitive ? "••••••••••••" : field.value || "Not set"}
                    </dd>
                  </div>
                )}
              </For>
            </dl>
          </Modal>
        )}
      </Show>
    </section>
  );
}
