import {
  For,
  Show,
  createMemo,
  createSignal,
  onCleanup,
  onMount,
  type JSX,
} from "solid-js";
import {
  IconArrowLeft,
  IconDownload,
  IconDots,
  IconFile,
  IconFolder,
  IconFolderPlus,
  IconPencil,
  IconRefresh,
  IconTrash,
  IconUpload,
  IconX,
} from "@tabler/icons-solidjs";
import { truncate } from "@k2b/stdlib";
import type { SFTPEntry, SFTPTransferEvent, TerminalTheme } from "../../../shared/contracts";
import { MenuButton } from "../ui/Menu";
import { applyTerminalTheme } from "../lib/terminal";
import { observeSystemTheme, systemThemeIsDark } from "../lib/theme";
import {
  decodeSFTPPreview,
  remoteBreadcrumbs,
  remoteJoin,
  remoteParent,
  sftpErrorNeedsReconnect,
  type SFTPPreviewContent,
} from "../lib/sftp";

type DialogState =
  | { kind: "mkdir"; value: string }
  | { kind: "rename"; value: string; entry: SFTPEntry }
  | { kind: "remove"; value: string; entry: SFTPEntry };

type FileError = {
  message: string;
  reconnect: boolean;
};

type PreviewState = {
  entry: SFTPEntry;
  loading: boolean;
  content?: SFTPPreviewContent;
  size?: number;
  truncated?: boolean;
};

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = -1;
  do {
    amount /= 1024;
    unit += 1;
  } while (amount >= 1024 && unit < units.length - 1);
  return `${amount < 10 ? amount.toFixed(1) : amount.toFixed(0)} ${units[unit]}`;
}

function dialogEntryName(value: DialogState): string {
  return value.kind === "mkdir" ? "this folder" : value.entry.name;
}

export function FilesWindow(): JSX.Element {
  const [host, setHost] = createSignal("SSH host");
  const [theme, setTheme] = createSignal<TerminalTheme>("system");
  const [path, setPath] = createSignal("/");
  const [entries, setEntries] = createSignal<SFTPEntry[]>([]);
  const [loading, setLoading] = createSignal(true);
  const [error, setError] = createSignal<FileError>();
  const [dragging, setDragging] = createSignal(false);
  const [dialog, setDialog] = createSignal<DialogState>();
  const [preview, setPreview] = createSignal<PreviewState>();
  const [transfers, setTransfers] = createSignal<Record<string, SFTPTransferEvent>>({});

  const sortedEntries = createMemo(() =>
    [...entries()].sort((left, right) => {
      if (left.type === "directory" && right.type !== "directory") return -1;
      if (left.type !== "directory" && right.type === "directory") return 1;
      return left.name.localeCompare(right.name, undefined, { numeric: true, sensitivity: "base" });
    }),
  );
  const breadcrumbs = createMemo(() => remoteBreadcrumbs(path()));
  const visibleTransfers = createMemo(() => Object.values(transfers()));

  function showError(cause: unknown, fallback: string): void {
    setError({
      message: cause instanceof Error ? cause.message : fallback,
      reconnect: sftpErrorNeedsReconnect(cause),
    });
  }

  async function load(nextPath = path()): Promise<void> {
    setLoading(true);
    setError();
    try {
      const next = await window.fd0.sftpList(nextPath);
      setEntries(next);
      setPath(nextPath);
    } catch (cause) {
      showError(cause, "fd0 could not load this directory.");
    } finally {
      setLoading(false);
    }
  }

  async function reconnect(): Promise<void> {
    setLoading(true);
    setError();
    try {
      const session = await window.fd0.sftpReconnect();
      setHost(session.host);
      await load(session.workingDirectory);
    } catch (cause) {
      showError(cause, "fd0 could not reconnect the file session.");
      setLoading(false);
    }
  }

  onMount(() => {
    const applyTheme = (): void => {
      applyTerminalTheme(theme(), systemThemeIsDark());
    };
    const stopTransfer = window.fd0.onSFTPTransfer((event) => {
      setTransfers((current) => ({ ...current, [event.id]: event }));
      if (event.state === "completed") void load();
      if (event.state === "failed" && sftpErrorNeedsReconnect(event.error)) {
        showError(event.error, "The file session was interrupted.");
      }
    });
    const stopTerminalTheme = window.fd0.onTerminalTheme((next) => {
      setTheme(next);
      applyTheme();
    });
    const stopSystemTheme = observeSystemTheme(() => {
      if (theme() === "system") applyTheme();
    });
    onCleanup(() => {
      stopTransfer();
      stopTerminalTheme();
      stopSystemTheme();
    });
    void window.fd0.sftpSession()
      .then((session) => {
        setHost(session.host);
        setTheme(session.terminalTheme);
        applyTheme();
        document.title = `${session.host} — Files — fd0`;
        return load(session.workingDirectory);
      })
      .catch((cause) => {
        showError(cause, "fd0 could not start the file session.");
        setLoading(false);
      });
  });

  async function submitDialog(): Promise<void> {
    const current = dialog();
    if (!current) return;
    const value = current.value.trim();
    if (!value || value.includes("/") || value === "." || value === "..") {
      setError({ message: "Use a single file or folder name.", reconnect: false });
      return;
    }
    try {
      if (current.kind === "mkdir") {
        await window.fd0.sftpMkdir(remoteJoin(path(), value));
      } else if (current.kind === "rename") {
        await window.fd0.sftpRename(current.entry.path, remoteJoin(path(), value));
      } else {
        await window.fd0.sftpRemove(current.entry.path, current.entry.type === "directory");
      }
      setDialog();
      await load();
    } catch (cause) {
      showError(cause, "fd0 could not complete that file action.");
    }
  }

  function openPreview(entry: SFTPEntry): void {
    setError();
    setPreview({ entry, loading: true });
    void window.fd0.sftpPreview(entry.path)
      .then((value) => setPreview({
        entry,
        loading: false,
        content: decodeSFTPPreview(value),
        size: value.size,
        truncated: value.truncated,
      }))
      .catch((cause) => {
        setPreview();
        const message = cause instanceof Error ? cause.message : "fd0 could not preview this file.";
        setError({
          message: `${truncate(entry.name, 48, "middle")}: ${message}`,
          reconnect: sftpErrorNeedsReconnect(cause),
        });
      });
  }

  function openEntry(entry: SFTPEntry): void {
    if (entry.type === "directory") {
      setPreview();
      void load(entry.path);
      return;
    }
    if (entry.type === "file") openPreview(entry);
  }

  function refresh(): void {
    const current = preview();
    if (current) {
      openPreview(current.entry);
    } else {
      void load();
    }
  }

  function upload(): void {
    void window.fd0.sftpUpload(path()).catch((cause) =>
      showError(cause, "fd0 could not start the upload"),
    );
  }

  function download(entry: SFTPEntry): void {
    void window.fd0.sftpDownload(entry).catch((cause) =>
      showError(cause, "fd0 could not start the download"),
    );
  }

  return (
    <main
      classList={{
        "files-window": true,
        "is-mac": window.fd0.platform === "darwin",
        "is-dragging": dragging(),
      }}
      onDragEnter={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragOver={(event) => event.preventDefault()}
      onDragLeave={(event) => {
        if (event.currentTarget === event.target) setDragging(false);
      }}
      onDrop={(event) => {
        event.preventDefault();
        setDragging(false);
        const files = [...(event.dataTransfer?.files ?? [])];
        if (files.length === 0) return;
        void window.fd0.sftpUploadDropped(path(), files).catch((cause) =>
          showError(cause, "fd0 could not start the upload"),
        );
      }}
    >
      <header class="terminal-window-header files-header">
        <div class="window-drag-handle">
          <span classList={{ "terminal-status": true, "is-closed": Boolean(error()?.reconnect) }} aria-hidden="true" />
          <div class="terminal-identity">
            <strong>{host()}</strong>
            <span>SFTP</span>
          </div>
        </div>
        <nav class="files-header-path" aria-label="Remote path">
          <For each={breadcrumbs()}>
            {(part, index) => (
              <>
                <Show when={index() > 1}><span>/</span></Show>
                <button title={part.label} type="button" onClick={() => {
                  setPreview();
                  void load(part.path);
                }}>
                  {truncate(part.label, 28, "middle")}
                </button>
              </>
            )}
          </For>
        </nav>
        <div class="files-actions">
          <button class="icon-button" type="button" title="Refresh" onClick={refresh}>
            <IconRefresh size={18} classList={{ spinning: loading() || Boolean(preview()?.loading) }} />
          </button>
          <button class="secondary-button" type="button" onClick={() => setDialog({ kind: "mkdir", value: "" })}>
            <IconFolderPlus size={17} />
            New folder
          </button>
          <button class="primary-button" type="button" onClick={upload}>
            <IconUpload size={17} />
            Upload
          </button>
        </div>
      </header>

      <Show when={error()}>
        {(current) => <div class="files-error" role="alert">
          <span>{current().message}</span>
          <div class="files-error-actions">
            <Show when={current().reconnect}>
              <button type="button" onClick={() => void reconnect()}>Reconnect</button>
            </Show>
            <button type="button" title="Dismiss" onClick={() => setError()}><IconX size={17} /></button>
          </div>
        </div>}
      </Show>

      <section class="files-list" aria-busy={loading()}>
        <Show when={preview()} fallback={
          <>
        <div class="files-list-head">
          <span>Name</span>
          <span>Size</span>
          <span>Modified</span>
          <span class="files-permissions">Permissions</span>
          <span />
        </div>
        <Show when={path() !== "/"}>
          <div class="files-row files-parent-row">
            <button
              class="files-row-open"
              type="button"
              aria-label="Open parent folder"
              onClick={() => void load(remoteParent(path()))}
            />
            <div class="files-name">
              <IconFolder size={19} />
              <span>..</span>
            </div>
            <span>—</span>
            <span>Parent folder</span>
            <span class="files-permissions" />
            <span />
          </div>
        </Show>
        <Show
          when={!loading() && sortedEntries().length > 0}
          fallback={<div class="files-empty">{loading() ? "Loading…" : "This directory is empty."}</div>}
        >
          <For each={sortedEntries()}>
            {(entry) => (
              <div class="files-row">
                <Show when={entry.type !== "symlink"}>
                  <button
                    class="files-row-open"
                    type="button"
                    aria-label={`${entry.type === "directory" ? "Open folder" : "Preview file"} ${entry.name}`}
                    onClick={() => openEntry(entry)}
                  />
                </Show>
                <div class="files-name" title={entry.name}>
                  <Show when={entry.type === "directory"} fallback={<IconFile size={19} />}>
                    <IconFolder size={19} />
                  </Show>
                  <span>{truncate(entry.name, 52, "middle")}</span>
                  <Show when={entry.type === "symlink"}><small>link</small></Show>
                </div>
                <span>{entry.type === "directory" ? "—" : formatBytes(entry.size)}</span>
                <span>{new Date(entry.modifiedAt).toLocaleString()}</span>
                <span class="files-permissions">{entry.mode}</span>
                <div class="files-row-actions">
                  <button type="button" title="Download" disabled={entry.type === "symlink"} onClick={() => download(entry)}>
                    <IconDownload size={17} />
                  </button>
                  <MenuButton
                    label={`Actions for ${entry.name}`}
                    sections={[{
                      id: "file-actions",
                      items: [
                        {
                          id: "rename",
                          label: "Rename",
                          icon: IconPencil,
                          run: () => setDialog({ kind: "rename", value: entry.name, entry }),
                        },
                        {
                          id: "delete",
                          label: "Delete",
                          icon: IconTrash,
                          danger: true,
                          run: () => setDialog({ kind: "remove", value: entry.name, entry }),
                        },
                      ],
                    }]}
                  >
                    <IconDots size={18} />
                  </MenuButton>
                </div>
              </div>
            )}
          </For>
        </Show>
          </>
        }>
          {(current) => (
            <section class="files-preview-inline" aria-label={`Preview ${current().entry.name}`}>
              <header>
                <div>
                  <button class="icon-button" type="button" title="Back to files" onClick={() => setPreview()}>
                    <IconArrowLeft size={18} />
                  </button>
                  <IconFile size={18} />
                  <strong title={current().entry.name}>{truncate(current().entry.name, 64, "middle")}</strong>
                  <Show when={current().content}>
                    {(content) => <span>{content().kind === "text" ? "Text" : "Hex"}</span>}
                  </Show>
                </div>
                <button class="secondary-button" type="button" onClick={() => download(current().entry)}>
                  <IconDownload size={16} />
                  Download
                </button>
              </header>
              <Show when={!current().loading} fallback={<div class="files-preview-state">Loading preview…</div>}>
                <div class="files-preview-body">
                  <Show when={current().truncated}>
                    <div class="files-preview-notice">
                      Showing the first {formatBytes(128 * 1024)} of {formatBytes(current().size ?? 0)}.
                    </div>
                  </Show>
                  <pre classList={{ "is-hex": current().content?.kind === "hex" }}>
                    {current().content?.value}
                  </pre>
                </div>
              </Show>
            </section>
          )}
        </Show>
      </section>

      <Show when={visibleTransfers().length > 0}>
        <aside class="files-transfers" aria-label="File transfers">
          <For each={visibleTransfers()}>
            {(transfer) => {
              const percentage = () => transfer.total > 0
                ? Math.min(100, Math.round((transfer.transferred / transfer.total) * 100))
                : 0;
              return (
                <div
                  classList={{
                    "files-transfer": true,
                    "is-failed": transfer.state === "failed",
                  }}
                >
                  <div>
                    <strong>{transfer.name}</strong>
                    <span>
                      {transfer.state === "running"
                        ? `${transfer.direction === "upload" ? "Uploading" : "Downloading"} · ${percentage()}%`
                        : transfer.state === "completed"
                          ? "Completed"
                          : transfer.state === "cancelled"
                            ? "Cancelled"
                            : transfer.error?.message ?? "Failed"}
                    </span>
                  </div>
                  <Show when={transfer.state === "running"}>
                    <progress max="100" value={percentage()} />
                  </Show>
                  <button
                    type="button"
                    title={transfer.state === "running" ? "Cancel transfer" : "Dismiss"}
                    onClick={() => {
                      if (transfer.state === "running") {
                        void window.fd0.sftpCancel(transfer.id).catch((cause) =>
                          showError(cause, "fd0 could not cancel the transfer"),
                        );
                      } else {
                        setTransfers((current) => {
                          const next = { ...current };
                          delete next[transfer.id];
                          return next;
                        });
                      }
                    }}
                  >
                    <IconX size={16} />
                  </button>
                </div>
              );
            }}
          </For>
        </aside>
      </Show>

      <Show when={dragging()}>
        <div class="files-drop-overlay">Drop to upload to {path()}</div>
      </Show>

      <Show when={dialog()}>
        {(current) => (
          <div class="files-dialog-backdrop" role="presentation" onMouseDown={(event) => {
            if (event.currentTarget === event.target) setDialog();
          }}>
            <form class="files-dialog" onSubmit={(event) => {
              event.preventDefault();
              void submitDialog();
            }}>
              <h1>
                {current().kind === "mkdir"
                  ? "New folder"
                  : current().kind === "rename"
                    ? "Rename"
                    : "Delete permanently?"}
              </h1>
              <Show when={current().kind !== "remove"} fallback={<p>This removes {dialogEntryName(current())} from {host()}. This cannot be undone.</p>}>
                <label>
                  Name
                  <input
                    autofocus
                    value={current().value}
                    onInput={(event) => setDialog({ ...current(), value: event.currentTarget.value })}
                  />
                </label>
              </Show>
              <div class="files-dialog-actions">
                <button class="secondary-button" type="button" onClick={() => setDialog()}>Cancel</button>
                <button classList={{ "primary-button": current().kind !== "remove", "danger-button": current().kind === "remove" }} type="submit">
                  {current().kind === "mkdir" ? "Create" : current().kind === "rename" ? "Rename" : "Delete"}
                </button>
              </div>
            </form>
          </div>
        )}
      </Show>

    </main>
  );
}
