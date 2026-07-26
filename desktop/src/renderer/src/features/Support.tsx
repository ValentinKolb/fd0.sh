import { For, Show, createMemo, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import {
  IconAlertTriangle,
  IconCopy,
  IconExternalLink,
  IconFolder,
  IconRefresh,
  IconShieldCheck,
} from "@tabler/icons-solidjs";
import type { DiagnosticsSnapshot, UpdateStatus } from "../../../shared/contracts";
import { absoluteDate, plural, relativeDate } from "../lib/format";
import { useVault } from "../lib/store";
import { Button } from "../ui/Button";

const DIAGNOSTICS_INTERVAL_MS = 10_000;

/** One thing that is wrong, paired with the single control that fixes it. */
type Problem = {
  /** Lower-case fragment used to build the one-line summary. */
  short: string;
  title: string;
  detail: string;
  actionLabel: string;
  /** Read lazily so a busy signal does not invalidate the whole problem list. */
  disabled?(): boolean;
  run(): void;
};

/**
 * Support.
 *
 * The previous version could say "fd0 needs attention" and then show a row
 * reading "Recovery: Required" with nothing to click. Here every reason the
 * health line turns amber is listed as its own row with its own fix, so the
 * panel is never a dead end.
 */
export function Support(props: Record<string, never>): JSX.Element {
  const vault = useVault();
  const [update, setUpdate] = createSignal<UpdateStatus>({ state: "unsupported" });
  const [diagnostics, setDiagnostics] = createSignal<DiagnosticsSnapshot | null>(null);

  function refreshDiagnostics(): Promise<void> {
    return window.fd0
      .diagnostics()
      .then((snapshot) => {
        setDiagnostics(snapshot);
      })
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not read its own health");
      });
  }

  onMount(() => {
    void window.fd0
      .updateStatus()
      .then(setUpdate)
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not read the update status");
      });
    void refreshDiagnostics();
    const timer = setInterval(() => void refreshDiagnostics(), DIAGNOSTICS_INTERVAL_MS);
    const unsubscribe = window.fd0.onUpdate(setUpdate);
    onCleanup(() => {
      clearInterval(timer);
      unsubscribe();
    });
  });

  function restartService(): void {
    void window.fd0
      .restartAgent()
      .then((next) => {
        vault.setStatus(next);
        vault.notify("Local service restarted");
        void refreshDiagnostics();
      })
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not restart the local service");
      });
  }

  function recheckService(): void {
    void vault.checkLockState();
    void refreshDiagnostics();
  }

  const problems = createMemo<Problem[]>(() => {
    const status = vault.status();
    if (!status) return [];
    const list: Problem[] = [];

    // Only a service this app genuinely cannot talk to is a problem. A service
    // from another release is not: see the Background service section below.
    if (status.agentIncompatible && status.agentStartedBy === "desktop") {
      list.push({
        short: "the local service needs a restart",
        title: "The local service needs a restart",
        detail: `${status.agentIncompatibleReason ?? "This app cannot use the running service."} Restarting locks the vault once — nothing stored is lost.`,
        actionLabel: "Restart local service",
        run: restartService,
      });
    }

    // Not ours to restart: the fix is in the terminal that started it, so the
    // button here only re-checks rather than pretending this app can act.
    if (status.agentIncompatible && status.agentStartedBy !== "desktop") {
      list.push({
        short: "another program runs the service fd0 needs",
        title: "Another program is running the fd0 service",
        detail: `${status.agentIncompatibleReason ?? "This app cannot use the running service."} fd0 Desktop does not stop a service it did not start. Run \`fd0 agent stop\` in the terminal you started it from, then check again.`,
        actionLabel: "Check again",
        run: recheckService,
      });
    }

    // Readiness only means anything once a vault exists on this device.
    if (status.vaultExists && !status.readiness?.recoveryVerifiedAt) {
      list.push({
        short: "there is no recovery file",
        title: "No recovery file yet",
        detail:
          "A recovery file is the only way back into this vault if you lose this device. Nobody can recreate it for you — not even fd0.",
        actionLabel: "Open Settings",
        run: () => vault.setMainView("settings"),
      });
    }

    if (status.vaultExists && !status.readiness?.firstSyncAt) {
      list.push({
        short: "this vault has never synced",
        title: "This vault has never synced",
        detail: "Your items exist only on this device until the first sync finishes.",
        actionLabel: "Sync now",
        disabled: () => vault.syncing(),
        run: () => void vault.sync(),
      });
    }

    return list;
  });

  const healthy = createMemo(() => diagnostics()?.health === "healthy" && problems().length === 0);

  const summary = createMemo(() => {
    if (healthy()) return "The local service, sync, updates, and your recovery file are all in order.";
    const list = problems();
    if (list.length === 0) {
      // Health can turn amber for reasons this panel cannot fix directly, such
      // as a failed sync or a failed update check.
      return "Something did not finish cleanly. Copy diagnostics below and send them with a report.";
    }
    return `${plural(list.length, "thing")} to fix: ${list.map((problem) => problem.short).join(", ")}.`;
  });

  const serviceValue = createMemo(() => {
    const status = vault.status();
    if (status?.agentIncompatible) return "Unusable";
    return status?.agentRunning ? "Running" : "Stopped";
  });

  /**
   * Who owns the fd0 background service.
   *
   * Exactly one service serves a vault, and it is just as normal for the fd0
   * command line to have started it as for this app to have. That used to be
   * invisible — and reported as a version mismatch — so this section names the
   * owner, the version it reports, and says plainly when a difference is fine.
   */
  const serviceHeadline = createMemo(() => {
    const status = vault.status();
    if (!status?.agentRunning) return "Not running";
    if (status.agentIncompatible) return "Running, but this app cannot use it";
    return status.agentStartedBy === "desktop"
      ? "Running — started by fd0 Desktop"
      : "Running — started outside fd0 Desktop";
  });

  const serviceDetail = createMemo(() => {
    const status = vault.status();
    if (!status?.agentRunning) {
      return "fd0 starts the service when you unlock. It holds your keys while the vault is unlocked, and the fd0 command line uses the same one.";
    }
    const reason = status.agentIncompatibleReason ?? "This app cannot use the running service.";
    if (status.agentIncompatible) {
      return status.agentStartedBy === "desktop"
        ? `${reason} Restart the local service to replace it.`
        : `${reason} fd0 Desktop does not stop a service it did not start. Run \`fd0 agent stop\` in the terminal you started it from, then check again.`;
    }
    if (status.agentStartedBy === "desktop") {
      return "This app started it and keeps it running. The fd0 command line shares the same service.";
    }
    const different = status.version && status.expectedVersion && status.version !== status.expectedVersion;
    return "Something else started it — most likely `fd0 unlock` in a terminal. fd0 Desktop shares that service instead of replacing it, so your terminal session stays unlocked."
      + (different
        ? ` It reports ${status.version}, this app is ${status.expectedVersion}: different versions are fine as long as both speak the same service protocol, and these do.`
        : "");
  });

  const serviceBuild = createMemo(() => {
    const status = vault.status();
    if (!status?.agentRunning) return "";
    const flavor = status.flavor === "yubikey" ? "YubiKey build" : "standard build";
    return `${status.version || "unknown version"} · ${flavor}`;
  });

  const versionValue = createMemo(() => {
    const status = vault.status();
    // This app's own version and build. The background service reports its own
    // below, and the two are allowed to differ.
    const version = status?.expectedVersion || "Development";
    // The YubiKey variant changes which unlock methods exist, so it belongs
    // next to the version rather than in a row of its own.
    return status?.expectedFlavor === "yubikey" ? `${version} · YubiKey support` : version;
  });

  const syncValue = createMemo(() => {
    const sync = diagnostics()?.sync;
    if (!sync?.lastAttemptAt) return sync?.state === "error" ? "Failed" : "Not yet";
    const when = relativeDate(sync.lastAttemptAt);
    return sync.state === "error" ? `Failed ${when}` : when;
  });

  const syncTitle = createMemo(() => {
    const at = diagnostics()?.sync.lastAttemptAt;
    return at ? absoluteDate(at) : undefined;
  });

  const updateLabel = createMemo(() => {
    const current = update();
    switch (current.state) {
      case "checking":
        return "Checking…";
      case "available":
        return `${current.version ?? "New version"} available`;
      case "downloading":
        return `Downloading ${Math.round(current.progress ?? 0)}%`;
      case "ready":
        return `${current.version ?? "Update"} ready to install`;
      case "current":
        return "Up to date";
      case "error":
        return current.message ?? "Update check failed";
      case "unsupported":
        return "Updates are managed by however you installed fd0";
      default:
        return "Not checked yet";
    }
  });

  const updateHint = createMemo(() =>
    update().state === "unsupported" ? "" : "fd0 verifies the signature of an update before installing it.",
  );

  const updateBusy = createMemo(() => {
    const state = update().state;
    return state === "checking" || state === "downloading" || state === "unsupported";
  });

  function checkForUpdates(): void {
    void window.fd0
      .checkForUpdates()
      .then(setUpdate)
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not check for updates");
      });
  }

  function installUpdate(): void {
    void window.fd0.installUpdate().catch((cause: unknown) => {
      vault.fail(cause, "fd0 could not install the update");
    });
  }

  function copyDiagnostics(): void {
    void window.fd0
      .copyDiagnostics()
      .then(() => vault.notify("Diagnostics copied"))
      .catch((cause: unknown) => {
        vault.fail(cause, "fd0 could not copy diagnostics");
      });
  }

  function openLogs(): void {
    void window.fd0.openLogs().catch((cause: unknown) => {
      vault.fail(cause, "fd0 could not open the log folder");
    });
  }

  function openSupportLink(target: "docs" | "issues"): void {
    void window.fd0.openSupportLink(target).catch((cause: unknown) => {
      vault.fail(cause, "fd0 could not open that link");
    });
  }

  return (
    <section class="panel">
      <header class="panel-header">
        <h1>Support</h1>
        <p>Health, updates, and help for this device.</p>
      </header>

      <div class="panel-column">
        <div classList={{ callout: true, "callout-good": healthy(), "callout-warn": !healthy() }}>
          <div class="health-summary">
            <Show when={healthy()} fallback={<IconAlertTriangle size={26} strokeWidth={1.6} />}>
              <IconShieldCheck size={26} strokeWidth={1.6} />
            </Show>
            <div>
              <strong>{healthy() ? "Everything is working" : "fd0 needs attention"}</strong>
              <span>{summary()}</span>
            </div>
          </div>
          <For each={problems()}>
            {(problem) => (
              <div class="problem-row">
                <div>
                  <strong>{problem.title}</strong>
                  <small>{problem.detail}</small>
                </div>
                <Button variant="primary" size="sm" disabled={problem.disabled?.()} onClick={problem.run}>
                  {problem.actionLabel}
                </Button>
              </div>
            )}
          </For>
        </div>

        <section class="setting-group">
          <h2 class="eyebrow">Status</h2>
          <div class="status-grid">
            <div class="status-cell">
              <span>Vault</span>
              <strong>{vault.status()?.unlocked ? "Unlocked" : "Locked"}</strong>
            </div>
            <div class="status-cell">
              <span>Local service</span>
              <strong>{serviceValue()}</strong>
            </div>
            <div class="status-cell">
              <span>Version</span>
              <strong>{versionValue()}</strong>
            </div>
            <div class="status-cell" title={syncTitle()}>
              <span>Last sync</span>
              <strong>{syncValue()}</strong>
            </div>
            <div class="status-cell">
              <span>Recovery file</span>
              <strong>{vault.status()?.readiness?.recoveryVerifiedAt ? "Verified" : "Not set up"}</strong>
            </div>
          </div>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Background service</h2>
          <div class="setting-row setting-static">
            <div>
              <strong>{serviceHeadline()}</strong>
              <small>{serviceDetail()}</small>
            </div>
            <Show when={serviceBuild()}>
              <span class="setting-value">{serviceBuild()}</span>
            </Show>
          </div>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Updates</h2>
          <div class="setting-row">
            <div>
              <strong>{updateLabel()}</strong>
              <Show when={updateHint()}>
                <small>{updateHint()}</small>
              </Show>
            </div>
            <Show
              when={update().state === "ready"}
              fallback={
                <Button disabled={updateBusy()} onClick={checkForUpdates}>
                  <IconRefresh size={16} />
                  Check now
                </Button>
              }
            >
              <Button variant="primary" onClick={installUpdate}>
                Restart and update
              </Button>
            </Show>
          </div>
        </section>

        <section class="setting-group">
          <h2 class="eyebrow">Diagnostics</h2>
          <div class="support-actions">
            <Button onClick={copyDiagnostics}>
              <IconCopy size={16} />
              Copy diagnostics
            </Button>
            <Button onClick={openLogs}>
              <IconFolder size={16} />
              Open logs
            </Button>
            <Button onClick={() => openSupportLink("docs")}>
              <IconExternalLink size={16} />
              Open documentation
            </Button>
            <Button onClick={() => openSupportLink("issues")}>
              <IconAlertTriangle size={16} />
              Report a problem
            </Button>
          </div>
          <Show when={diagnostics()}>
            {(snapshot) => (
              <p class="diagnostics-timestamp" title={absoluteDate(snapshot().generatedAt)}>
                Last checked {relativeDate(snapshot().generatedAt)}
              </p>
            )}
          </Show>
        </section>
      </div>
    </section>
  );
}
