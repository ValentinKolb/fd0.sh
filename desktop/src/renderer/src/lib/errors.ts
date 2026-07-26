/**
 * User-facing error model.
 *
 * The renderer used to hold a single error *string*, so a second failure
 * overwrote the first and raw bridge text ("fd0 bridge protocol mismatch: 3",
 * "Untrusted IPC sender") reached the banner verbatim. An AppError carries a
 * plain-language title, a recovery action, and keeps the protocol text behind
 * a disclosure for support.
 */
export type AppErrorAction = {
  label: string;
  run(): void | Promise<void>;
};

export type AppError = {
  id: number;
  /** One sentence, plain language, names what failed. */
  title: string;
  /** What the user can do about it. Optional but strongly preferred. */
  detail?: string;
  /** The raw message from the bridge or main process. Shown behind "Details". */
  technical?: string;
  severity: "error" | "warning";
  action?: AppErrorAction;
};

let nextID = 1;

type Rule = {
  match: RegExp;
  title: string;
  detail?: string;
  severity?: "error" | "warning";
};

/**
 * Known failures, mapped to language a person can act on. The raw text is never
 * discarded — it moves to `technical`.
 */
const rules: Rule[] = [
  {
    match: /protocol mismatch|incompatible_version|different versions/i,
    title: "fd0 needs a restart to finish updating",
    detail: "The app and the local service are running different versions. Restarting the service reconnects them. Your vault is not changed.",
  },
  {
    match: /bridge supervisor is closed|supervisor.*closed/i,
    title: "Lost contact with the local fd0 service",
    detail: "The background service stopped. Restart it from Support, then try again.",
  },
  {
    match: /restarted after an internal error/i,
    title: "That action was interrupted",
    detail: "The local service recovered from an internal error. Try the action again.",
  },
  {
    match: /did not become ready|agent_unavailable|agent is not running/i,
    title: "The local fd0 service is not responding",
    detail: "fd0 stores and decrypts everything through this service. Restart it from Support.",
  },
  {
    match: /untrusted ipc sender|window is unavailable/i,
    title: "fd0 could not complete that action",
    detail: "The window handling this request is no longer available. Try again.",
  },
  {
    match: /authorization expired/i,
    title: "The editing session expired",
    detail: "For safety, edit permission is short-lived. Close the editor and open the item again.",
  },
  {
    match: /github release lookup|update metadata limit|release signature|authenticated release manifest/i,
    title: "Could not check for updates",
    detail: "fd0 could not verify the update. Your installation is untouched. Try again later.",
  },
  {
    match: /must be smaller than|is larger than|exceeds/i,
    title: "That file is too large",
    detail: "Pick a smaller file and try again.",
    severity: "warning",
  },
  {
    match: /only credential-free https/i,
    title: "fd0 will not open that link",
    detail: "Only plain HTTPS addresses without embedded credentials can be opened.",
    severity: "warning",
  },
  {
    match: /invalid config import|clipboard value is invalid/i,
    title: "fd0 could not read that file",
    detail: "The file is not in a format fd0 recognises.",
    severity: "warning",
  },
  {
    match: /vault is locked/i,
    title: "Your vault locked itself",
    detail: "fd0 locks automatically to keep your items safe. Unlock to continue where you left off.",
    severity: "warning",
  },
  {
    match: /passphrase|unlock failed|invalid key/i,
    title: "That passphrase did not work",
    detail: "Check for typos and try again. fd0 cannot reset it for you.",
    severity: "warning",
  },
  {
    match: /sync_disabled/i,
    title: "Sync is turned off for this vault",
    detail: "This is a development vault. Sync is disabled on purpose.",
    severity: "warning",
  },
  // Legacy-format vaults. These sit above the generic network rule because
  // the offline variant mentions the connection, and the useful thing to say
  // is not "you are offline" but "this vault needs a one-time repair".
  // Matched on message text, not on the bridge code: toAppError only ever
  // sees `message` + `action` (see rawMessage), so a code-based rule would
  // silently never fire.
  {
    match: /older version of fd0 and needs a one-time repair/i,
    title: "This vault needs a one-time repair",
    detail:
      "It was saved by an older version of fd0. Connect this device to the internet and open Sync to finish the repair. Nothing on this device has been changed, so it is safe to try again.",
    severity: "warning",
  },
  {
    match: /older version of fd0, but the history/i,
    title: "This vault needs a one-time repair, and fd0 could not verify it",
    detail:
      "It was saved by an older version of fd0, but the history the server returned does not match the history this device already trusts. Run `fd0 sync` from the command line to reconcile the difference, then reopen fd0. Nothing on this device has been changed.",
  },
  {
    match: /network|connection refused|timeout|dns|unreachable|offline/i,
    title: "fd0 could not reach the sync server",
    detail: "Your vault still works offline. Everything syncs once the connection is back.",
    severity: "warning",
  },
];

function rawMessage(error: unknown): string {
  if (error instanceof Error) {
    const action = "action" in error && typeof error.action === "string" ? error.action : "";
    return action ? `${error.message} ${action}` : error.message;
  }
  if (typeof error === "string") return error;
  return "";
}

/** Builds an AppError from anything thrown by the bridge, IPC, or the renderer. */
export function toAppError(error: unknown, fallbackTitle = "fd0 could not complete that action"): AppError {
  const technical = rawMessage(error);
  const rule = rules.find((candidate) => candidate.match.test(technical));
  if (rule) {
    return {
      id: nextID++,
      title: rule.title,
      detail: rule.detail,
      technical,
      severity: rule.severity ?? "error",
    };
  }
  return {
    id: nextID++,
    title: fallbackTitle,
    detail: technical ? "The details below may help support diagnose this." : undefined,
    technical: technical || undefined,
    severity: "error",
  };
}

/** A warning fd0 raises itself, not from a thrown error. */
export function appWarning(title: string, detail?: string): AppError {
  return { id: nextID++, title, detail, severity: "warning" };
}

/**
 * Legacy helper retained for call sites that still want a flat string.
 * New code should use `toAppError`.
 */
export function errorText(error: unknown): string {
  const message = rawMessage(error);
  return message || "fd0 could not complete that action.";
}
