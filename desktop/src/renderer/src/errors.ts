export function errorText(error: unknown): string {
  if (error instanceof Error) {
    const action = "action" in error && typeof error.action === "string" ? error.action : "";
    return action ? `${error.message} ${action}` : error.message;
  }
  return "fd0 could not complete that action.";
}
