import { randomUUID } from "node:crypto";

export type OperationGrantKind = "pass.edit" | "secret.edit" | "ssh.edit" | "ssh-key.edit";

type Grant = {
  kind: OperationGrantKind;
  scopeId: string;
  name: string;
  expiresAt: number;
};

export class OperationGrants {
  private readonly grants = new Map<string, Grant>();

  constructor(
    private readonly lifetimeMillis = 2 * 60_000,
    private readonly now: () => number = Date.now,
    private readonly issueID: () => string = randomUUID,
  ) {}

  issue(kind: OperationGrantKind, scopeId: string, name: string): string {
    this.prune();
    const token = this.issueID();
    this.grants.set(token, {
      kind,
      scopeId,
      name,
      expiresAt: this.now() + this.lifetimeMillis,
    });
    return token;
  }

  consume(token: string | undefined, kind: OperationGrantKind, scopeId: string, name: string): boolean {
    if (!token) return false;
    const grant = this.grants.get(token);
    this.grants.delete(token);
    return Boolean(
      grant &&
      grant.expiresAt >= this.now() &&
      grant.kind === kind &&
      grant.scopeId === scopeId &&
      grant.name === name,
    );
  }

  clear(): void {
    this.grants.clear();
  }

  private prune(): void {
    const now = this.now();
    for (const [token, grant] of this.grants) {
      if (grant.expiresAt < now) this.grants.delete(token);
    }
  }
}
