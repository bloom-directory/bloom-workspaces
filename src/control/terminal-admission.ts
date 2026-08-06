export class TerminalAdmission {
  private active = 0;
  private readonly byWorkspace = new Map<string, number>();

  constructor(
    private readonly perWorkspaceLimit: number,
    private readonly globalLimit: number,
  ) {}

  acquire(workspaceId: string): (() => void) | undefined {
    const workspaceCount = this.byWorkspace.get(workspaceId) ?? 0;
    if (workspaceCount >= this.perWorkspaceLimit || this.active >= this.globalLimit) return undefined;
    this.byWorkspace.set(workspaceId, workspaceCount + 1);
    this.active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const remaining = (this.byWorkspace.get(workspaceId) ?? 1) - 1;
      if (remaining === 0) this.byWorkspace.delete(workspaceId);
      else this.byWorkspace.set(workspaceId, remaining);
      this.active -= 1;
    };
  }
}
