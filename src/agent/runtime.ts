export type RuntimeState = "running" | "stopped" | "failed" | "missing";

export type RuntimeSpec = {
  id: string;
  leaseExpiresAt: number;
};

export type TerminalMessage =
  | { type: "output"; data: string }
  | { type: "closed"; reason: string };

export interface WorkspaceRuntime {
  create(spec: RuntimeSpec): Promise<void>;
  stop(id: string, reason: string): Promise<void>;
  status(id: string): RuntimeState;
  attach(id: string, listener: (message: TerminalMessage) => void): () => void;
  write(id: string, data: string): void;
  resize(id: string, cols: number, rows: number): void;
  sweep(now?: number): Promise<void>;
  close(): Promise<void>;
}
