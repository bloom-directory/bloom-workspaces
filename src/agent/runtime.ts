export type RuntimeState = "running" | "stopped" | "failed" | "missing";

export type StorageMode = "disposable" | "persistent";

export type RuntimeStorage = {
  mode: StorageMode;
  /** Opaque control-plane allocation. Present only for persistent storage. */
  volumeId?: string;
  quotaBytes: number;
};

export type RuntimeSpec = {
  id: string;
  leaseExpiresAt: number;
  storage: RuntimeStorage;
  /** Public SIWE identity only. Never a signer, token, key, or session secret. */
  identity?: { walletAddress: string };
};

export type WorkspaceDataCapabilities = {
  persistence: boolean;
  persistenceReason?: string;
  fileTransfer: boolean;
  fileTransferReason?: string;
};

export type WorkspaceFileEntry = {
  path: string;
  type: "file" | "directory" | "symlink";
  size: number;
  modifiedAt: number;
};

export type WorkspaceFileWrite = {
  size: number;
  usedBytes: number;
  quotaBytes: number;
};

export class RuntimeDataError extends Error {
  constructor(message: string, readonly status: 400 | 404 | 409 | 413 | 501 = 400) { super(message); }
}

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
  dataCapabilities?(id: string): WorkspaceDataCapabilities;
  listFiles?(id: string, path: string): Promise<WorkspaceFileEntry[]>;
  readFile?(id: string, path: string): Promise<Buffer>;
  writeFile?(id: string, path: string, contents: Buffer): Promise<WorkspaceFileWrite>;
  deleteFile?(id: string, path: string): Promise<{ usedBytes: number; quotaBytes: number }>;
  destroyVolume?(volumeId: string): Promise<void>;
  /** Private control-plane transport into the bounded guest service. */
  guestRequest?(id: string, request: import("../guest-protocol.js").GuestRequest, timeoutMs?: number): Promise<unknown>;
  sshEndpoint?(id: string): import("../ssh/contracts.js").PrivateSshEndpoint;
  sweep(now?: number): Promise<void>;
  close(): Promise<void>;
}
