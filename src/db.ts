import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export type WorkspaceState = "queued" | "provisioning" | "running" | "stopping" | "stopped" | "failed";

export type WorkspaceRow = {
  id: string;
  wallet: string;
  ip_hash: string;
  state: WorkspaceState;
  runtime: string;
  created_at: number;
  lease_expires_at: number;
  stopped_at: number | null;
  failure: string | null;
};

export function openDatabase(path: string) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;

    CREATE TABLE IF NOT EXISTS auth_challenges (
      nonce TEXT PRIMARY KEY,
      domain TEXT NOT NULL,
      uri TEXT NOT NULL,
      chain_id INTEGER NOT NULL,
      ip_hash TEXT NOT NULL,
      issued_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      consumed_at INTEGER
    ) STRICT;
    CREATE INDEX IF NOT EXISTS auth_challenges_ip_time ON auth_challenges(ip_hash, issued_at);
    CREATE INDEX IF NOT EXISTS auth_challenges_time ON auth_challenges(issued_at);

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      wallet TEXT NOT NULL,
      csrf_token TEXT NOT NULL,
      ip_hash TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS sessions_wallet ON sessions(wallet);

    CREATE TABLE IF NOT EXISTS workspaces (
      id TEXT PRIMARY KEY,
      wallet TEXT NOT NULL,
      ip_hash TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('queued','provisioning','running','stopping','stopped','failed')),
      runtime TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      lease_expires_at INTEGER NOT NULL,
      stopped_at INTEGER,
      failure TEXT
    ) STRICT;
    CREATE INDEX IF NOT EXISTS workspaces_wallet ON workspaces(wallet, created_at DESC);
    CREATE INDEX IF NOT EXISTS workspaces_state ON workspaces(state, created_at);
    CREATE INDEX IF NOT EXISTS workspaces_ip ON workspaces(ip_hash, created_at DESC);

    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      occurred_at INTEGER NOT NULL,
      kind TEXT NOT NULL,
      actor TEXT,
      workspace_id TEXT,
      detail TEXT NOT NULL DEFAULT '{}'
    ) STRICT;
    CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events(occurred_at);
  `);
  return db;
}

export type BloomDatabase = ReturnType<typeof openDatabase>;

export function audit(db: BloomDatabase, kind: string, actor?: string, workspaceId?: string, detail: Record<string, unknown> = {}) {
  db.prepare("INSERT INTO audit_events (occurred_at, kind, actor, workspace_id, detail) VALUES (?, ?, ?, ?, ?)")
    .run(Date.now(), kind, actor ?? null, workspaceId ?? null, JSON.stringify(detail));
}
