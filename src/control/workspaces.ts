import { randomUUID } from "node:crypto";
import type { Config } from "../config.js";
import type { BloomDatabase, WorkspaceRow } from "../db.js";
import { audit } from "../db.js";
import { AgentClient } from "./agent-client.js";

const ACTIVE = "'queued','provisioning','running','stopping'";

export class WorkspaceError extends Error {
  constructor(message: string, readonly status = 400) { super(message); }
}

export class WorkspaceService {
  private reconciling = false;

  constructor(private readonly db: BloomDatabase, private readonly config: Config, private readonly agent: AgentClient) {}

  create(wallet: string, ipHash: string) {
    const now = Date.now();
    const since = now - 24 * 60 * 60_000;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const activeWallet = this.count(`SELECT COUNT(*) AS count FROM workspaces WHERE wallet = ? AND state IN (${ACTIVE})`, wallet);
      if (activeWallet >= this.config.maxActivePerWallet) throw new WorkspaceError("This wallet already has an active workspace", 409);
      const activeIp = this.count(`SELECT COUNT(*) AS count FROM workspaces WHERE ip_hash = ? AND state IN (${ACTIVE})`, ipHash);
      if (activeIp >= this.config.maxActivePerIp) throw new WorkspaceError("This network has reached its active workspace limit", 429);
      const dailyWallet = this.count("SELECT COUNT(*) AS count FROM workspaces WHERE wallet = ? AND created_at >= ?", wallet, since);
      if (dailyWallet >= this.config.dailyPerWallet) throw new WorkspaceError("This wallet has reached its 24-hour creation limit", 429);
      const dailyIp = this.count("SELECT COUNT(*) AS count FROM workspaces WHERE ip_hash = ? AND created_at >= ?", ipHash, since);
      if (dailyIp >= this.config.dailyPerIp) throw new WorkspaceError("This network has reached its 24-hour creation limit", 429);
      const queued = this.count("SELECT COUNT(*) AS count FROM workspaces WHERE state = 'queued'");
      if (queued >= this.config.maxQueue) throw new WorkspaceError("All workspace capacity and queue slots are currently in use", 503);
      const row: WorkspaceRow = {
        id: randomUUID(), wallet: wallet.toLowerCase(), ip_hash: ipHash, state: "queued", runtime: this.config.runtime,
        created_at: now, lease_expires_at: now + this.config.leaseMs, stopped_at: null, failure: null,
      };
      this.db.prepare("INSERT INTO workspaces (id, wallet, ip_hash, state, runtime, created_at, lease_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(row.id, row.wallet, row.ip_hash, row.state, row.runtime, row.created_at, row.lease_expires_at);
      audit(this.db, "workspace.requested", wallet, row.id, { runtime: row.runtime });
      this.db.exec("COMMIT");
      void this.reconcile();
      return this.publicWorkspace(row);
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  current(wallet: string) {
    const row = this.db.prepare(`SELECT * FROM workspaces WHERE wallet = ? ORDER BY CASE WHEN state IN (${ACTIVE}) THEN 0 ELSE 1 END, created_at DESC LIMIT 1`)
      .get(wallet.toLowerCase()) as WorkspaceRow | undefined;
    if (!row) return undefined;
    if (["stopped", "failed"].includes(row.state) && row.created_at < Date.now() - 5 * 60_000) return undefined;
    return this.publicWorkspace(row);
  }

  async stopCurrent(wallet: string) {
    const row = this.db.prepare(`SELECT * FROM workspaces WHERE wallet = ? AND state IN (${ACTIVE}) ORDER BY created_at DESC LIMIT 1`).get(wallet.toLowerCase()) as WorkspaceRow | undefined;
    if (!row) return;
    this.db.prepare("UPDATE workspaces SET state = 'stopping' WHERE id = ? AND state IN ('queued','provisioning','running')").run(row.id);
    await this.agent.stop(row.id).catch((error) => audit(this.db, "workspace.agent_stop_failed", wallet, row.id, { error: String(error) }));
    this.db.prepare("UPDATE workspaces SET state = 'stopped', stopped_at = ? WHERE id = ?").run(Date.now(), row.id);
    audit(this.db, "workspace.stopped", wallet, row.id, { reason: "owner" });
    void this.reconcile();
  }

  ownsRunning(wallet: string, id: string) {
    return Boolean(this.db.prepare("SELECT 1 FROM workspaces WHERE id = ? AND wallet = ? AND state = 'running' AND lease_expires_at > ?")
      .get(id, wallet.toLowerCase(), Date.now()));
  }

  async recover() {
    const active = this.db.prepare("SELECT * FROM workspaces WHERE state IN ('running','provisioning')").all() as unknown as WorkspaceRow[];
    for (const row of active) {
      const status = await this.agent.status(row.id).catch(() => ({ state: "missing" as const }));
      if (status.state !== "running") {
        this.db.prepare("UPDATE workspaces SET state = 'failed', stopped_at = ?, failure = ? WHERE id = ?")
          .run(Date.now(), "Workspace node restarted; request a new workspace", row.id);
        audit(this.db, "workspace.lost", row.wallet, row.id, { agentState: status.state });
      }
    }
    await this.reconcile();
  }

  async reconcile() {
    if (this.reconciling) return;
    this.reconciling = true;
    try {
      const expired = this.db.prepare("SELECT * FROM workspaces WHERE state IN ('queued','provisioning','running') AND lease_expires_at <= ?").all(Date.now()) as unknown as WorkspaceRow[];
      for (const row of expired) {
        await this.agent.stop(row.id).catch(() => undefined);
        this.db.prepare("UPDATE workspaces SET state = 'stopped', stopped_at = ? WHERE id = ?").run(Date.now(), row.id);
        audit(this.db, "workspace.stopped", row.wallet, row.id, { reason: "lease_expired" });
      }

      const running = this.db.prepare("SELECT * FROM workspaces WHERE state = 'running'").all() as unknown as WorkspaceRow[];
      for (const row of running) {
        const status = await this.agent.status(row.id).catch(() => ({ state: "missing" as const }));
        if (status.state !== "running") {
          this.db.prepare("UPDATE workspaces SET state = 'failed', stopped_at = ?, failure = ? WHERE id = ? AND state = 'running'")
            .run(Date.now(), "The workspace process ended unexpectedly; please retry", row.id);
          audit(this.db, "workspace.lost", row.wallet, row.id, { agentState: status.state });
        }
      }

      let capacity = this.config.maxRunning - this.count("SELECT COUNT(*) AS count FROM workspaces WHERE state IN ('running','provisioning')");
      while (capacity-- > 0) {
        const row = this.db.prepare("SELECT * FROM workspaces WHERE state = 'queued' AND lease_expires_at > ? ORDER BY created_at LIMIT 1").get(Date.now()) as WorkspaceRow | undefined;
        if (!row) break;
        const claimed = this.db.prepare("UPDATE workspaces SET state = 'provisioning' WHERE id = ? AND state = 'queued'").run(row.id);
        if (Number(claimed.changes) !== 1) continue;
        try {
          await this.agent.create({ id: row.id, leaseExpiresAt: row.lease_expires_at });
          this.db.prepare("UPDATE workspaces SET state = 'running' WHERE id = ? AND state = 'provisioning'").run(row.id);
          audit(this.db, "workspace.running", row.wallet, row.id);
        } catch (error) {
          this.db.prepare("UPDATE workspaces SET state = 'failed', stopped_at = ?, failure = ? WHERE id = ?")
            .run(Date.now(), "The workspace could not start; please retry", row.id);
          audit(this.db, "workspace.start_failed", row.wallet, row.id, { error: String(error) });
        }
      }
    } finally { this.reconciling = false; }
  }

  private count(sql: string, ...params: (string | number)[]) {
    return Number((this.db.prepare(sql).get(...params) as { count: number }).count);
  }

  private publicWorkspace(row: WorkspaceRow) {
    const result: { id: string; state: WorkspaceRow["state"]; createdAt: number; leaseExpiresAt: number; queuePosition?: number; failure?: string } = {
      id: row.id, state: row.state, createdAt: row.created_at, leaseExpiresAt: row.lease_expires_at,
    };
    if (row.failure) result.failure = row.failure;
    if (row.state === "queued") {
      result.queuePosition = 1 + this.count("SELECT COUNT(*) AS count FROM workspaces WHERE state = 'queued' AND created_at < ?", row.created_at);
    }
    return result;
  }
}
