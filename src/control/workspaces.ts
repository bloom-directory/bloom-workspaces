import { randomUUID } from "node:crypto";
import type { Config } from "../config.js";
import type { BloomDatabase, PersistentVolumeRow, WorkspaceRow } from "../db.js";
import { audit } from "../db.js";
import type { StorageMode, WorkspaceDataCapabilities } from "../agent/runtime.js";
import { AgentClient, AgentClientError } from "./agent-client.js";
import type { StructuredJobSpec } from "../jobs/model.js";
import type { SshLeaseBody } from "../ssh/api.js";

const ACTIVE = "'queued','provisioning','running','stopping'";
export const DEFAULT_STORAGE_QUOTA_BYTES = 128 * 1024 * 1024;

export class WorkspaceError extends Error {
  constructor(message: string, readonly status = 400) { super(message); }
}

export class WorkspaceService {
  private reconciling = false;

  constructor(
    private readonly db: BloomDatabase,
    private readonly config: Config,
    private readonly agent: AgentClient,
    private readonly runtimeDataCapabilities?: WorkspaceDataCapabilities,
  ) {}

  create(wallet: string, ipHash: string, options: { storage?: StorageMode } = {}) {
    const now = Date.now();
    const since = now - 24 * 60 * 60_000;
    const normalizedWallet = wallet.toLowerCase();
    const storageMode = options.storage ?? "disposable";
    if (storageMode === "persistent" && this.runtimeDataCapabilities?.persistence === false) {
      throw new WorkspaceError(this.runtimeDataCapabilities.persistenceReason ?? "Persistent storage is unavailable for this runtime", 501);
    }
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const activeWallet = this.count(`SELECT COUNT(*) AS count FROM workspaces WHERE wallet = ? AND state IN (${ACTIVE})`, normalizedWallet);
      if (activeWallet >= this.config.maxActivePerWallet) throw new WorkspaceError("This wallet already has an active workspace", 409);
      const activeIp = this.count(`SELECT COUNT(*) AS count FROM workspaces WHERE ip_hash = ? AND state IN (${ACTIVE})`, ipHash);
      if (activeIp >= this.config.maxActivePerIp) throw new WorkspaceError("This network has reached its active workspace limit", 429);
      const dailyWallet = this.count("SELECT COUNT(*) AS count FROM workspaces WHERE wallet = ? AND created_at >= ?", normalizedWallet, since);
      if (dailyWallet >= this.config.dailyPerWallet) throw new WorkspaceError("This wallet has reached its 24-hour creation limit", 429);
      const dailyIp = this.count("SELECT COUNT(*) AS count FROM workspaces WHERE ip_hash = ? AND created_at >= ?", ipHash, since);
      if (dailyIp >= this.config.dailyPerIp) throw new WorkspaceError("This network has reached its 24-hour creation limit", 429);
      const queued = this.count("SELECT COUNT(*) AS count FROM workspaces WHERE state = 'queued'");
      if (queued >= this.config.maxQueue) throw new WorkspaceError("All workspace capacity and queue slots are currently in use", 503);
      const volume = storageMode === "persistent" ? this.getOrCreatePersistentVolume(normalizedWallet, now) : undefined;
      const row: WorkspaceRow = {
        id: randomUUID(), wallet: normalizedWallet, ip_hash: ipHash, state: "queued", runtime: this.config.runtime,
        created_at: now, lease_expires_at: now + this.config.leaseMs, stopped_at: null, failure: null,
        storage_mode: storageMode, volume_id: volume?.id ?? null, storage_quota_bytes: volume?.quota_bytes ?? DEFAULT_STORAGE_QUOTA_BYTES,
      };
      this.db.prepare("INSERT INTO workspaces (id, wallet, ip_hash, state, runtime, created_at, lease_expires_at, storage_mode, volume_id, storage_quota_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .run(row.id, row.wallet, row.ip_hash, row.state, row.runtime, row.created_at, row.lease_expires_at, row.storage_mode, row.volume_id, row.storage_quota_bytes);
      audit(this.db, "workspace.requested", normalizedWallet, row.id, { runtime: row.runtime, storage: row.storage_mode, quotaBytes: row.storage_quota_bytes });
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

  async listFiles(wallet: string, id: string, path: string) {
    const row = this.ownedRunning(wallet, id, "list");
    return this.dataOperation(row, "list", path, async () => {
      const result = await this.agent.listFiles(row.id, path);
      audit(this.db, "workspace.file_listed", row.wallet, row.id, { path, entries: result.files.length });
      return result.files;
    });
  }

  async readFile(wallet: string, id: string, path: string) {
    const row = this.ownedRunning(wallet, id, "download");
    return this.dataOperation(row, "download", path, async () => {
      const contents = await this.agent.readFile(row.id, path);
      audit(this.db, "workspace.file_downloaded", row.wallet, row.id, { path, bytes: contents.byteLength });
      return contents;
    });
  }

  async writeFile(wallet: string, id: string, path: string, contents: Buffer) {
    const row = this.ownedRunning(wallet, id, "upload");
    return this.dataOperation(row, "upload", path, async () => {
      const result = await this.agent.writeFile(row.id, path, contents);
      audit(this.db, "workspace.file_uploaded", row.wallet, row.id, { path, bytes: contents.byteLength, usedBytes: result.usedBytes });
      return result;
    });
  }

  async deleteFile(wallet: string, id: string, path: string) {
    const row = this.ownedRunning(wallet, id, "delete");
    return this.dataOperation(row, "delete", path, async () => {
      const result = await this.agent.deleteFile(row.id, path);
      audit(this.db, "workspace.file_deleted", row.wallet, row.id, { path, usedBytes: result.usedBytes });
      return result;
    });
  }

  async startJob(wallet: string, id: string, spec: StructuredJobSpec) {
    const row = this.ownedRunning(wallet, id, "job_start");
    try {
      const result = await this.agent.startJob(row.id, spec);
      audit(this.db, "workspace.job_started", row.wallet, row.id, { jobId: result.jobId, timeoutMs: result.timeoutMs, argvCount: spec.argv.length });
      return result;
    } catch (error) { throw this.agentWorkspaceError(error); }
  }

  async jobStatus(wallet: string, id: string, jobId: string, offset: number, maxBytes: number) {
    const row = this.ownedRunning(wallet, id, "job_status");
    try { return await this.agent.jobStatus(row.id, jobId, offset, maxBytes); }
    catch (error) { throw this.agentWorkspaceError(error); }
  }

  async cancelJob(wallet: string, id: string, jobId: string) {
    const row = this.ownedRunning(wallet, id, "job_cancel");
    try {
      const result = await this.agent.cancelJob(row.id, jobId);
      audit(this.db, "workspace.job_cancelled", row.wallet, row.id, { jobId });
      return result;
    } catch (error) { throw this.agentWorkspaceError(error); }
  }

  async bloomStatus(wallet: string, id: string) {
    const row = this.ownedRunning(wallet, id, "bloom_status");
    try { return await this.agent.bloomStatus(row.id); }
    catch (error) { throw this.agentWorkspaceError(error); }
  }

  async connections(wallet: string, id: string) {
    const row = this.ownedRunning(wallet, id, "connections");
    try { return await this.agent.connections(row.id); }
    catch (error) { throw this.agentWorkspaceError(error); }
  }

  async issueSsh(wallet: string, id: string, body: SshLeaseBody) {
    const row = this.ownedRunning(wallet, id, "ssh_issue");
    try {
      const result = await this.agent.issueSsh(row.id, body);
      audit(this.db, "workspace.ssh_issued", row.wallet, row.id, { leaseId: result.leaseId, mode: body.mode, validBefore: result.validBefore });
      return result;
    } catch (error) { throw this.agentWorkspaceError(error); }
  }

  async revokeSsh(wallet: string, id: string, leaseId: string) {
    const row = this.ownedRunning(wallet, id, "ssh_revoke");
    try {
      await this.agent.revokeSsh(row.id, leaseId);
      audit(this.db, "workspace.ssh_revoked", row.wallet, row.id, { leaseId });
    } catch (error) { throw this.agentWorkspaceError(error); }
  }

  async destroyPersistentVolume(wallet: string) {
    const normalizedWallet = wallet.toLowerCase();
    const volume = this.db.prepare("SELECT * FROM persistent_volumes WHERE wallet = ? AND destroyed_at IS NULL").get(normalizedWallet) as PersistentVolumeRow | undefined;
    if (!volume) throw new WorkspaceError("No persistent workspace volume exists", 404);
    const attached = this.db.prepare(`SELECT 1 FROM workspaces WHERE volume_id = ? AND state IN (${ACTIVE})`).get(volume.id);
    if (attached) throw new WorkspaceError("Stop the workspace before destroying its persistent volume", 409);
    try { await this.agent.destroyVolume(volume.id); }
    catch (error) { throw this.agentWorkspaceError(error); }
    this.db.prepare("UPDATE persistent_volumes SET destroyed_at = ? WHERE id = ? AND destroyed_at IS NULL").run(Date.now(), volume.id);
    audit(this.db, "workspace.volume_destroyed", normalizedWallet, undefined, { quotaBytes: volume.quota_bytes });
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
          await this.agent.create({
            id: row.id,
            leaseExpiresAt: row.lease_expires_at,
            identity: { walletAddress: row.wallet },
            storage: row.storage_mode === "persistent"
              ? { mode: "persistent", volumeId: row.volume_id!, quotaBytes: row.storage_quota_bytes }
              : { mode: "disposable", quotaBytes: row.storage_quota_bytes },
          });
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

  private getOrCreatePersistentVolume(wallet: string, now: number) {
    const existing = this.db.prepare("SELECT * FROM persistent_volumes WHERE wallet = ? AND destroyed_at IS NULL").get(wallet) as PersistentVolumeRow | undefined;
    if (existing) {
      this.db.prepare("UPDATE persistent_volumes SET last_attached_at = ? WHERE id = ?").run(now, existing.id);
      return { ...existing, last_attached_at: now };
    }
    const volume: PersistentVolumeRow = {
      id: randomUUID(), wallet, quota_bytes: DEFAULT_STORAGE_QUOTA_BYTES, created_at: now, last_attached_at: now, destroyed_at: null,
    };
    this.db.prepare("INSERT INTO persistent_volumes (id, wallet, quota_bytes, created_at, last_attached_at) VALUES (?, ?, ?, ?, ?)")
      .run(volume.id, volume.wallet, volume.quota_bytes, volume.created_at, volume.last_attached_at);
    audit(this.db, "workspace.volume_created", wallet, undefined, { quotaBytes: volume.quota_bytes });
    return volume;
  }

  private ownedRunning(wallet: string, id: string, operation: string) {
    const normalizedWallet = wallet.toLowerCase();
    const row = this.db.prepare("SELECT * FROM workspaces WHERE id = ? AND wallet = ?").get(id, normalizedWallet) as WorkspaceRow | undefined;
    if (!row) {
      audit(this.db, "workspace.file_denied", normalizedWallet, id, { operation, reason: "not_owner" });
      throw new WorkspaceError("Workspace not found", 404);
    }
    if (row.state !== "running" || row.lease_expires_at <= Date.now()) {
      audit(this.db, "workspace.file_denied", normalizedWallet, id, { operation, reason: "not_running" });
      throw new WorkspaceError("Workspace is not running", 409);
    }
    return row;
  }

  private async dataOperation<T>(row: WorkspaceRow, operation: string, path: string, run: () => Promise<T>) {
    try { return await run(); }
    catch (error) {
      audit(this.db, "workspace.file_failed", row.wallet, row.id, { operation, path, error: error instanceof Error ? error.message : "unknown" });
      throw this.agentWorkspaceError(error);
    }
  }

  private agentWorkspaceError(error: unknown) {
    if (error instanceof AgentClientError) {
      const status = [400, 403, 404, 409, 413, 501].includes(error.status) ? error.status : 503;
      return new WorkspaceError(error.message, status);
    }
    return new WorkspaceError("Workspace node is unavailable", 503);
  }

  private publicWorkspace(row: WorkspaceRow) {
    const result: { id: string; state: WorkspaceRow["state"]; createdAt: number; leaseExpiresAt: number; storage: { mode: StorageMode; quotaBytes: number; retainedAfterStop: boolean }; queuePosition?: number; failure?: string } = {
      id: row.id, state: row.state, createdAt: row.created_at, leaseExpiresAt: row.lease_expires_at,
      storage: { mode: row.storage_mode, quotaBytes: row.storage_quota_bytes, retainedAfterStop: row.storage_mode === "persistent" },
    };
    if (row.failure) result.failure = row.failure;
    if (row.state === "queued") {
      result.queuePosition = 1 + this.count("SELECT COUNT(*) AS count FROM workspaces WHERE state = 'queued' AND created_at < ?", row.created_at);
    }
    return result;
  }
}
