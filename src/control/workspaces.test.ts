import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { openDatabase } from "../db.js";
import type { RuntimeSpec, RuntimeState } from "../agent/runtime.js";
import type { AgentClient } from "./agent-client.js";
import { WorkspaceError, WorkspaceService } from "./workspaces.js";

class FakeAgent {
  readonly states = new Map<string, RuntimeState>();
  async create(spec: RuntimeSpec) { this.states.set(spec.id, "running"); return { state: "running" as const }; }
  async stop(id: string) { this.states.set(id, "stopped"); }
  async status(id: string) { return { state: this.states.get(id) ?? "missing" }; }
  async startJob(_id: string, spec: { timeoutMs: number }) { return jobStatus("running", spec.timeoutMs); }
  async jobStatus(_id: string, _jobId: string) { return jobStatus("succeeded", 5_000); }
  async cancelJob(_id: string, _jobId: string) { return jobStatus("cancelled", 5_000); }
  async bloomStatus(_id: string) {
    return { available: true, mount: { path: "/bloom" as const, mounted: false }, identity: { kind: "watch" as const, address: "0x1111111111111111111111111111111111111111" }, capabilities: { files: true, jobs: true, bloomRead: true, walletSigning: false as const, transactions: false as const }, helper: { name: "bloom-workspace" as const, protocolVersion: 1 as const } };
  }
}

describe("public admission", () => {
  it("admits one workspace per wallet and destroys it on request", async () => {
    const db = openDatabase(":memory:");
    const agent = new FakeAgent();
    const service = new WorkspaceService(db, loadConfig(), agent as unknown as AgentClient);
    const first = service.create("0xabc", "ip-a");
    await eventually(() => service.current("0xabc")?.state === "running");
    expect(() => service.create("0xabc", "ip-a")).toThrow(WorkspaceError);
    await service.stopCurrent("0xabc");
    expect(agent.states.get(first.id)).toBe("stopped");
    db.close();
  });

  it("queues fairly when global capacity is occupied", async () => {
    const db = openDatabase(":memory:");
    const agent = new FakeAgent();
    const config = { ...loadConfig(), maxRunning: 1 };
    const service = new WorkspaceService(db, config, agent as unknown as AgentClient);
    service.create("wallet-a", "ip-a");
    await eventually(() => service.current("wallet-a")?.state === "running");
    const second = service.create("wallet-b", "ip-b");
    expect(service.current("wallet-b")).toMatchObject({ id: second.id, state: "queued", queuePosition: 1 });
    await service.stopCurrent("wallet-a");
    await eventually(() => service.current("wallet-b")?.state === "running");
    db.close();
  });

  it("enforces hard expiry through the node agent", async () => {
    const db = openDatabase(":memory:");
    const agent = new FakeAgent();
    const config = { ...loadConfig(), leaseMs: 10 };
    const service = new WorkspaceService(db, config, agent as unknown as AgentClient);
    const workspace = service.create("wallet-a", "ip-a");
    await eventually(() => service.current("wallet-a")?.state === "running");
    await new Promise((resolve) => setTimeout(resolve, 15));
    await service.reconcile();
    expect(agent.states.get(workspace.id)).toBe("stopped");
    db.close();
  });

  it("authorizes structured jobs and watch-only Bloom state to the running owner", async () => {
    const db = openDatabase(":memory:");
    const agent = new FakeAgent();
    const service = new WorkspaceService(db, loadConfig(), agent as unknown as AgentClient);
    const workspace = service.create("wallet-a", "ip-a");
    await eventually(() => service.current("wallet-a")?.state === "running");
    const spec = { argv: ["printf", "%s", "literal;not-a-shell"], cwd: ".", environment: { CI: "1" }, timeoutMs: 5_000 };
    await expect(service.startJob("wallet-a", workspace.id, spec)).resolves.toMatchObject({ state: "running" });
    await expect(service.jobStatus("wallet-a", workspace.id, JOB_ID, 0, 1024)).resolves.toMatchObject({ state: "succeeded" });
    await expect(service.cancelJob("wallet-a", workspace.id, JOB_ID)).resolves.toMatchObject({ state: "cancelled" });
    await expect(service.bloomStatus("wallet-a", workspace.id)).resolves.toMatchObject({ identity: { kind: "watch" }, capabilities: { walletSigning: false } });
    await expect(service.startJob("wallet-b", workspace.id, spec)).rejects.toMatchObject({ status: 404 });
    const audit = db.prepare("SELECT detail FROM audit_events WHERE kind = 'workspace.job_started'").get() as { detail: string };
    expect(JSON.parse(audit.detail)).toEqual({ jobId: JOB_ID, timeoutMs: 5_000, argvCount: 3 });
    db.close();
  });
});

const JOB_ID = randomUUID();

function jobStatus(state: "running" | "succeeded" | "cancelled", timeoutMs: number) {
  const terminal = state !== "running";
  return {
    jobId: JOB_ID, state, createdAt: 1, startedAt: 1, finishedAt: terminal ? 2 : null,
    exitCode: state === "succeeded" ? 0 : null, signal: null, timeoutMs,
    logs: { offset: 0, nextOffset: 0, endOffset: 0, truncatedBefore: false, eof: terminal, encoding: "base64" as const, data: "" },
  };
}

async function eventually(predicate: () => boolean) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("condition was not reached");
}
