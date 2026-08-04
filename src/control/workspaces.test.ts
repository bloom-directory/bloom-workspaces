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
});

async function eventually(predicate: () => boolean) {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("condition was not reached");
}
