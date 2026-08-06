import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { AgentClient } from "../control/agent-client.js";
import type { RuntimeSpec, RuntimeState, TerminalMessage, WorkspaceRuntime } from "./runtime.js";
import { startAgent } from "./server.js";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => { await Promise.allSettled(cleanups.splice(0).map((cleanup) => cleanup())); });

describe("node terminal gateway", () => {
  it("closes the WebSocket when the runtime terminal closes", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-agent-terminal-"));
    cleanups.push(() => rm(directory, { recursive: true, force: true }));
    const config = loadConfig({ BLOOM_AGENT_SOCKET: join(directory, "agent.sock") }, "agent");
    const runtime = new FakeTerminalRuntime();
    const agent = await startAgent(config, runtime);
    cleanups.push(() => agent.close());
    const client = new AgentClient(config);
    const id = randomUUID();
    await client.create({ id, leaseExpiresAt: Date.now() + 60_000, storage: { mode: "disposable", quotaBytes: 1024 } });
    const terminal = client.terminal(id);
    await new Promise<void>((resolve, reject) => { terminal.once("open", resolve); terminal.once("error", reject); });
    const message = new Promise<string>((resolve) => terminal.once("message", (data) => resolve(data.toString())));
    const closed = new Promise<void>((resolve) => terminal.once("close", () => resolve()));
    runtime.emit({ type: "closed", reason: "lease expired" });
    await expect(message).resolves.toContain('"type":"closed"');
    await expect(closed).resolves.toBeUndefined();
  });
});

class FakeTerminalRuntime implements WorkspaceRuntime {
  private state: RuntimeState = "missing";
  private listener: ((message: TerminalMessage) => void) | undefined;
  async create(_spec: RuntimeSpec) { this.state = "running"; }
  async stop() { this.state = "stopped"; }
  status() { return this.state; }
  attach(_id: string, listener: (message: TerminalMessage) => void) { this.listener = listener; return () => { this.listener = undefined; }; }
  emit(message: TerminalMessage) { this.listener?.(message); }
  write() {}
  resize() {}
  async sweep() {}
  async close() {}
}
