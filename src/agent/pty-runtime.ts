import { EventEmitter } from "node:events";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import * as pty from "node-pty";
import type { RuntimeSpec, RuntimeState, TerminalMessage, WorkspaceRuntime } from "./runtime.js";

type Command = { file: string; args: string[]; cwd: string; env?: Record<string, string>; cleanup?: () => Promise<void> };
type Instance = {
  process: pty.IPty;
  leaseExpiresAt: number;
  state: Exclude<RuntimeState, "missing">;
  events: EventEmitter;
  history: string;
  cleanup?: () => Promise<void>;
};

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_HISTORY = 256 * 1024;

export abstract class PtyRuntime implements WorkspaceRuntime {
  protected readonly instances = new Map<string, Instance>();

  constructor(protected readonly dataDir: string) {}

  protected abstract command(spec: RuntimeSpec, workspaceDir: string): Promise<Command>;

  async create(spec: RuntimeSpec) {
    if (!ID.test(spec.id)) throw new Error("Invalid workspace id");
    if (spec.leaseExpiresAt <= Date.now()) throw new Error("Lease is already expired");
    if (this.instances.has(spec.id)) return;
    const workspaceDir = join(this.dataDir, spec.id);
    await mkdir(workspaceDir, { recursive: true, mode: 0o700 });
    const command = await this.command(spec, workspaceDir);
    const events = new EventEmitter();
    const child = pty.spawn(command.file, command.args, {
      name: "xterm-256color",
      cols: 100,
      rows: 30,
      cwd: command.cwd,
      env: command.env ?? minimalEnvironment(),
    });
    const instance: Instance = { process: child, leaseExpiresAt: spec.leaseExpiresAt, state: "running", events, history: "", ...(command.cleanup ? { cleanup: command.cleanup } : {}) };
    this.instances.set(spec.id, instance);
    child.onData((data) => {
      instance.history = (instance.history + data).slice(-MAX_HISTORY);
      events.emit("message", { type: "output", data } satisfies TerminalMessage);
    });
    child.onExit(({ exitCode, signal }) => {
      if (instance.state === "running") instance.state = exitCode === 0 ? "stopped" : "failed";
      events.emit("message", { type: "closed", reason: `process exited (${exitCode}${signal ? `, signal ${signal}` : ""})` } satisfies TerminalMessage);
      void instance.cleanup?.();
      this.forgetLater(spec.id, instance);
    });
  }

  status(id: string): RuntimeState {
    return this.instances.get(id)?.state ?? "missing";
  }

  attach(id: string, listener: (message: TerminalMessage) => void) {
    const instance = this.instances.get(id);
    if (!instance || instance.state !== "running") throw new Error("Workspace is not running");
    if (instance.history) listener({ type: "output", data: instance.history });
    instance.events.on("message", listener);
    return () => instance.events.off("message", listener);
  }

  write(id: string, data: string) {
    if (Buffer.byteLength(data) > 64 * 1024) throw new Error("Terminal input is too large");
    const instance = this.instances.get(id);
    if (!instance || instance.state !== "running") throw new Error("Workspace is not running");
    instance.process.write(data);
  }

  resize(id: string, cols: number, rows: number) {
    const instance = this.instances.get(id);
    if (!instance || instance.state !== "running") return;
    instance.process.resize(Math.max(20, Math.min(300, cols)), Math.max(5, Math.min(120, rows)));
  }

  async stop(id: string, reason: string) {
    const instance = this.instances.get(id);
    if (!instance || instance.state !== "running") return;
    instance.state = "stopped";
    instance.events.emit("message", { type: "closed", reason } satisfies TerminalMessage);
    try { instance.process.kill("SIGKILL"); } catch { /* already exited */ }
    await instance.cleanup?.();
    this.forgetLater(id, instance);
  }

  async sweep(now = Date.now()) {
    await Promise.all([...this.instances.entries()]
      .filter(([, instance]) => instance.state === "running" && instance.leaseExpiresAt <= now)
      .map(([id]) => this.stop(id, "lease expired")));
  }

  async close() {
    await Promise.all([...this.instances.keys()].map((id) => this.stop(id, "node agent stopped")));
  }

  protected cleanupDirectory(id: string) {
    const target = join(this.dataDir, id);
    return async () => { await rm(target, { recursive: true, force: true }); };
  }

  private forgetLater(id: string, instance: Instance) {
    const timer = setTimeout(() => {
      if (this.instances.get(id) !== instance) return;
      instance.history = "";
      instance.events.removeAllListeners();
      this.instances.delete(id);
    }, 60_000);
    timer.unref();
  }
}

function minimalEnvironment() {
  return {
    HOME: "/workspace",
    LANG: "C.UTF-8",
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    TERM: "xterm-256color",
  };
}
