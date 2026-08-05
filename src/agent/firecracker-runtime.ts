import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { constants } from "node:fs";
import { access, chown, copyFile, mkdir, rm, writeFile } from "node:fs/promises";
import { connect, type Socket } from "node:net";
import { join } from "node:path";
import type { Config } from "../config.js";
import { destroyVolumeDirectory, ensureExt4Volume, volumeDirectory } from "./data-volume.js";
import { startFirecrackerWorkspaceEgress, type WorkspaceEgress } from "./egress-session.js";
import { requestGuest } from "./guest-channel.js";
import { GuestWorkspace } from "./guest-workspace.js";
import { waitForGuestControl } from "./guest-ready.js";
import type { GuestRequest } from "../guest-protocol.js";
import { RuntimeDataError, type RuntimeSpec, type RuntimeState, type TerminalMessage, type WorkspaceFileEntry, type WorkspaceFileWrite, type WorkspaceRuntime } from "./runtime.js";

type PreparedVm = { file: string; args: string[]; cwd: string; vsockPath: string; cleanup: () => Promise<void> };
type Instance = {
  process: ChildProcess;
  state: Exclude<RuntimeState, "missing">;
  leaseExpiresAt: number;
  events: EventEmitter;
  history: string;
  pendingInput: string;
  socket: Socket | undefined;
  connecting: boolean;
  cleanup: () => Promise<void>;
};

const ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_HISTORY = 256 * 1024;

/** Terminal I/O uses AF_VSOCK instead of depending on Firecracker's serial console in production. */
export class FirecrackerRuntime implements WorkspaceRuntime {
  private readonly instances = new Map<string, Instance>();
  private readonly allocatedUids = new Set<number>();
  private readonly storage = new Map<string, RuntimeSpec["storage"]>();

  constructor(private readonly config: Config) {}

  async create(spec: RuntimeSpec) {
    if (!ID.test(spec.id)) throw new Error("Invalid workspace id");
    if (spec.leaseExpiresAt <= Date.now()) throw new Error("Lease is already expired");
    if (this.instances.has(spec.id)) return;
    validateStorage(this.config, spec);
    this.storage.set(spec.id, spec.storage);
    let prepared: PreparedVm;
    try { prepared = await this.prepare(spec); }
    catch (error) { this.storage.delete(spec.id); throw error; }
    const events = new EventEmitter();
    const child = spawn(prepared.file, prepared.args, { cwd: prepared.cwd, stdio: ["ignore", "pipe", "pipe"] });
    const instance: Instance = {
      process: child, state: "running", leaseExpiresAt: spec.leaseExpiresAt, events,
      history: "", pendingInput: "", socket: undefined, connecting: false, cleanup: prepared.cleanup,
    };
    this.instances.set(spec.id, instance);
    let diagnostic = "";
    const collectDiagnostic = (data: Buffer) => { diagnostic = (diagnostic + data.toString()).slice(-16_384); };
    child.stdout?.on("data", collectDiagnostic);
    child.stderr?.on("data", collectDiagnostic);
    child.once("error", (error) => {
      instance.state = "failed";
      events.emit("message", { type: "closed", reason: `Firecracker failed: ${error.message}` } satisfies TerminalMessage);
    });
    child.once("exit", (code, signal) => {
      if (instance.state === "running") instance.state = code === 0 ? "stopped" : "failed";
      instance.socket?.destroy();
      events.emit("message", { type: "closed", reason: `microVM exited (${code ?? signal})${diagnostic ? `: ${lastLine(diagnostic)}` : ""}` } satisfies TerminalMessage);
      if (instance.state === "failed") console.error(`Firecracker workspace ${spec.id} exited (${code ?? signal}): ${diagnostic}`);
      void instance.cleanup();
      this.forgetLater(spec.id, instance);
    });
    try { await waitForGuestControl((request, timeout) => this.guestRequest(spec.id, request, timeout)); }
    catch (error) {
      await this.stop(spec.id, "guest control failed readiness");
      this.storage.delete(spec.id);
      throw error;
    }
  }

  status(id: string): RuntimeState { return this.instances.get(id)?.state ?? "missing"; }

  attach(id: string, listener: (message: TerminalMessage) => void) {
    const instance = this.instances.get(id);
    if (!instance || instance.state !== "running") throw new Error("Workspace is not running");
    if (instance.history) listener({ type: "output", data: instance.history });
    instance.events.on("message", listener);
    this.connectTerminal(id, instance, 0);
    return () => instance.events.off("message", listener);
  }

  write(id: string, data: string) {
    if (Buffer.byteLength(data) > 64 * 1024) throw new Error("Terminal input is too large");
    const instance = this.instances.get(id);
    if (!instance || instance.state !== "running") throw new Error("Workspace is not running");
    if (instance.socket?.writable) instance.socket.write(data);
    else {
      instance.pendingInput += data;
      if (Buffer.byteLength(instance.pendingInput) > 64 * 1024) throw new Error("Terminal input queue is full");
      this.connectTerminal(id, instance, 0);
    }
  }

  resize(_id: string, _cols: number, _rows: number) {
    // The minimal raw-vsock protocol deliberately omits resize. The guest PTY defaults to 100x30.
  }

  dataCapabilities(_id: string) {
    return {
      persistence: !this.config.firecrackerJailed,
      ...(this.config.firecrackerJailed ? { persistenceReason: "Persistent data disks are unsupported with the Firecracker jailer" } : {}),
      fileTransfer: true,
    };
  }

  async listFiles(id: string, path: string): Promise<WorkspaceFileEntry[]> { return this.guestFiles(id).list(path); }
  async readFile(id: string, path: string): Promise<Buffer> { return this.guestFiles(id).read(path); }
  async writeFile(id: string, path: string, contents: Buffer): Promise<WorkspaceFileWrite> { return this.guestFiles(id).write(path, contents); }
  async deleteFile(id: string, path: string): Promise<{ usedBytes: number; quotaBytes: number }> { return this.guestFiles(id).delete(path); }

  guestRequest(id: string, request: GuestRequest, timeoutMs?: number) {
    if (this.status(id) !== "running") throw new RuntimeDataError("Workspace is not running", 409);
    return requestGuest({ kind: "firecracker-vsock", path: this.vsockPath(id), port: 5001 }, request, timeoutMs);
  }

  async destroyVolume(volumeId: string) {
    for (const [id, storage] of this.storage) {
      if (storage.volumeId === volumeId && this.status(id) === "running") throw new RuntimeDataError("Volume is attached to a running workspace", 409);
    }
    await destroyVolumeDirectory(this.config.dataDir, volumeId);
  }

  private guestFiles(id: string) { return new GuestWorkspace((request, timeout) => this.guestRequest(id, request, timeout)); }

  async stop(id: string, reason: string) {
    const instance = this.instances.get(id);
    if (!instance || instance.state !== "running") return;
    instance.state = "stopped";
    instance.events.emit("message", { type: "closed", reason } satisfies TerminalMessage);
    instance.socket?.destroy();
    instance.process.kill("SIGKILL");
    await instance.cleanup();
    this.forgetLater(id, instance);
  }

  async sweep(now = Date.now()) {
    await Promise.all([...this.instances.entries()]
      .filter(([, instance]) => instance.state === "running" && instance.leaseExpiresAt <= now)
      .map(([id]) => this.stop(id, "lease expired")));
  }

  async close() { await Promise.all([...this.instances.keys()].map((id) => this.stop(id, "node agent stopped"))); }

  private connectTerminal(id: string, instance: Instance, attempt: number) {
    if (instance.socket || instance.connecting || instance.state !== "running") return;
    instance.connecting = true;
    const path = this.vsockPath(id);
    const socket = connect(path);
    let handshake = "";
    let connected = false;
    socket.once("connect", () => socket.write("CONNECT 5000\n"));
    socket.on("data", (chunk: Buffer) => {
      if (!connected) {
        handshake += chunk.toString("binary");
        const newline = handshake.indexOf("\n");
        if (newline < 0) return;
        const response = handshake.slice(0, newline);
        if (!response.startsWith("OK ")) { socket.destroy(new Error(`vsock rejected terminal: ${response}`)); return; }
        connected = true;
        instance.connecting = false;
        instance.socket = socket;
        const remainder = Buffer.from(handshake.slice(newline + 1), "binary");
        if (remainder.length) this.emitOutput(instance, remainder.toString());
        if (instance.pendingInput) { socket.write(instance.pendingInput); instance.pendingInput = ""; }
        return;
      }
      this.emitOutput(instance, chunk.toString());
    });
    socket.once("close", () => {
      if (instance.socket === socket) instance.socket = undefined;
      instance.connecting = false;
    });
    socket.once("error", () => {
      instance.connecting = false;
      if (attempt < 100 && instance.state === "running") {
        const timer = setTimeout(() => this.connectTerminal(id, instance, attempt + 1), 100);
        timer.unref();
      } else if (instance.state === "running") {
        instance.events.emit("message", { type: "closed", reason: "guest terminal did not become ready" } satisfies TerminalMessage);
      }
    });
  }

  private emitOutput(instance: Instance, data: string) {
    instance.history = (instance.history + data).slice(-MAX_HISTORY);
    instance.events.emit("message", { type: "output", data } satisfies TerminalMessage);
  }

  private forgetLater(id: string, instance: Instance) {
    const timer = setTimeout(() => {
      if (this.instances.get(id) !== instance) return;
      instance.history = "";
      instance.pendingInput = "";
      instance.events.removeAllListeners();
      this.instances.delete(id);
    }, 60_000);
    timer.unref();
  }

  private vsockPath(id: string) {
    if (!this.config.firecrackerJailed) return join(this.config.runtimeSocketDir, id, "v.sock");
    return join(this.config.jailerChrootBase, "firecracker", id, "root", "run", "vsock.sock");
  }

  private async prepare(spec: RuntimeSpec): Promise<PreparedVm> {
    await Promise.all([
      access(this.config.firecrackerBin, constants.X_OK), access(this.config.vmKernel, constants.R_OK), access(this.config.vmRootfs, constants.R_OK),
      ...(this.config.firecrackerJailed ? [access(this.config.firecrackerJailerBin, constants.X_OK)] : []),
    ]);
    return this.config.firecrackerJailed ? this.prepareJailed(spec) : this.prepareDirect(spec);
  }

  private async prepareDirect(spec: RuntimeSpec): Promise<PreparedVm> {
    const workspaceDir = join(this.config.dataDir, spec.id);
    const socketDir = join(this.config.runtimeSocketDir, spec.id);
    await Promise.all([mkdir(workspaceDir, { recursive: true, mode: 0o700 }), mkdir(socketDir, { recursive: true, mode: 0o700 })]);
    const rootfs = join(workspaceDir, "rootfs.ext4");
    const apiSocket = join(socketDir, "api.sock");
    const configPath = join(workspaceDir, "firecracker.json");
    const vsockPath = this.vsockPath(spec.id);
    await copyFile(this.config.vmRootfs, rootfs, constants.COPYFILE_FICLONE);
    const workspaceDisk = spec.storage.mode === "persistent"
      ? await ensureExt4Volume(this.config.dataDir, spec.storage.volumeId!, spec.storage.quotaBytes)
      : undefined;
    const egress = await startFirecrackerWorkspaceEgress(this.config, spec.id, vsockPath);
    try {
      await writeFile(configPath, JSON.stringify(vmConfig(this.config, spec, this.config.vmKernel, rootfs, vsockPath, workspaceDisk, egress)), { mode: 0o600 });
    } catch (error) {
      await egress?.close();
      throw error;
    }
    return {
      file: this.config.firecrackerBin,
      args: ["--api-sock", apiSocket, "--config-file", configPath],
      cwd: workspaceDir,
      vsockPath,
      cleanup: async () => {
        await egress?.close();
        await Promise.all([rm(workspaceDir, { recursive: true, force: true }), rm(socketDir, { recursive: true, force: true })]);
      },
    };
  }

  private async prepareJailed(spec: RuntimeSpec): Promise<PreparedVm> {
    if (process.getuid?.() !== 0) throw new Error("The Firecracker jailer requires the node agent to run as root");
    let uid = 30_000 + (Number.parseInt(spec.id.slice(0, 8), 16) % 20_000);
    while (this.allocatedUids.has(uid)) uid = 30_000 + ((uid - 29_999) % 20_000);
    this.allocatedUids.add(uid);
    const workspaceDir = join(this.config.dataDir, spec.id);
    const jail = join(this.config.jailerChrootBase, "firecracker", spec.id);
    const root = join(jail, "root");
    const run = join(root, "run");
    await Promise.all([mkdir(workspaceDir, { recursive: true, mode: 0o700 }), mkdir(run, { recursive: true, mode: 0o700 })]);
    const rootfs = join(root, "rootfs.ext4");
    const kernel = join(root, "vmlinux");
    const configPath = join(root, "firecracker.json");
    await Promise.all([copyFile(this.config.vmRootfs, rootfs, constants.COPYFILE_FICLONE), copyFile(this.config.vmKernel, kernel, constants.COPYFILE_FICLONE)]);
    await Promise.all([chown(root, uid, uid), chown(run, uid, uid), chown(rootfs, uid, uid), chown(kernel, uid, uid)]);
    const egress = await startFirecrackerWorkspaceEgress(this.config, spec.id, this.vsockPath(spec.id));
    try {
      await writeFile(configPath, JSON.stringify(vmConfig(this.config, spec, "/vmlinux", "/rootfs.ext4", "/run/vsock.sock", undefined, egress)), { mode: 0o600 });
      await chown(configPath, uid, uid);
    } catch (error) {
      await egress?.close();
      throw error;
    }
    return {
      file: this.config.firecrackerJailerBin,
      args: ["--id", spec.id, "--exec-file", this.config.firecrackerBin, "--uid", String(uid), "--gid", String(uid), "--chroot-base-dir", this.config.jailerChrootBase, "--new-pid-ns", "--", "--api-sock", "/run/firecracker.sock", "--config-file", "/firecracker.json"],
      cwd: workspaceDir,
      vsockPath: this.vsockPath(spec.id),
      cleanup: async () => {
        await egress?.close();
        this.allocatedUids.delete(uid);
        await Promise.all([rm(workspaceDir, { recursive: true, force: true }), rm(jail, { recursive: true, force: true })]);
      },
    };
  }
}

function vmConfig(config: Config, spec: RuntimeSpec, kernel: string, rootfs: string, vsockPath: string, workspaceDisk?: string, egress?: WorkspaceEgress) {
  const deadline = Math.floor(spec.leaseExpiresAt / 1000);
  return {
    "boot-source": { kernel_image_path: kernel, boot_args: `console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/usr/local/sbin/bloom-init bloom_transport=vsock bloom_deadline=${deadline}${workspaceDisk ? " bloom_workspace=/dev/vdb" : ""}${egress ? ` ${egress.kernelArgument}` : ""}${spec.identity ? ` bloom_identity=${spec.identity.walletAddress}` : ""}${config.preinstalledPetals.length ? ` bloom_petals=${config.preinstalledPetals.join(",")}` : ""}` },
    drives: [
      { drive_id: "rootfs", path_on_host: rootfs, is_root_device: true, is_read_only: false },
      ...(workspaceDisk ? [{ drive_id: "workspace", path_on_host: workspaceDisk, is_root_device: false, is_read_only: false }] : []),
    ],
    vsock: { guest_cid: 3, uds_path: vsockPath },
    "machine-config": { vcpu_count: config.vmVcpus, mem_size_mib: config.vmMemoryMib, smt: false },
  };
}

function lastLine(value: string) { return value.trim().split("\n").at(-1)?.slice(0, 500) ?? ""; }

function validateStorage(config: Config, spec: RuntimeSpec) {
  if (spec.storage.mode === "persistent") {
    volumeDirectory(config.dataDir, spec.storage.volumeId ?? "");
    if (config.firecrackerJailed) throw new RuntimeDataError("Persistent data disks are unsupported with the Firecracker jailer", 501);
  }
  else if (spec.storage.volumeId !== undefined) throw new RuntimeDataError("Disposable storage cannot name a persistent volume", 400);
}
