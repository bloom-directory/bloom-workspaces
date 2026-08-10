import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { GuestRequest } from "../guest-protocol.js";
import { WorkspaceDataFiles } from "./data-files.js";
import { destroyVolumeDirectory, volumeDirectory } from "./data-volume.js";
import { MockCeremonyStore } from "./mock-ceremony.js";
import { RealBloom } from "./real-bloom.js";
import { RuntimeDataError, type RuntimeSpec } from "./runtime.js";
import { PtyRuntime } from "./pty-runtime.js";

/** Development-only. This is intentionally rejected by public-mode configuration. */
export class ProcessRuntime extends PtyRuntime {
  private readonly storage = new Map<string, RuntimeSpec["storage"]>();
  private readonly files = new WorkspaceDataFiles();
  private readonly petals: readonly string[];
  private readonly mockCeremony: boolean;
  private readonly realBloom: boolean;
  private readonly bloomBin: string;
  private readonly ceremonyStore = new MockCeremonyStore();
  private readonly realBloomInstances = new Map<string, RealBloom>();

  constructor(dataDir: string, petals: readonly string[] = [], mockCeremony = false, realBloom = false, bloomBin = "bloom") {
    super(dataDir);
    this.petals = petals;
    this.mockCeremony = mockCeremony;
    this.realBloom = realBloom;
    this.bloomBin = bloomBin;
  }

  override async create(spec: RuntimeSpec) {
    this.validateStorage(spec);
    this.storage.set(spec.id, spec.storage);
    try {
      await super.create(spec);
      if (this.realBloom) await this.seedRealBloom(spec);
      else if (this.mockCeremony) this.seedMockCeremony(spec);
    }
    catch (error) { this.storage.delete(spec.id); throw error; }
  }

  async guestRequest(id: string, request: GuestRequest): Promise<unknown> {
    if (this.status(id) !== "running") throw new RuntimeDataError("Workspace is not running", 409);
    const realBloom = this.realBloomInstances.get(id);
    if (realBloom) return this.handleRealBloom(realBloom, request);
    if (!this.mockCeremony) throw new RuntimeDataError("The process runtime has no guest control service", 501);
    if (request.operation === "ceremony.pending") return this.ceremonyStore.pending(id);
    if (request.operation === "ceremony.approve") {
      if (!this.ceremonyStore.approve(id, request.txId)) throw new RuntimeDataError("Ceremony request not found", 404);
      return { approved: true };
    }
    throw new RuntimeDataError(`The process runtime does not provide "${request.operation}"`, 501);
  }

  private async handleRealBloom(realBloom: RealBloom, request: GuestRequest): Promise<unknown> {
    if (request.operation === "ceremony.pending") return realBloom.pending();
    if (request.operation === "ceremony.approve") {
      if (!await realBloom.approve(request.txId)) throw new RuntimeDataError("Ceremony request not found", 404);
      return { approved: true };
    }
    throw new RuntimeDataError(`The process runtime does not provide "${request.operation}"`, 501);
  }

  private async seedRealBloom(spec: RuntimeSpec) {
    // bloom binds its IPC socket at <home>/run/bloom.sock, capped at SUN_LEN (108).
    // The deep workspace path exceeds that, so place the home under a short tmp dir.
    const home = join(tmpdir(), `bloom-ws-${spec.id}`);
    const wallet = spec.identity?.walletAddress ?? "0x0000000000000000000000000000000000000000";
    const instance = new RealBloom({ bloomBin: this.bloomBin, home, wallet });
    try {
      await instance.init();
      await instance.stage({ to: "0x1111111111111111111111111111111111111111", value: "1000000", description: "dev relay smoke (real bloom)" });
      this.realBloomInstances.set(spec.id, instance);
    } catch (error) {
      await rm(home, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  }

  override async stop(id: string, reason: string) {
    try { await super.stop(id, reason); }
    finally {
      const instance = this.realBloomInstances.get(id);
      if (instance) {
        this.realBloomInstances.delete(id);
        await rm(instance.home, { recursive: true, force: true }).catch(() => {});
      }
    }
  }

  private seedMockCeremony(spec: RuntimeSpec) {
    const wallet = spec.identity?.walletAddress ?? "0x0000000000000000000000000000000000000000";
    this.ceremonyStore.seed({
      workspaceId: spec.id,
      txId: `dev_mock_${spec.id}`,
      chain: "8453",
      wallet,
      planMd: "# Dev mock transaction\n\nSeeded by BLOOM_DEV_MOCK_CEREMONY=1. Approve to exercise the relay end to end without KVM.\n",
    });
  }

  protected async command(spec: RuntimeSpec, workspaceDir: string) {
    const dataRoot = spec.storage.mode === "persistent"
      ? join(volumeDirectory(this.dataDir, spec.storage.volumeId!), "workspace")
      : join(workspaceDir, "workspace");
    await mkdir(dataRoot, { recursive: true, mode: 0o700 });
    // When real bloom is enabled, expose it inside the workspace shell: bloom on
    // PATH and BLOOM_HOME pointing at the (short, SUN_LEN-safe) workspace bloom
    // home that seedRealBloom provisions. So `bloom`, `bloom vfs ls /`, etc. work
    // from the terminal just like in the VM workspace.
    const bloomHome = this.realBloom ? join(tmpdir(), `bloom-ws-${spec.id}`) : undefined;
    const basePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    return {
      file: "/bin/bash",
      args: ["--noprofile", "--norc"],
      cwd: dataRoot,
      env: {
        HOME: dataRoot,
        LANG: "C.UTF-8",
        PATH: bloomHome ? `${dirname(this.bloomBin)}:${basePath}` : basePath,
        PS1: "\\[\\e[38;5;114m\\]bloom-dev\\[\\e[0m\\]:\\w$ ",
        TERM: "xterm-256color",
        ...(this.petals.length ? { BLOOM_PREINSTALLED_PETALS: this.petals.join(",") } : {}),
        ...(bloomHome ? { BLOOM_HOME: bloomHome } : {}),
      },
      cleanup: this.cleanupDirectory(spec.id),
    };
  }

  dataCapabilities(_id: string) { return { persistence: true, fileTransfer: true }; }

  async listFiles(id: string, path: string) { return this.files.list(this.dataRoot(id), path); }
  async readFile(id: string, path: string) { return this.files.read(this.dataRoot(id), path); }
  async writeFile(id: string, path: string, contents: Buffer) { return this.files.write(this.dataRoot(id), path, contents); }
  async deleteFile(id: string, path: string) { return this.files.delete(this.dataRoot(id), path); }

  async destroyVolume(volumeId: string) {
    for (const [id, storage] of this.storage) {
      if (storage.volumeId === volumeId && this.status(id) === "running") throw new RuntimeDataError("Volume is attached to a running workspace", 409);
    }
    await destroyVolumeDirectory(this.dataDir, volumeId);
  }

  private dataRoot(id: string) {
    if (this.status(id) !== "running") throw new RuntimeDataError("Workspace is not running", 409);
    const storage = this.storage.get(id);
    if (!storage) throw new RuntimeDataError("Workspace data is unavailable", 404);
    return {
      path: storage.mode === "persistent"
        ? join(volumeDirectory(this.dataDir, storage.volumeId!), "workspace")
        : join(this.dataDir, id, "workspace"),
      quotaBytes: storage.quotaBytes,
    };
  }

  private validateStorage(spec: RuntimeSpec) {
    if (!Number.isSafeInteger(spec.storage.quotaBytes) || spec.storage.quotaBytes <= 0) throw new RuntimeDataError("Invalid storage quota", 400);
    if (spec.storage.mode === "persistent") volumeDirectory(this.dataDir, spec.storage.volumeId ?? "");
    else if (spec.storage.volumeId !== undefined) throw new RuntimeDataError("Disposable storage cannot name a persistent volume", 400);
  }
}
