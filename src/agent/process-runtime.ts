import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { WorkspaceDataFiles } from "./data-files.js";
import { destroyVolumeDirectory, volumeDirectory } from "./data-volume.js";
import { RuntimeDataError, type RuntimeSpec } from "./runtime.js";
import { PtyRuntime } from "./pty-runtime.js";

/** Development-only. This is intentionally rejected by public-mode configuration. */
export class ProcessRuntime extends PtyRuntime {
  private readonly storage = new Map<string, RuntimeSpec["storage"]>();
  private readonly files = new WorkspaceDataFiles();

  override async create(spec: RuntimeSpec) {
    this.validateStorage(spec);
    this.storage.set(spec.id, spec.storage);
    try { await super.create(spec); }
    catch (error) { this.storage.delete(spec.id); throw error; }
  }

  protected async command(spec: RuntimeSpec, workspaceDir: string) {
    const dataRoot = spec.storage.mode === "persistent"
      ? join(volumeDirectory(this.dataDir, spec.storage.volumeId!), "workspace")
      : join(workspaceDir, "workspace");
    await mkdir(dataRoot, { recursive: true, mode: 0o700 });
    return {
      file: "/bin/bash",
      args: ["--noprofile", "--norc"],
      cwd: dataRoot,
      env: {
        HOME: dataRoot,
        LANG: "C.UTF-8",
        PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        PS1: "\\[\\e[38;5;114m\\]bloom-dev\\[\\e[0m\\]:\\w$ ",
        TERM: "xterm-256color",
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
