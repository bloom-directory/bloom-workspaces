import { constants } from "node:fs";
import { access, copyFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.js";
import { destroyVolumeDirectory, ensureExt4Volume, volumeDirectory } from "./data-volume.js";
import { startQemuWorkspaceEgress } from "./egress-session.js";
import { requestGuest } from "./guest-channel.js";
import { GuestWorkspace } from "./guest-workspace.js";
import { waitForGuestControl } from "./guest-ready.js";
import { allocateLoopbackPort } from "./private-port.js";
import type { PrivateSshEndpoint } from "../ssh/contracts.js";
import type { GuestRequest } from "../guest-protocol.js";
import { RuntimeDataError, type RuntimeSpec, type WorkspaceFileEntry, type WorkspaceFileWrite } from "./runtime.js";
import { PtyRuntime } from "./pty-runtime.js";

export class QemuRuntime extends PtyRuntime {
  private readonly storage = new Map<string, RuntimeSpec["storage"]>();
  private readonly sshEndpoints = new Map<string, PrivateSshEndpoint>();

  constructor(private readonly config: Config) { super(config.dataDir); }

  override async create(spec: RuntimeSpec) {
    validateStorage(this.config.dataDir, spec);
    this.storage.set(spec.id, spec.storage);
    try {
      await super.create(spec);
      await waitForGuestControl((request, timeout) => this.guestRequest(spec.id, request, timeout), this.config.vmAccel === "tcg" ? 300_000 : 20_000);
    }
    catch (error) {
      await this.stop(spec.id, "guest control failed readiness").catch(() => undefined);
      this.storage.delete(spec.id);
      throw error;
    }
  }

  protected async command(spec: RuntimeSpec, workspaceDir: string) {
    await Promise.all([access(this.config.vmKernel, constants.R_OK), access(this.config.vmRootfs, constants.R_OK)]);
    const rootfs = join(workspaceDir, "rootfs.ext4");
    const socketDir = join(this.config.runtimeSocketDir, spec.id);
    const controlSocket = join(socketDir, "control.sock");
    await mkdir(socketDir, { recursive: true, mode: 0o700 });
    await copyFile(this.config.vmRootfs, rootfs, constants.COPYFILE_FICLONE);
    const deadline = Math.floor(spec.leaseExpiresAt / 1000);
    const workspaceDisk = spec.storage.mode === "persistent"
      ? await ensureExt4Volume(this.config.dataDir, spec.storage.volumeId!, spec.storage.quotaBytes)
      : undefined;
    const egress = await startQemuWorkspaceEgress(this.config, spec.id);
    const sshEndpoint = this.config.sshEnabled ? { kind: "tcp" as const, host: "127.0.0.1" as const, port: await allocateLoopbackPort() } : undefined;
    if (sshEndpoint) this.sshEndpoints.set(spec.id, sshEndpoint);
    const netdev = this.config.vmEgress === "internet"
      ? `user,id=net0${sshEndpoint ? `,hostfwd=tcp:127.0.0.1:${sshEndpoint.port}-:22` : ""}`
      : `user,id=net0,restrict=on${egress?.qemuGuestForward ? `,${egress.qemuGuestForward}` : ""}${sshEndpoint ? `,hostfwd=tcp:127.0.0.1:${sshEndpoint.port}-:22` : ""}`;
    return {
      file: this.config.qemuBin,
      args: [
        "-machine", "q35",
        "-accel", this.config.vmAccel === "tcg" ? "tcg,thread=multi" : "kvm",
        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-cpu", this.config.vmCpu,
        "-smp", String(this.config.vmVcpus),
        "-m", String(this.config.vmMemoryMib),
        "-kernel", this.config.vmKernel,
        "-append", `console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/usr/local/sbin/bloom-init bloom_transport=qemu bloom_deadline=${deadline}${workspaceDisk ? " bloom_workspace=/dev/vdb" : ""}${egress ? ` ${egress.kernelArgument}` : ""}${spec.identity ? ` bloom_identity=${spec.identity.walletAddress}` : ""}${this.config.preinstalledPetals.length ? ` bloom_petals=${this.config.preinstalledPetals.join(",")}` : ""}`,
        "-drive", `file=${rootfs},if=virtio,format=raw,cache=none,aio=native`,
        ...(workspaceDisk ? ["-drive", `file=${workspaceDisk},if=virtio,format=raw,cache=none,aio=native`] : []),
        "-chardev", `socket,id=bloom-control,path=${controlSocket},server=on,wait=off`,
        "-device", "virtio-serial-pci",
        "-device", "virtserialport,chardev=bloom-control,name=org.bloom.control",
        "-device", "virtio-rng-pci",
        "-netdev", netdev,
        "-device", "virtio-net-pci,netdev=net0",
        "-display", "none",
        "-nodefaults",
        "-monitor", "none",
        "-serial", "stdio",
        "-no-reboot",
      ],
      cwd: workspaceDir,
      cleanup: async () => {
        this.sshEndpoints.delete(spec.id);
        await egress?.close();
        await Promise.all([
          rm(socketDir, { recursive: true, force: true }),
          this.cleanupDirectory(spec.id)(),
        ]);
      },
    };
  }

  dataCapabilities(_id: string) {
    return { persistence: true, fileTransfer: true };
  }

  async listFiles(id: string, path: string): Promise<WorkspaceFileEntry[]> { return this.guestFiles(id).list(path); }
  async readFile(id: string, path: string): Promise<Buffer> { return this.guestFiles(id).read(path); }
  async writeFile(id: string, path: string, contents: Buffer): Promise<WorkspaceFileWrite> { return this.guestFiles(id).write(path, contents); }
  async deleteFile(id: string, path: string): Promise<{ usedBytes: number; quotaBytes: number }> { return this.guestFiles(id).delete(path); }

  guestRequest(id: string, request: GuestRequest, timeoutMs?: number) {
    if (this.status(id) !== "running") throw new RuntimeDataError("Workspace is not running", 409);
    return requestGuest({ kind: "unix", path: join(this.config.runtimeSocketDir, id, "control.sock") }, request, timeoutMs);
  }

  sshEndpoint(id: string): PrivateSshEndpoint {
    if (this.status(id) !== "running") throw new RuntimeDataError("Workspace is not running", 409);
    const endpoint = this.sshEndpoints.get(id);
    if (!endpoint) throw new RuntimeDataError("SSH is unavailable for this workspace", 501);
    return endpoint;
  }

  async destroyVolume(volumeId: string) {
    for (const [id, storage] of this.storage) {
      if (storage.volumeId === volumeId && this.status(id) === "running") throw new RuntimeDataError("Volume is attached to a running workspace", 409);
    }
    await destroyVolumeDirectory(this.config.dataDir, volumeId);
  }

  private guestFiles(id: string) { return new GuestWorkspace((request, timeout) => this.guestRequest(id, request, timeout)); }
}

function validateStorage(dataDir: string, spec: RuntimeSpec) {
  if (spec.storage.mode === "persistent") volumeDirectory(dataDir, spec.storage.volumeId ?? "");
  else if (spec.storage.volumeId !== undefined) throw new RuntimeDataError("Disposable storage cannot name a persistent volume", 400);
}
