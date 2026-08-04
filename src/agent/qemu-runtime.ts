import { constants } from "node:fs";
import { access, copyFile } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.js";
import type { RuntimeSpec } from "./runtime.js";
import { PtyRuntime } from "./pty-runtime.js";

export class QemuRuntime extends PtyRuntime {
  constructor(private readonly config: Config) { super(config.dataDir); }

  protected async command(spec: RuntimeSpec, workspaceDir: string) {
    await Promise.all([access(this.config.vmKernel, constants.R_OK), access(this.config.vmRootfs, constants.R_OK)]);
    const rootfs = join(workspaceDir, "rootfs.ext4");
    await copyFile(this.config.vmRootfs, rootfs, constants.COPYFILE_FICLONE);
    const deadline = Math.floor(spec.leaseExpiresAt / 1000);
    const netdev = this.config.vmEgress === "internet" ? "user,id=net0" : "user,id=net0,restrict=on";
    return {
      file: this.config.qemuBin,
      args: [
        "-machine", "q35,accel=kvm",
        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-cpu", "host",
        "-smp", String(this.config.vmVcpus),
        "-m", String(this.config.vmMemoryMib),
        "-kernel", this.config.vmKernel,
        "-append", `console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/usr/local/sbin/bloom-init bloom_deadline=${deadline}`,
        "-drive", `file=${rootfs},if=virtio,format=raw,cache=none,aio=native`,
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
      cleanup: this.cleanupDirectory(spec.id),
    };
  }
}
