export const NFS_GUEST_PORT = 2049;
export const NFS_EXPORT_PATH = "/workspace";

export type Command = { program: string; args: string[] };

export type NfsExportPlan = {
  runtime: "qemu";
  listen: { host: "127.0.0.1"; port: 2049 };
  exportPath: "/workspace";
  prepare: Command[];
  daemons: Command[];
  activate: Command[];
  stop: Command[];
  security: {
    versions: readonly [4];
    authenticationBoundary: "ssh-certificate";
    identityMapping: "all-squash-workspace-user";
  };
};

/**
 * Linux NFSD is the reviewed QEMU reference mechanism. The stock Firecracker
 * kernel has NFSD disabled, so callers must report Firecracker as unsupported
 * instead of changing the network boundary or pretending nfs-utils is enough.
 */
export function createNfsExportPlan(input: { workspaceId: string; runtime: "process" | "qemu" | "firecracker"; nfsdBuiltIn: boolean; persistentWorkspace: boolean }): NfsExportPlan {
  if (input.runtime !== "qemu") throw new Error("Native NFS is available only on the QEMU reference runtime");
  if (!input.nfsdBuiltIn) throw new Error("The guest kernel does not provide NFSD");
  if (!input.persistentWorkspace) throw new Error("Native NFS requires a persistent workspace volume");
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(input.workspaceId)) throw new Error("Invalid workspace id");
  const exportTarget = `127.0.0.1:${NFS_EXPORT_PATH}`;
  const exportOptions = "rw,fsid=0,sync,no_subtree_check,root_squash,all_squash,anonuid=1000,anongid=1000,insecure";
  return {
    runtime: "qemu",
    listen: { host: "127.0.0.1", port: NFS_GUEST_PORT },
    exportPath: NFS_EXPORT_PATH,
    prepare: [
      { program: "/bin/hostname", args: [`bloom-${input.workspaceId.toLowerCase()}`] },
      { program: "/bin/mount", args: ["-t", "nfsd", "nfsd", "/proc/fs/nfsd"] },
      { program: "/usr/sbin/exportfs", args: ["-i", "-o", exportOptions, exportTarget] },
    ],
    daemons: [
      { program: "/usr/sbin/rpc.mountd", args: ["--foreground", "--no-udp", "--no-nfs-version", "2", "--no-nfs-version", "3", "--ttl", "10"] },
    ],
    activate: [
      { program: "/usr/sbin/rpc.nfsd", args: ["--host", "127.0.0.1", "--no-udp", "--no-nfs-version", "2", "--no-nfs-version", "3", "--nfs-version", "4", "--leasetime", "10", "--grace-time", "10", "--port", String(NFS_GUEST_PORT), "1"] },
    ],
    stop: [
      { program: "/usr/sbin/rpc.nfsd", args: ["0"] },
      { program: "/usr/sbin/exportfs", args: ["-u", exportTarget] },
      { program: "/bin/umount", args: ["/proc/fs/nfsd"] },
    ],
    security: { versions: [4], authenticationBoundary: "ssh-certificate", identityMapping: "all-squash-workspace-user" },
  };
}
