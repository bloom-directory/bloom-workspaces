import { nfsPlatformCapability, type ClientPlatform, type PlatformNfsCapability } from "./client-plan.js";

export type NativeNfsDecision = PlatformNfsCapability & {
  runtime: "process" | "qemu" | "firecracker";
  transport?: "nfs4-over-ssh";
};

export function nativeNfsDecision(input: {
  runtime: "process" | "qemu" | "firecracker";
  persistentWorkspace: boolean;
  sshGateway: boolean;
  nfsdBuiltIn: boolean;
  platform: ClientPlatform;
}): NativeNfsDecision {
  const base = nfsPlatformCapability(input.platform);
  if (base.status === "fallback") return { ...base, runtime: input.runtime };
  if (input.runtime !== "qemu") return { status: "fallback", reason: input.runtime === "firecracker" ? "The current Firecracker kernel has no NFSD server; use browser files" : "The development process runtime does not provide an isolated NFS export", requiresAdmin: false, fallback: "browser-files", runtime: input.runtime };
  if (!input.persistentWorkspace) return { status: "fallback", reason: "Native NFS requires a persistent workspace volume", requiresAdmin: false, fallback: "browser-files", runtime: input.runtime };
  if (!input.sshGateway) return { status: "fallback", reason: "Native NFS is disabled until the authenticated SSH gateway is configured", requiresAdmin: false, fallback: "browser-files", runtime: input.runtime };
  if (!input.nfsdBuiltIn) return { status: "fallback", reason: "The QEMU guest kernel has not passed the NFSD capability gate", requiresAdmin: false, fallback: "browser-files", runtime: input.runtime };
  return { ...base, runtime: input.runtime, transport: "nfs4-over-ssh" };
}
