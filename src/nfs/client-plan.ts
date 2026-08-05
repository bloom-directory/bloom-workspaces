import { assertPort } from "../ssh/contracts.js";
import { createSshClientArgv, type SshClientPlanInput } from "../ssh/client-plan.js";

export type ClientPlatform = "linux" | "macos" | "windows" | "android" | "ios" | "unknown";
export type PlatformNfsCapability = {
  status: "supported" | "conditional" | "fallback";
  reason: string;
  requiresAdmin: boolean;
  fallback: "browser-files";
};

export type NfsClientPlan = {
  capability: PlatformNfsCapability;
  sshTunnelArgv?: string[];
  mountArgv?: string[];
  unmountArgv?: string[];
};

export type NfsClientInput = SshClientPlanInput & {
  platform: ClientPlatform;
  localPort: number;
  mountPoint: string;
};

export function nfsPlatformCapability(platform: ClientPlatform): PlatformNfsCapability {
  switch (platform) {
    case "linux": return { status: "supported", reason: "Linux supports the reviewed NFSv4 client over an OpenSSH local tunnel", requiresAdmin: true, fallback: "browser-files" };
    case "macos": return { status: "supported", reason: "macOS supports NFSv4 over an OpenSSH local tunnel; device validation remains required", requiresAdmin: true, fallback: "browser-files" };
    case "windows": return { status: "conditional", reason: "Windows requires the optional Client for NFS, built-in OpenSSH, administrator access to bind local port 2049, and an NFSv4 compatibility probe", requiresAdmin: true, fallback: "browser-files" };
    case "android":
    case "ios": return { status: "fallback", reason: "Mobile platforms use the authenticated browser file API; native NFS is not offered", requiresAdmin: false, fallback: "browser-files" };
    default: return { status: "fallback", reason: "This client platform has not passed the native NFS compatibility gate", requiresAdmin: false, fallback: "browser-files" };
  }
}

/** Build argv arrays, never a shell command. Paths and host data stay values. */
export function createNfsClientPlan(input: NfsClientInput): NfsClientPlan {
  const capability = nfsPlatformCapability(input.platform);
  if (capability.status === "fallback") return { capability };
  assertPort(input.localPort, "local NFS tunnel port");
  for (const [label, value] of [["private key", input.privateKeyPath], ["certificate", input.certificatePath], ["known hosts", input.knownHostsPath], ["mount point", input.mountPoint]] as const) assertLocalValue(value, label);
  if (input.platform === "windows" && input.localPort !== 2049) throw new Error("Windows native NFS requires an administrator-bound local port 2049 tunnel");
  if (input.platform !== "windows" && input.localPort < 1024) throw new Error("Use an unprivileged local NFS tunnel port");

  const sshTunnelArgv = createSshClientArgv(input);
  sshTunnelArgv.splice(1, 0, "-N", "-T", "-o", "ExitOnForwardFailure=yes", "-o", "ClearAllForwardings=yes", "-L", `127.0.0.1:${input.localPort}:127.0.0.1:2049`);

  if (input.platform === "linux") return {
    capability,
    sshTunnelArgv,
    mountArgv: ["mount", "-t", "nfs4", "-o", `vers=4.2,proto=tcp,port=${input.localPort},hard,timeo=600,retrans=2`, "127.0.0.1:/", input.mountPoint],
    unmountArgv: ["umount", input.mountPoint],
  };
  if (input.platform === "macos") return {
    capability,
    sshTunnelArgv,
    mountArgv: ["mount_nfs", "-o", `vers=4,tcp,port=${input.localPort}`, "127.0.0.1:/", input.mountPoint],
    unmountArgv: ["umount", input.mountPoint],
  };
  return {
    capability,
    sshTunnelArgv,
    // The Windows built-in client exposes no documented custom-port option.
    // It can be attempted only after the operator's NFSv4 compatibility probe.
    mountArgv: ["mount.exe", "-o", "anon", "127.0.0.1:/", input.mountPoint],
    unmountArgv: ["umount.exe", input.mountPoint],
  };
}

function assertLocalValue(value: string, label: string) {
  if (!value || value.length > 4096 || value.includes("\0") || value.includes("\n") || value.includes("\r")) throw new Error(`Invalid ${label} path`);
}
