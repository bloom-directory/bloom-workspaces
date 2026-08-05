export const capabilityNames = [
  "terminal",
  "files",
  "persistence",
  "jobs",
  "bloom",
  "controlledEgress",
  "ssh",
  "nfs",
] as const;

export type CapabilityName = (typeof capabilityNames)[number];
export type CapabilityStatus = "available" | "disabled" | "unsupported";

export type Capability = {
  status: CapabilityStatus;
  reason: string;
  transport?: "websocket" | "https" | "guest-control" | "http-proxy" | "ssh" | "nfs4";
};

export type CapabilitySet = Record<CapabilityName, Capability>;

export type RuntimeCapabilityInputs = {
  runtime: "process" | "qemu" | "firecracker";
  guestControl: boolean;
  persistentDataDisk: boolean;
  egressProxy: boolean;
  sshGateway: boolean;
  nfsGateway: boolean;
};

/**
 * Capability negotiation is deliberately pessimistic. A control-plane feature is
 * advertised only when every runtime dependency that enforces its boundary is
 * present. This prevents a frontend from treating a configured-but-unreachable
 * feature as safe or usable.
 */
export function runtimeCapabilities(input: RuntimeCapabilityInputs): CapabilitySet {
  const developmentProcess = input.runtime === "process";
  const guestControlReason = developmentProcess
    ? "Available through the development runtime"
    : "This VM image/runtime does not expose the bounded guest-control protocol";

  const files = input.guestControl || developmentProcess
    ? available("Authenticated HTTPS file API", "https")
    : unsupported(guestControlReason);

  const persistence = input.persistentDataDisk
    ? available("Wallet-owned quota-bounded data volume", "guest-control")
    : unsupported("This runtime does not attach an independently managed data volume");

  const jobs = input.guestControl
    ? available("Structured argv jobs with bounded logs and cancellation", "guest-control")
    : unsupported(guestControlReason);

  const bloom = input.guestControl
    ? available("Scoped /bloom workspace service surface", "guest-control")
    : unsupported(guestControlReason);

  const controlledEgress = input.egressProxy
    ? available("HTTP/HTTPS only through the policy proxy", "http-proxy")
    : disabled("Controlled Internet access is disabled by the operator");

  const ssh = input.sshGateway && (input.guestControl || developmentProcess)
    ? available("Short-lived workspace-scoped SSH authorization", "ssh")
    : input.sshGateway
      ? unsupported(guestControlReason)
      : disabled("The SSH gateway is disabled by the operator");

  const nfs = input.nfsGateway && input.persistentDataDisk && ssh.status === "available"
    ? available("NFSv4 through the authenticated workspace tunnel", "nfs4")
    : input.nfsGateway
      ? unsupported("NFS requires both a persistent data volume and the authenticated SSH tunnel")
      : disabled("The private NFS gateway is disabled by the operator");

  return {
    terminal: available("Interactive workspace terminal", "websocket"),
    files,
    persistence,
    jobs,
    bloom,
    controlledEgress,
    ssh,
    nfs,
  };
}

function available(reason: string, transport: NonNullable<Capability["transport"]>): Capability {
  return { status: "available", reason, transport };
}

function disabled(reason: string): Capability {
  return { status: "disabled", reason };
}

function unsupported(reason: string): Capability {
  return { status: "unsupported", reason };
}
