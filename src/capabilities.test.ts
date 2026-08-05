import { describe, expect, it } from "vitest";
import { capabilityNames, runtimeCapabilities } from "./capabilities.js";

describe("runtime capability negotiation", () => {
  it("never advertises configured gateways without their runtime dependencies", () => {
    const capabilities = runtimeCapabilities({
      runtime: "firecracker",
      guestControl: false,
      persistentDataDisk: false,
      egressProxy: false,
      sshGateway: true,
      nfsGateway: true,
    });

    expect(capabilities.terminal.status).toBe("available");
    expect(capabilities.files.status).toBe("unsupported");
    expect(capabilities.ssh.status).toBe("unsupported");
    expect(capabilities.nfs.status).toBe("unsupported");
    expect(capabilities.controlledEgress.status).toBe("disabled");
  });

  it("does not advertise jobs or Bloom merely because the development file API exists", () => {
    const capabilities = runtimeCapabilities({ runtime: "process", guestControl: false, persistentDataDisk: true, egressProxy: false, sshGateway: false, nfsGateway: false });
    expect(capabilities.files.status).toBe("available");
    expect(capabilities.jobs.status).toBe("unsupported");
    expect(capabilities.bloom.status).toBe("unsupported");
  });

  it("requires a private SSH path and persistent disk before advertising NFS", () => {
    const withoutSsh = runtimeCapabilities({
      runtime: "qemu",
      guestControl: true,
      persistentDataDisk: true,
      egressProxy: true,
      sshGateway: false,
      nfsGateway: true,
    });
    expect(withoutSsh.nfs).toMatchObject({ status: "unsupported" });

    const complete = runtimeCapabilities({
      runtime: "qemu",
      guestControl: true,
      persistentDataDisk: true,
      egressProxy: true,
      sshGateway: true,
      nfsGateway: true,
    });
    expect(complete.nfs).toMatchObject({ status: "available", transport: "nfs4" });
    expect(complete.controlledEgress).toMatchObject({ status: "available", transport: "http-proxy" });
  });

  it("returns an explicit decision for every stable capability name", () => {
    const capabilities = runtimeCapabilities({
      runtime: "process",
      guestControl: false,
      persistentDataDisk: false,
      egressProxy: false,
      sshGateway: false,
      nfsGateway: false,
    });
    expect(Object.keys(capabilities).sort()).toEqual([...capabilityNames].sort());
    expect(Object.values(capabilities).every((capability) => capability.reason.length > 0)).toBe(true);
  });
});
