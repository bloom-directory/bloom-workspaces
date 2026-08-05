import type { AddressInfo } from "node:net";
import type { Config } from "../config.js";
import { EgressPolicy } from "./egress-policy.js";
import { createEgressProxy, type EgressProxy } from "./egress-proxy.js";

export type WorkspaceEgress = {
  kernelArgument: "bloom_egress=qemu" | "bloom_egress=vsock";
  qemuGuestForward?: string;
  close(): Promise<void>;
};

export async function startQemuWorkspaceEgress(config: Config, workspaceId: string): Promise<WorkspaceEgress | undefined> {
  if (config.vmEgress !== "controlled") return undefined;
  const proxy = workspaceProxy(config, workspaceId);
  await proxy.listen(0, "127.0.0.1");
  const address = proxy.server.address();
  if (!address || typeof address === "string") {
    await proxy.close();
    throw new Error("Controlled egress proxy did not bind a TCP port");
  }
  return {
    kernelArgument: "bloom_egress=qemu",
    qemuGuestForward: `guestfwd=tcp:10.0.2.100:3128-tcp:127.0.0.1:${(address as AddressInfo).port}`,
    close: idempotentClose(proxy),
  };
}

export async function startFirecrackerWorkspaceEgress(
  config: Config,
  workspaceId: string,
  vsockPath: string,
): Promise<WorkspaceEgress | undefined> {
  if (config.vmEgress !== "controlled") return undefined;
  const proxy = workspaceProxy(config, workspaceId);
  await proxy.listen(`${vsockPath}_3128`);
  return { kernelArgument: "bloom_egress=vsock", close: idempotentClose(proxy) };
}

function workspaceProxy(config: Config, workspaceId: string) {
  return createEgressProxy({
    policy: new EgressPolicy({ allowedHosts: config.egressAllowedHosts }),
    maxConcurrentConnections: config.egressMaxConnections,
    maxBytesPerConnection: config.egressMaxBytesPerConnection,
    maxConnectionMs: config.egressMaxConnectionMs,
    audit: (event) => process.stdout.write(`${JSON.stringify({ component: "workspace-egress", workspaceId, ...event })}\n`),
  });
}

function idempotentClose(proxy: EgressProxy) {
  let closed = false;
  return async () => {
    if (closed) return;
    closed = true;
    await proxy.close();
  };
}
