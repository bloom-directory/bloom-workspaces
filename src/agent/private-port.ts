import { createServer, type AddressInfo } from "node:net";

/**
 * Ask the kernel for an unprivileged loopback port immediately before VM spawn.
 * QEMU performs the authoritative bind; a collision fails provisioning instead
 * of falling back to a public or wildcard listener.
 */
export async function allocateLoopbackPort() {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  const address = server.address() as AddressInfo;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return address.port;
}
