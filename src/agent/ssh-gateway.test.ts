import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer as createTcpServer, type Server as TcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { GuestRequest } from "../guest-protocol.js";
import { loadConfig } from "../config.js";
import { AgentClient } from "../control/agent-client.js";
import type { RuntimeSpec, TerminalMessage, WorkspaceRuntime } from "./runtime.js";
import { startAgent } from "./server.js";

const execute = promisify(execFile);
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.allSettled(cleanups.splice(0).map((cleanup) => cleanup()));
});

describe("node SSH gateway integration", () => {
  it("configures the guest with public material and carries an issued certificate over the private tunnel", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-agent-ssh-"));
    cleanups.push(() => rm(directory, { recursive: true, force: true }));
    const ca = join(directory, "ca");
    const user = join(directory, "user");
    const host = join(directory, "host");
    await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", ca]);
    await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", user]);
    await execute("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", host]);
    await chmod(ca, 0o600);

    const echo = createTcpServer((socket) => socket.on("data", (chunk) => socket.write(chunk)));
    await listen(echo);
    cleanups.push(() => closeServer(echo));
    const port = (echo.address() as import("node:net").AddressInfo).port;
    const runtime = new FakeSshRuntime(port, (await readFile(`${host}.pub`, "utf8")).trim());
    const config = loadConfig({
      BLOOM_RUNTIME: "qemu",
      BLOOM_AGENT_SOCKET: join(directory, "agent.sock"),
      BLOOM_DATA_DIR: join(directory, "data"),
      BLOOM_RUNTIME_SOCKET_DIR: join(directory, "runtime"),
      BLOOM_SSH_ENABLED: "1",
      BLOOM_SSH_CA_KEY: ca,
    }, "agent");
    const agent = await startAgent(config, runtime);
    cleanups.push(() => agent.close());
    const client = new AgentClient(config);
    const id = randomUUID();
    const wallet = "0x1111111111111111111111111111111111111111";
    await client.create({ id, leaseExpiresAt: Date.now() + 60_000, identity: { walletAddress: wallet }, storage: { mode: "disposable", quotaBytes: 128 * 1024 * 1024 } });
    expect(runtime.connectionRequest).toMatchObject({ operation: "connections.configure", workspaceId: id, wallet, nfs: false });
    expect(JSON.stringify(runtime.connectionRequest)).not.toContain("PRIVATE KEY");

    const publicKey = await readFile(`${user}.pub`, "utf8");
    const grant = await client.issueSsh(id, { publicKey, mode: "shell", requestedTtlMs: 20_000 });
    expect(grant.certificate).toMatch(/^ssh-ed25519-cert-v01@openssh.com /);
    expect(grant.hostKey.knownHostsLine).toContain(`bloom-${id} ssh-ed25519 `);
    expect(grant.validBefore).toBeLessThanOrEqual(Date.now() + 21_000);

    const tunnel = client.sshTunnel(id, grant.leaseId, "shell", grant.accessToken);
    await opened(tunnel);
    const received = new Promise<Buffer>((resolve) => tunnel.once("message", (data) => resolve(Buffer.from(data as ArrayBuffer))));
    tunnel.send(Buffer.from("private-ssh-byte-stream"), { binary: true });
    await expect(received).resolves.toEqual(Buffer.from("private-ssh-byte-stream"));
    await client.revokeSsh(id, grant.leaseId);
    await closed(tunnel);
  }, 20_000);
});

class FakeSshRuntime implements WorkspaceRuntime {
  private readonly states = new Map<string, "running" | "stopped">();
  connectionRequest?: GuestRequest;
  constructor(private readonly port: number, private readonly hostKey: string) {}
  async create(spec: RuntimeSpec) { this.states.set(spec.id, "running"); }
  async stop(id: string) { this.states.set(id, "stopped"); }
  status(id: string) { return this.states.get(id) ?? "missing"; }
  attach(_id: string, _listener: (message: TerminalMessage) => void) { return () => undefined; }
  write() {}
  resize() {}
  dataCapabilities() { return { persistence: true, fileTransfer: true }; }
  async guestRequest(_id: string, request: GuestRequest) {
    this.connectionRequest = request;
    if (request.operation !== "connections.configure") throw new Error("unexpected operation");
    return { workspaceId: request.workspaceId, ssh: { available: true, hostKey: this.hostKey, port: 22 }, nfs: { available: false, port: null } };
  }
  sshEndpoint() { return { kind: "tcp" as const, host: "127.0.0.1" as const, port: this.port }; }
  async sweep() {}
  async close() {}
}

function listen(server: TcpServer) {
  return new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
}

function closeServer(server: TcpServer) {
  return new Promise<void>((resolve) => server.close(() => resolve()));
}

function opened(socket: import("ws").default) {
  return new Promise<void>((resolve, reject) => { socket.once("open", resolve); socket.once("error", reject); });
}

function closed(socket: import("ws").default) {
  return new Promise<void>((resolve) => {
    if (socket.readyState === socket.CLOSED) resolve();
    else socket.once("close", () => resolve());
  });
}
