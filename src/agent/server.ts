import { createServer } from "node:http";
import { lstat, mkdir, readFile, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import type { Duplex } from "node:stream";
import express from "express";
import { createWebSocketStream, WebSocketServer, type WebSocket } from "ws";
import { z } from "zod";
import type { Config } from "../config.js";
import { runtimeCapabilities } from "../capabilities.js";
import { BloomGuestStatus } from "../guest/results.js";
import { GuestJobs, type GuestRequestCall } from "../jobs/client.js";
import { StructuredJobSpec } from "../jobs/model.js";
import { safeEqual } from "../security.js";
import { MAX_FILE_TRANSFER_BYTES } from "./data-files.js";
import { RuntimeDataError, type WorkspaceRuntime } from "./runtime.js";
import { requestLogger } from "../logging.js";
import { GuestChannelError } from "./guest-channel.js";
import { GuestConnectionStatus, SshLeaseBody, type AgentSshLeaseGrant } from "../ssh/api.js";
import { workspaceKnownHostsLine } from "../ssh/client-plan.js";
import { SshLeaseManager } from "../ssh/lease-manager.js";
import { validateSshCaPair } from "../ssh/certificate.js";
import { verifyNfsKernelArtifacts } from "../nfs/kernel-gate.js";

const Storage = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("disposable"), quotaBytes: z.number().int().positive().max(5 * 1024 * 1024 * 1024) }).strict(),
  z.object({ mode: z.literal("persistent"), volumeId: z.string().uuid(), quotaBytes: z.number().int().min(16 * 1024 * 1024).max(5 * 1024 * 1024 * 1024) }).strict(),
]);
const CreateBody = z.object({ id: z.string().uuid(), leaseExpiresAt: z.number().int().positive(), storage: Storage }).strict();
const WorkspaceIdentity = z.object({ walletAddress: z.string().regex(/^0x[0-9a-f]{40}$/) }).strict();
const CreateWorkspaceBody = CreateBody.extend({ identity: WorkspaceIdentity.optional() }).strict();
const FilePath = z.string().max(4_096);
const TerminalInput = z.discriminatedUnion("type", [
  z.object({ type: z.literal("input"), data: z.string().max(65_536) }),
  z.object({ type: z.literal("resize"), cols: z.number().int(), rows: z.number().int() }),
]);
const JobId = z.string().uuid();
const JobStatusQuery = z.object({
  offset: z.coerce.number().int().nonnegative().default(0),
  maxBytes: z.coerce.number().int().min(1).max(256 * 1024).default(256 * 1024),
});

export async function startAgent(config: Config, runtime: WorkspaceRuntime) {
  await prepareSocket(config.agentSocket);
  if (config.nfsEnabled) await verifyNfsKernelArtifacts(config.vmKernel, config.nfsKernelConfig!);
  const caPublicKey = config.sshEnabled
    ? await validateSshCaPair(config.sshCaKeyPath!, await readFile(`${config.sshCaKeyPath!}.pub`, "utf8"))
    : undefined;
  const ssh = config.sshEnabled
    ? new SshLeaseManager({ caKeyPath: config.sshCaKeyPath!, privateSocketRoot: config.runtimeSocketDir, maxLeaseMs: config.sshMaxLeaseMs })
    : undefined;
  const connections = new Map<string, {
    wallet: string;
    leaseExpiresAt: number;
    storageMode: "disposable" | "persistent";
    guest: GuestConnectionStatus;
  }>();
  const app = express();
  app.disable("x-powered-by");
  app.use(requestLogger("agent"));
  app.use(express.json({ limit: "16kb" }));
  app.use((request, response, next) => {
    const token = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
    if (!safeEqual(token, config.agentToken)) { response.status(401).json({ error: "Unauthorized" }); return; }
    next();
  });

  const advertisedCapabilities = () => {
    const runtimeDataCapabilities = runtime.dataCapabilities?.("") ?? {
      persistence: false,
      persistenceReason: "Runtime persistence is unavailable",
      fileTransfer: false,
      fileTransferReason: "Runtime data API is unavailable",
    };
    const dataCapabilities = config.persistenceEnabled
      ? runtimeDataCapabilities
      : { ...runtimeDataCapabilities, persistence: false, persistenceReason: "Persistent workspace volumes are disabled by the operator" };
    return {
      dataCapabilities,
      capabilities: runtimeCapabilities({
        runtime: config.runtime,
        guestControl: Boolean(runtime.guestRequest),
        persistentDataDisk: dataCapabilities.persistence,
        egressProxy: config.vmEgress === "controlled",
        sshGateway: Boolean(ssh && runtime.sshEndpoint && runtime.guestRequest),
        nfsGateway: Boolean(config.nfsEnabled && ssh && runtime.sshEndpoint && runtime.guestRequest),
      }),
    };
  };
  app.get("/v1/health", (_request, response) => response.json({ ok: true, runtime: config.runtime, ...advertisedCapabilities() }));
  app.post("/v1/workspaces", async (request, response, next) => {
    try {
      const parsed = CreateWorkspaceBody.parse(request.body);
      const spec = { id: parsed.id, leaseExpiresAt: parsed.leaseExpiresAt, storage: parsed.storage, ...(parsed.identity ? { identity: parsed.identity } : {}) };
      if (spec.storage.mode === "persistent" && !config.persistenceEnabled) throw new RuntimeDataError("Persistent workspace volumes are disabled by the operator", 501);
      if (spec.leaseExpiresAt > Date.now() + config.maxLeaseMs + 60_000) throw new Error("Lease exceeds node maximum");
      await runtime.create(spec);
      if (ssh) {
        try {
          if (!runtime.guestRequest || !runtime.sshEndpoint || !spec.identity) throw new RuntimeDataError("SSH is unsupported by this runtime", 501);
          const guest = GuestConnectionStatus.parse(await runtime.guestRequest(spec.id, {
            version: 1,
            id: `connections_${spec.id.replaceAll("-", "")}`,
            operation: "connections.configure",
            workspaceId: spec.id,
            wallet: spec.identity.walletAddress,
            caPublicKey: caPublicKey!,
            nfs: config.nfsEnabled && spec.storage.mode === "persistent",
          }, 15_000));
          runtime.sshEndpoint(spec.id);
          connections.set(spec.id, {
            wallet: spec.identity.walletAddress,
            leaseExpiresAt: spec.leaseExpiresAt,
            storageMode: spec.storage.mode,
            guest,
          });
        } catch (error) {
          await runtime.stop(spec.id, "private connection setup failed").catch(() => undefined);
          throw error;
        }
      }
      response.status(201).json({ state: runtime.status(spec.id) });
    } catch (error) { next(error); }
  });
  app.get("/v1/workspaces/:id", (request, response) => {
    const id = request.params.id ?? "";
    response.json({ state: runtime.status(id), ...advertisedCapabilities() });
  });
  app.delete("/v1/workspaces/:id", async (request, response, next) => {
    const id = request.params.id ?? "";
    try {
      ssh?.revokeWorkspace(id);
      connections.delete(id);
      await runtime.stop(id, "destroyed by owner");
      response.status(204).end();
    } catch (error) { next(error); }
  });
  app.get("/v1/workspaces/:id/files", async (request, response, next) => {
    try {
      const path = FilePath.parse(request.query.path ?? "");
      response.json({ files: await requireDataMethod(runtime.listFiles, "File listing").call(runtime, request.params.id ?? "", path) });
    } catch (error) { next(error); }
  });
  app.get("/v1/workspaces/:id/files/content", async (request, response, next) => {
    try {
      const path = FilePath.min(1).parse(request.query.path);
      const contents = await requireDataMethod(runtime.readFile, "File download").call(runtime, request.params.id ?? "", path);
      response.type("application/octet-stream").set("content-length", String(contents.byteLength)).send(contents);
    } catch (error) { next(error); }
  });
  app.put("/v1/workspaces/:id/files", express.raw({ type: "application/octet-stream", limit: MAX_FILE_TRANSFER_BYTES }), async (request, response, next) => {
    try {
      const path = FilePath.min(1).parse(request.query.path);
      if (!Buffer.isBuffer(request.body)) throw new RuntimeDataError("Upload must use application/octet-stream", 400);
      response.json(await requireDataMethod(runtime.writeFile, "File upload").call(runtime, request.params.id ?? "", path, request.body));
    } catch (error) { next(error); }
  });
  app.delete("/v1/workspaces/:id/files", async (request, response, next) => {
    try {
      const path = FilePath.min(1).parse(request.query.path);
      response.json(await requireDataMethod(runtime.deleteFile, "File delete").call(runtime, request.params.id ?? "", path));
    } catch (error) { next(error); }
  });
  app.delete("/v1/volumes/:id", async (request, response, next) => {
    try { await requireDataMethod(runtime.destroyVolume, "Persistent volume destruction").call(runtime, request.params.id ?? ""); response.status(204).end(); }
    catch (error) { next(error); }
  });
  app.post("/v1/workspaces/:id/jobs", async (request, response, next) => {
    try {
      const jobs = guestJobs(runtime, request.params.id ?? "");
      response.status(202).json(await jobs.start(StructuredJobSpec.parse(request.body)));
    } catch (error) { next(error); }
  });
  app.get("/v1/workspaces/:id/jobs/:jobId", async (request, response, next) => {
    try {
      const query = JobStatusQuery.parse(request.query);
      response.json(await guestJobs(runtime, request.params.id ?? "").status(JobId.parse(request.params.jobId), query.offset, query.maxBytes));
    } catch (error) { next(error); }
  });
  app.delete("/v1/workspaces/:id/jobs/:jobId", async (request, response, next) => {
    try { response.json(await guestJobs(runtime, request.params.id ?? "").cancel(JobId.parse(request.params.jobId))); }
    catch (error) { next(error); }
  });
  app.get("/v1/workspaces/:id/bloom", async (request, response, next) => {
    try {
      const call = requireGuest(runtime, request.params.id ?? "");
      response.json(BloomGuestStatus.parse(await call({ version: 1, id: `bloom_${request.params.id?.replaceAll("-", "") ?? "status"}`, operation: "bloom.status" }, 10_000)));
    } catch (error) { next(error); }
  });
  app.get("/v1/workspaces/:id/connections", (request, response, next) => {
    try {
      const id = request.params.id ?? "";
      if (runtime.status(id) !== "running") throw new RuntimeDataError("Workspace is not running", 409);
      const state = connections.get(id);
      response.json({
        connections: {
          ssh: state?.guest.ssh.available
            ? { status: "available", reason: "Short-lived OpenSSH certificates through the authenticated WebSocket tunnel", instructions: ["Generate an Ed25519 key locally; submit only the .pub line.", "Save the returned certificate, host-key line, and one-time token with mode 0600.", "Install the Bloom ProxyCommand helper and connect before the lease expires."] }
            : { status: config.sshEnabled ? "unsupported" : "disabled", reason: config.sshEnabled ? "SSH setup did not complete for this workspace" : "SSH is disabled by the operator", instructions: ["Use the browser terminal."] },
          nfs: state?.guest.nfs.available
            ? { status: "available", reason: "NFSv4 is private to an NFS-mode SSH tunnel", instructions: ["Issue an NFS-mode grant.", "Start the local SSH forward, then mount the loopback endpoint.", "Unmount before the short-lived lease expires."] }
            : { status: config.nfsEnabled ? "unsupported" : "disabled", reason: config.nfsEnabled && state?.storageMode !== "persistent" ? "Native NFS requires a persistent workspace" : config.nfsEnabled ? "The guest NFSD capability is unavailable" : "Native NFS is disabled by the operator", instructions: ["Use the authenticated browser file API."] },
        },
      });
    } catch (error) { next(error); }
  });
  app.get("/v1/workspaces/:id/ceremony", async (request, response, next) => {
    try {
      const call = requireGuest(runtime, request.params.id ?? "");
      const result = await call({ version: 1, id: `ceremony_pending_${(request.params.id ?? "").replaceAll("-", "")}`, operation: "ceremony.pending" }, 10_000);
      response.json(result);
    } catch (error) { next(error); }
  });
  app.post("/v1/workspaces/:id/connections/ssh", async (request, response, next) => {
    try {
      if (!ssh || !runtime.sshEndpoint) throw new RuntimeDataError("SSH is disabled by the operator", 501);
      const id = request.params.id ?? "";
      if (runtime.status(id) !== "running") throw new RuntimeDataError("Workspace is not running", 409);
      const state = connections.get(id);
      if (!state?.guest.ssh.available) throw new RuntimeDataError("SSH is unavailable for this workspace", 501);
      const body = SshLeaseBody.parse(request.body);
      if (body.mode === "nfs" && !state.guest.nfs.available) throw new RuntimeDataError("Native NFS is unavailable for this workspace", 501);
      const grant = await ssh.issue({
        workspaceId: id,
        wallet: state.wallet,
        publicKey: body.publicKey,
        mode: body.mode,
        workspaceLeaseExpiresAt: state.leaseExpiresAt,
        ...(body.requestedTtlMs === undefined ? {} : { requestedTtlMs: body.requestedTtlMs }),
        endpoint: runtime.sshEndpoint(id),
      });
      const hostKey = workspaceKnownHostsLine(id, state.guest.ssh.hostKey);
      const result: AgentSshLeaseGrant = {
        ...grant,
        hostKey: { alias: hostKey.alias, knownHostsLine: hostKey.line, fingerprint: hostKey.fingerprint },
      };
      response.status(201).json(result);
    } catch (error) { next(error); }
  });
  app.delete("/v1/workspaces/:id/connections/ssh/:leaseId", (request, response, next) => {
    try {
      if (!ssh) throw new RuntimeDataError("SSH is disabled by the operator", 501);
      const id = request.params.id ?? "";
      const state = connections.get(id);
      if (!state) throw new RuntimeDataError("Workspace connections are unavailable", 404);
      ssh.revoke({ leaseId: request.params.leaseId ?? "", workspaceId: id, wallet: state.wallet });
      response.status(204).end();
    } catch (error) { next(error); }
  });
  app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
    const message = error instanceof Error ? error.message : "Node agent error";
    const parserStatus = typeof error === "object" && error !== null && "status" in error && typeof error.status === "number" ? error.status : undefined;
    const guestStatus = error instanceof GuestChannelError
      ? error.code === "not_found" ? 404 : error.code === "conflict" ? 409 : error.code === "limit_exceeded" ? 413 : error.code === "permission_denied" ? 403 : error.code === "unavailable" || error.code === "transport" ? 501 : 400
      : undefined;
    const status = error instanceof z.ZodError ? 400 : error instanceof RuntimeDataError ? error.status : guestStatus ?? parserStatus ?? 500;
    response.status(status).json({ error: message });
  });

  const server = createServer(app);
  const sockets = new WebSocketServer({ noServer: true, maxPayload: 70 * 1024 });
  const sshSockets = new WebSocketServer({ noServer: true, maxPayload: 1024 * 1024 });
  server.on("upgrade", (request, socket, head) => {
    const token = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
    const url = new URL(request.url ?? "/", "http://agent.local");
    const terminal = url.pathname.match(/^\/v1\/workspaces\/([0-9a-f-]+)\/terminal$/i);
    if (!safeEqual(token, config.agentToken)) { rejectUpgrade(socket); return; }
    if (terminal?.[1]) {
      sockets.handleUpgrade(request, socket, head, (websocket) => attachTerminal(websocket, terminal[1]!, runtime));
      return;
    }
    const tunnel = url.pathname.match(/^\/v1\/workspaces\/([0-9a-f-]+)\/connections\/ssh\/tunnel$/i);
    const id = tunnel?.[1];
    const state = id ? connections.get(id) : undefined;
    const leaseId = url.searchParams.get("lease") ?? "";
    const mode = url.searchParams.get("mode");
    const accessToken = typeof request.headers["x-bloom-ssh-token"] === "string" ? request.headers["x-bloom-ssh-token"] : "";
    const protocols = String(request.headers["sec-websocket-protocol"] ?? "").split(",").map((value) => value.trim());
    if (!ssh || !id || !state || (mode !== "shell" && mode !== "nfs") || !protocols.includes("bloom-ssh-v1")) { rejectUpgrade(socket); return; }
    void ssh.openTunnel({ leaseId, workspaceId: id, wallet: state.wallet, mode, accessToken }).then((upstream) => {
      sshSockets.handleUpgrade(request, socket, head, (websocket) => attachSshTunnel(websocket, upstream));
    }).catch(() => rejectUpgrade(socket));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.agentSocket, () => { server.off("error", reject); resolve(); });
  });
  await new Promise<void>((resolve, reject) => {
    import("node:fs").then(({ chmod }) => chmod(config.agentSocket, 0o660, (error) => error ? reject(error) : resolve()), reject);
  });
  const sweeper = setInterval(() => {
    void runtime.sweep().catch(() => undefined).finally(() => {
      for (const id of connections.keys()) {
        if (runtime.status(id) === "running") continue;
        ssh?.revokeWorkspace(id);
        connections.delete(id);
      }
    });
  }, 1_000);
  const leaseSweeper = setInterval(() => ssh?.sweepExpired(), 1_000);
  sweeper.unref();
  leaseSweeper.unref();

  return {
    async close() {
      clearInterval(sweeper);
      clearInterval(leaseSweeper);
      sockets.clients.forEach((socket) => socket.close(1012, "agent shutting down"));
      sshSockets.clients.forEach((socket) => socket.close(1012, "agent shutting down"));
      ssh?.stop();
      await runtime.close();
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await unlink(config.agentSocket).catch(() => undefined);
    },
  };
}

function attachSshTunnel(socket: WebSocket, upstream: Duplex) {
  const bridge = createWebSocketStream(socket, { encoding: undefined, highWaterMark: 256 * 1024 });
  const close = () => { bridge.destroy(); upstream.destroy(); };
  bridge.once("error", close);
  upstream.once("error", close);
  bridge.pipe(upstream).pipe(bridge);
}

function rejectUpgrade(socket: import("node:stream").Duplex) {
  if (!socket.destroyed) socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
  socket.destroy();
}

function attachTerminal(socket: WebSocket, id: string, runtime: WorkspaceRuntime) {
  let detach: (() => void) | undefined;
  try {
    detach = runtime.attach(id, (message) => socket.readyState === socket.OPEN && socket.send(JSON.stringify(message)));
  } catch (error) {
    socket.close(1011, error instanceof Error ? error.message : "Workspace unavailable");
    return;
  }
  socket.on("message", (raw) => {
    try {
      const message = TerminalInput.parse(JSON.parse(raw.toString()));
      if (message.type === "input") runtime.write(id, message.data);
      else runtime.resize(id, message.cols, message.rows);
    } catch { socket.close(1008, "Invalid terminal message"); }
  });
  socket.once("close", () => detach?.());
}

async function prepareSocket(path: string) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try {
    const stat = await lstat(path);
    if (!stat.isSocket()) throw new Error(`Refusing to replace non-socket path: ${path}`);
    await unlink(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function requireDataMethod<T extends (...args: never[]) => unknown>(method: T | undefined, name: string): T {
  if (!method) throw new RuntimeDataError(`${name} is unavailable for this runtime`, 501);
  return method;
}

function requireGuest(runtime: WorkspaceRuntime, id: string): GuestRequestCall {
  if (!runtime.guestRequest) throw new RuntimeDataError("Guest control is unavailable for this runtime", 501);
  return (request, timeout) => runtime.guestRequest!(id, request, timeout);
}

function guestJobs(runtime: WorkspaceRuntime, id: string) { return new GuestJobs(requireGuest(runtime, id)); }
