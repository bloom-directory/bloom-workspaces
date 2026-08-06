import { createServer } from "node:http";
import { basename, resolve } from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { WebSocketServer } from "ws";
import { z } from "zod";
import type { Config } from "../config.js";
import type { BloomDatabase } from "../db.js";
import { audit } from "../db.js";
import { requestLogger } from "../logging.js";
import { clientIp, requestFingerprint, safeEqual, validBrowserOrigin } from "../security.js";
import { AgentClient } from "./agent-client.js";
import { AuthError, issueChallenge, verifyChallenge } from "./auth.js";
import { clearSession, createSession, readSession, type Session } from "./session.js";
import { verifyTurnstile } from "./turnstile.js";
import { WorkspaceError, WorkspaceService } from "./workspaces.js";
import { StructuredJobSpec, isTerminalJobState } from "../jobs/model.js";
import { SshLeaseBody } from "../ssh/api.js";
import { createSshClientArgv } from "../ssh/client-plan.js";
import { createNfsClientPlan } from "../nfs/client-plan.js";
import { TerminalAdmission } from "./terminal-admission.js";

const CreateWorkspace = z.object({
  turnstileToken: z.string().min(1).max(4096).nullable().optional(),
  storage: z.enum(["disposable", "persistent"]).default("disposable"),
}).strict();
const FilePath = z.string().max(4_096);
const MAX_FILE_TRANSFER_BYTES = 8 * 1024 * 1024;
const JobId = z.string().uuid();
const JobStatusQuery = z.object({
  offset: z.coerce.number().int().nonnegative().default(0),
  maxBytes: z.coerce.number().int().min(1).max(256 * 1024).default(256 * 1024),
});
const LeaseId = z.string().uuid();
const ClientConnectionPlan = z.object({
  platform: z.enum(["linux", "macos", "windows", "android", "ios", "unknown"]),
  proxyHelperPath: z.string().min(1).max(4096),
  tokenFilePath: z.string().min(1).max(4096),
  privateKeyPath: z.string().min(1).max(4096),
  certificatePath: z.string().min(1).max(4096),
  knownHostsPath: z.string().min(1).max(4096),
  localPort: z.number().int().min(1).max(65_535).optional(),
  mountPoint: z.string().min(1).max(4096).optional(),
}).strict();
const SshConnectionRequest = SshLeaseBody.extend({ client: ClientConnectionPlan.optional() }).strict();

export async function startControlPlane(config: Config, db: BloomDatabase) {
  const agent = new AgentClient(config);
  const agentHealth = await agent.health();
  if (agentHealth.runtime !== config.runtime) throw new Error(`Runtime mismatch: control expects ${config.runtime}, node agent runs ${agentHealth.runtime}`);
  const workspaces = new WorkspaceService(db, config, agent, agentHealth.dataCapabilities);
  await workspaces.recover();
  const maintenance = () => {
    const now = Date.now();
    const retention = now - 30 * 24 * 60 * 60_000;
    db.prepare("DELETE FROM auth_challenges WHERE expires_at < ?").run(now);
    db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(now);
    db.prepare("DELETE FROM audit_events WHERE occurred_at < ?").run(retention);
    db.prepare("DELETE FROM workspaces WHERE state IN ('stopped','failed') AND stopped_at < ?").run(retention);
  };
  maintenance();
  const app = express();
  app.disable("x-powered-by");
  app.use(requestLogger("control"));
  app.use((_request, response, next) => {
    response.set({
      "content-security-policy": "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss: https://challenges.cloudflare.com https://api.web3modal.org https://cloud.reown.com https://echo.walletconnect.com https://explorer-api.walletconnect.com https://pulse.walletconnect.org https://rpc.walletconnect.org https://verify.walletconnect.com https://verify.walletconnect.org https://secure.walletconnect.org https://secure-mobile.walletconnect.com https://secure-mobile.walletconnect.org; frame-src https://challenges.cloudflare.com https://secure.walletconnect.org https://secure-mobile.walletconnect.com https://secure-mobile.walletconnect.org; img-src 'self' data: https://api.web3modal.org https://explorer-api.walletconnect.com https://walletconnect.org; font-src 'self' https://fonts.reown.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    });
    next();
  });
  app.use("/api", express.json({ limit: "64kb" }));
  app.use("/api", (request, response, next) => {
    response.set("cache-control", "no-store");
    if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method) && !validBrowserOrigin(request.headers.origin, config.origin)) {
      response.status(403).json({ error: "Invalid request origin" }); return;
    }
    next();
  });

  const context = (request: Request) => {
    const ip = clientIp(request, config.trustedProxyHops);
    return { ip, ipHash: requestFingerprint(ip, config.sessionSecret), session: readSession(request, db, config) };
  };
  const requireSession = (request: Request, response: Response, next: NextFunction) => {
    try {
      const value = context(request);
      if (!value.session) { response.status(401).json({ error: "Sign in first" }); return; }
      if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method) && !safeEqual(String(request.headers["x-csrf-token"] ?? ""), value.session.csrfToken)) {
        response.status(403).json({ error: "Invalid CSRF token" }); return;
      }
      response.locals.context = value;
      next();
    } catch (error) { next(error); }
  };

  app.get("/healthz", async (_request, response) => {
    try { await agent.health(); response.json({ ok: true }); } catch { response.status(503).json({ ok: false }); }
  });
  app.get("/metricsz", (_request, response) => {
    const stats = db.prepare(`
      SELECT
        COUNT(*) FILTER (WHERE state = 'running') AS running,
        COUNT(*) FILTER (WHERE state = 'pending') AS pending,
        COUNT(*) FILTER (WHERE state = 'stopped') AS stopped,
        COUNT(*) FILTER (WHERE state = 'failed') AS failed,
        COUNT(*) AS total
      FROM workspaces
    `).get() as { running: number; pending: number; stopped: number; failed: number; total: number };
    const uptimeSeconds = process.uptime();
    const memoryUsage = process.memoryUsage();
    response.json({
      workspaces: stats,
      uptimeSeconds,
      memoryUsage: {
        rssBytes: memoryUsage.rss,
        heapUsedBytes: memoryUsage.heapUsed,
        heapTotalBytes: memoryUsage.heapTotal,
      },
    });
  });
  app.get("/api/session", (request, response, next) => {
    try {
      const { session } = context(request);
      response.json({
        authenticated: Boolean(session),
        ...(session ? { wallet: session.wallet, csrfToken: session.csrfToken, workspace: workspaces.current(session.wallet) } : {}),
        capabilities: agentHealth.capabilities,
        devAuth: config.devAuth,
        ...(config.turnstileSiteKey ? { turnstileSiteKey: config.turnstileSiteKey } : {}),
      });
    } catch (error) { next(error); }
  });
  app.get("/api/auth/challenge", (request, response, next) => {
    try {
      const { ipHash } = context(request);
      const recent = Number((db.prepare("SELECT COUNT(*) AS count FROM auth_challenges WHERE ip_hash = ? AND issued_at > ?").get(ipHash, Date.now() - 60_000) as { count: number }).count);
      if (recent >= 10) { response.status(429).json({ error: "Too many authentication attempts" }); return; }
      const recentGlobal = Number((db.prepare("SELECT COUNT(*) AS count FROM auth_challenges WHERE issued_at > ?").get(Date.now() - 60_000) as { count: number }).count);
      if (recentGlobal >= 1_000) { response.status(503).json({ error: "Authentication is temporarily at capacity" }); return; }
      response.json(issueChallenge(db, config, ipHash));
    } catch (error) { next(error); }
  });
  app.post("/api/auth/verify", async (request, response, next) => {
    try { const { ipHash } = context(request); response.json(await verifyChallenge(request, response, db, config, ipHash)); }
    catch (error) { next(error); }
  });
  app.post("/api/auth/dev", (request, response, next) => {
    try {
      if (!config.devAuth || config.publicMode) { response.status(404).json({ error: "Not found" }); return; }
      const { ipHash } = context(request);
      const wallet = "0x000000000000000000000000000000000000dEaD";
      const csrfToken = createSession(response, db, config, wallet, ipHash);
      audit(db, "auth.login", wallet, undefined, { method: "development" });
      response.json({ wallet, csrfToken });
    } catch (error) { next(error); }
  });
  app.post("/api/auth/logout", requireSession, (request, response) => { clearSession(request, response, db, config); response.status(204).end(); });

  app.post("/api/workspaces", requireSession, async (request, response, next) => {
    try {
      const body = CreateWorkspace.parse(request.body);
      const ctx = response.locals.context as { ip: string; ipHash: string; session: Session };
      if (!await verifyTurnstile(config, body.turnstileToken, ctx.ip)) { response.status(403).json({ error: "Human verification failed" }); return; }
      const workspace = workspaces.create(ctx.session.wallet, ctx.ipHash, { storage: body.storage });
      response.status(202).json({ workspace });
    } catch (error) { next(error); }
  });
  app.get("/api/workspaces/current", requireSession, (_request, response) => {
    const { session } = response.locals.context as { session: Session };
    response.json({ workspace: workspaces.current(session.wallet) });
  });
  app.delete("/api/workspaces/current", requireSession, async (_request, response, next) => {
    try { const { session } = response.locals.context as { session: Session }; await workspaces.stopCurrent(session.wallet); response.status(204).end(); }
    catch (error) { next(error); }
  });
  app.get("/api/workspaces/:id/files", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      const path = FilePath.parse(String(request.query.path ?? ""));
      response.json({ files: await workspaces.listFiles(session.wallet, String(request.params.id ?? ""), path) });
    } catch (error) { next(error); }
  });
  app.get("/api/workspaces/:id/files/content", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      const path = FilePath.min(1).parse(String(request.query.path ?? ""));
      const contents = await workspaces.readFile(session.wallet, String(request.params.id ?? ""), path);
      response.type("application/octet-stream")
        .set({ "content-length": String(contents.byteLength), "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(basename(path))}` })
        .send(contents);
    } catch (error) { next(error); }
  });
  app.put("/api/workspaces/:id/files", requireSession, express.raw({ type: "application/octet-stream", limit: MAX_FILE_TRANSFER_BYTES }), async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      const path = FilePath.min(1).parse(String(request.query.path ?? ""));
      if (!Buffer.isBuffer(request.body)) throw new WorkspaceError("Upload must use application/octet-stream", 400);
      response.json(await workspaces.writeFile(session.wallet, String(request.params.id ?? ""), path, request.body));
    } catch (error) { next(error); }
  });
  app.delete("/api/workspaces/:id/files", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      const path = FilePath.min(1).parse(String(request.query.path ?? ""));
      response.json(await workspaces.deleteFile(session.wallet, String(request.params.id ?? ""), path));
    } catch (error) { next(error); }
  });
  app.delete("/api/workspace-volume", requireSession, async (_request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      await workspaces.destroyPersistentVolume(session.wallet);
      response.status(204).end();
    } catch (error) { next(error); }
  });
  app.post("/api/workspaces/:id/jobs", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      response.status(202).json(await workspaces.startJob(session.wallet, String(request.params.id ?? ""), StructuredJobSpec.parse(request.body)));
    } catch (error) { next(error); }
  });
  app.get("/api/workspaces/:id/jobs/:jobId", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      const query = JobStatusQuery.parse(request.query);
      response.json(await workspaces.jobStatus(session.wallet, String(request.params.id ?? ""), JobId.parse(request.params.jobId), query.offset, query.maxBytes));
    } catch (error) { next(error); }
  });
  app.delete("/api/workspaces/:id/jobs/:jobId", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      response.json(await workspaces.cancelJob(session.wallet, String(request.params.id ?? ""), JobId.parse(request.params.jobId)));
    } catch (error) { next(error); }
  });
  app.get("/api/workspaces/:id/jobs/:jobId/events", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      const workspaceId = String(request.params.id ?? "");
      const jobId = JobId.parse(request.params.jobId);
      let offset = JobStatusQuery.shape.offset.parse(request.query.offset);
      let closed = false;
      request.once("close", () => { closed = true; });
      response.status(200).set({ "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive", "x-accel-buffering": "no" });
      response.flushHeaders();
      while (!closed) {
        const status = await workspaces.jobStatus(session.wallet, workspaceId, jobId, offset, 64 * 1024);
        response.write(`event: status\ndata: ${JSON.stringify(status)}\n\n`);
        offset = status.logs.nextOffset;
        if (isTerminalJobState(status.state)) break;
        await waitFor(500);
      }
      if (!response.writableEnded) response.end();
    } catch (error) {
      if (!response.headersSent) next(error);
      else response.end();
    }
  });
  app.get("/api/workspaces/:id/bloom", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      response.json(await workspaces.bloomStatus(session.wallet, String(request.params.id ?? "")));
    } catch (error) { next(error); }
  });
  app.get("/api/workspaces/:id/ceremony", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      response.json(await workspaces.ceremonyPending(session.wallet, String(request.params.id ?? "")));
    } catch (error) { next(error); }
  });
  app.get("/api/workspaces/:id/connections", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      response.json(await workspaces.connections(session.wallet, String(request.params.id ?? "")));
    } catch (error) { next(error); }
  });
  app.post("/api/workspaces/:id/connections/ssh", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      const id = String(request.params.id ?? "");
      const body = SshConnectionRequest.parse(request.body);
      const grant = await workspaces.issueSsh(session.wallet, id, {
        publicKey: body.publicKey,
        mode: body.mode,
        ...(body.requestedTtlMs === undefined ? {} : { requestedTtlMs: body.requestedTtlMs }),
      });
      const clientInput = body.client ? {
        gatewayOrigin: config.origin,
        workspaceId: id,
        leaseId: grant.leaseId,
        mode: grant.mode,
        proxyHelperPath: body.client.proxyHelperPath,
        tokenFilePath: body.client.tokenFilePath,
        privateKeyPath: body.client.privateKeyPath,
        certificatePath: body.client.certificatePath,
        knownHostsPath: body.client.knownHostsPath,
      } : undefined;
      const clientPlan = !clientInput
        ? undefined
        : grant.mode === "shell"
          ? { sshArgv: createSshClientArgv(clientInput), ceremonyArgv: [...createSshClientArgv(clientInput), "-L", "18734:localhost:18734"] }
          : createNfsClientPlan({
              ...clientInput,
              platform: body.client!.platform,
              localPort: body.client!.localPort ?? 30490,
              mountPoint: body.client!.mountPoint ?? defaultMountPoint(body.client!.platform),
            });
      response.status(201).json({
        ...grant,
        tunnel: {
          transport: "websocket",
          protocol: "bloom-ssh-v1",
          path: `/api/workspaces/${encodeURIComponent(id)}/connections/ssh/tunnel?lease=${encodeURIComponent(grant.leaseId)}&mode=${grant.mode}`,
          proxyHelper: `${config.origin}/downloads/bloom-ssh-proxy.mjs`,
        },
        ...(clientPlan ?? {}),
      });
    } catch (error) { next(error); }
  });
  app.delete("/api/workspaces/:id/connections/ssh/:leaseId", requireSession, async (request, response, next) => {
    try {
      const { session } = response.locals.context as { session: Session };
      await workspaces.revokeSsh(session.wallet, String(request.params.id ?? ""), LeaseId.parse(request.params.leaseId));
      response.status(204).end();
    } catch (error) { next(error); }
  });

  app.get("/downloads/bloom-ssh-proxy.mjs", (_request, response) => {
    response.type("text/javascript").set("content-disposition", "attachment; filename=bloom-ssh-proxy.mjs")
      .sendFile(resolve(process.cwd(), "ops/connections/bloom-ssh-proxy.mjs"));
  });

  const publicDir = resolve(process.cwd(), "dist/public");
  app.use(express.static(publicDir, { index: false, maxAge: config.publicMode ? "1h" : 0 }));
  app.get("/{*path}", (_request, response) => response.sendFile(resolve(publicDir, "index.html")));
  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    if (error instanceof z.ZodError) { response.status(400).json({ error: "Invalid request", issues: error.issues.map((issue) => issue.path.join(".")) }); return; }
    if (error instanceof AuthError) { response.status(401).json({ error: error.message }); return; }
    if (error instanceof WorkspaceError) { response.status(error.status).json({ error: error.message }); return; }
    if (typeof error === "object" && error !== null && "status" in error && error.status === 413) { response.status(413).json({ error: "Request body is too large" }); return; }
    console.error(error);
    response.status(500).json({ error: "Internal server error" });
  });

  const server = createServer(app);
  const browserSockets = new WebSocketServer({ noServer: true, maxPayload: 70 * 1024 });
  const connectionSockets = new WebSocketServer({ noServer: true, maxPayload: 1024 * 1024 });
  const terminalAdmission = new TerminalAdmission(4, Math.max(4, config.maxRunning * 4));
  server.on("upgrade", (request, socket, head) => {
    try {
      const url = new URL(request.url ?? "/", config.origin);
      const sshMatch = url.pathname.match(/^\/api\/workspaces\/([0-9a-f-]+)\/connections\/ssh\/tunnel$/i);
      if (sshMatch?.[1]) {
        const accessToken = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
        const leaseId = LeaseId.parse(url.searchParams.get("lease"));
        const mode = z.enum(["shell", "nfs"]).parse(url.searchParams.get("mode"));
        const protocols = String(request.headers["sec-websocket-protocol"] ?? "").split(",").map((value) => value.trim());
        if (!accessToken || !protocols.includes("bloom-ssh-v1")) throw new Error("Unauthorized");
        connectionSockets.handleUpgrade(request, socket, head, (client) => {
          bridgeBinaryWebSockets(client, agent.sshTunnel(sshMatch[1]!, leaseId, mode, accessToken));
        });
        return;
      }
      if (!validBrowserOrigin(request.headers.origin, config.origin)) throw new Error("Invalid origin");
      const match = url.pathname.match(/^\/api\/workspaces\/([0-9a-f-]+)\/terminal$/i);
      if (!match?.[1]) throw new Error("Not found");
      const session = readSession(request as Request, db, config);
      if (!session || !workspaces.ownsRunning(session.wallet, match[1])) throw new Error("Unauthorized");
      const workspaceId = match[1];
      const releaseTerminal = terminalAdmission.acquire(workspaceId);
      if (!releaseTerminal) { rejectHttpUpgrade(socket, "503 Service Unavailable"); return; }
      try { browserSockets.handleUpgrade(request, socket, head, (browser) => {
        browser.once("close", releaseTerminal);
        const upstream = agent.terminal(workspaceId);
        const pending: Array<{ data: Parameters<typeof upstream.send>[0]; binary: boolean }> = [];
        upstream.once("open", () => {
          for (const message of pending.splice(0)) upstream.send(message.data, { binary: message.binary });
        });
        upstream.on("message", (data, binary) => {
          if (browser.readyState === browser.OPEN && browser.bufferedAmount < 1024 * 1024) browser.send(data, { binary });
        });
        browser.on("message", (data, binary) => {
          if (upstream.readyState === upstream.CONNECTING) {
            if (pending.length >= 32) { browser.close(1008, "Too much input before terminal was ready"); return; }
            pending.push({ data, binary });
          } else if (upstream.readyState === upstream.OPEN && upstream.bufferedAmount < 1024 * 1024) upstream.send(data, { binary });
        });
        const closeBoth = () => { browser.close(); upstream.close(); };
        browser.once("close", () => upstream.close());
        upstream.once("close", () => browser.close());
        browser.once("error", closeBoth); upstream.once("error", closeBoth);
      }); } catch (error) { releaseTerminal(); throw error; }
    } catch { rejectHttpUpgrade(socket, "401 Unauthorized"); }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  const reconciler = setInterval(() => void workspaces.reconcile().catch((error) => console.error("Workspace reconciliation failed", error)), 2_000);
  reconciler.unref();
  const janitor = setInterval(maintenance, 60 * 60_000);
  janitor.unref();
  return {
    app,
    async close() {
      clearInterval(reconciler);
      clearInterval(janitor);
      browserSockets.clients.forEach((socket) => socket.close(1012, "server shutting down"));
      connectionSockets.clients.forEach((socket) => socket.close(1012, "server shutting down"));
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await workspaces.waitForReconciliation().catch((error) => console.error("Workspace reconciliation failed during shutdown", error));
      db.close();
    },
  };
}

function bridgeBinaryWebSockets(client: import("ws").WebSocket, upstream: import("ws").WebSocket) {
  const pending: Buffer[] = [];
  let pendingBytes = 0;
  upstream.once("open", () => {
    for (const message of pending.splice(0)) upstream.send(message, { binary: true });
    pendingBytes = 0;
  });
  client.on("message", (data, binary) => {
    if (!binary) { client.close(1003, "SSH tunnel accepts binary frames only"); return; }
    const message = Buffer.from(data as ArrayBuffer);
    if (upstream.readyState === upstream.CONNECTING) {
      pendingBytes += message.byteLength;
      if (pending.length >= 32 || pendingBytes > 1024 * 1024) { client.close(1008, "Too much SSH input before the tunnel was ready"); return; }
      pending.push(message);
    } else if (upstream.readyState === upstream.OPEN) {
      if (upstream.bufferedAmount >= 1024 * 1024) { client.close(1008, "SSH tunnel backpressure limit reached"); return; }
      upstream.send(message, { binary: true });
    }
  });
  upstream.on("message", (data, binary) => {
    if (!binary) { upstream.close(1003, "SSH tunnel requires binary frames"); return; }
    if (client.readyState === client.OPEN) {
      if (client.bufferedAmount >= 1024 * 1024) { upstream.close(1008, "SSH tunnel backpressure limit reached"); return; }
      client.send(data, { binary: true });
    }
  });
  const closeBoth = () => { client.close(); upstream.close(); };
  client.once("close", () => upstream.close());
  upstream.once("close", () => client.close());
  client.once("error", closeBoth);
  upstream.once("error", closeBoth);
}

function defaultMountPoint(platform: "linux" | "macos" | "windows" | "android" | "ios" | "unknown") {
  return platform === "windows" ? "Z:" : "/mnt/bloom-workspace";
}

function waitFor(milliseconds: number) { return new Promise<void>((resolve) => setTimeout(resolve, milliseconds)); }

function rejectHttpUpgrade(socket: import("node:stream").Duplex, status: string) {
  if (!socket.destroyed) socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}
