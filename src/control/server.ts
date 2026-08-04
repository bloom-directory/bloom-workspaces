import { createServer } from "node:http";
import { resolve } from "node:path";
import express, { type NextFunction, type Request, type Response } from "express";
import { WebSocketServer } from "ws";
import { z } from "zod";
import type { Config } from "../config.js";
import type { BloomDatabase } from "../db.js";
import { audit } from "../db.js";
import { clientIp, requestFingerprint, safeEqual, validBrowserOrigin } from "../security.js";
import { AgentClient } from "./agent-client.js";
import { AuthError, issueChallenge, verifyChallenge } from "./auth.js";
import { clearSession, createSession, readSession, type Session } from "./session.js";
import { verifyTurnstile } from "./turnstile.js";
import { WorkspaceError, WorkspaceService } from "./workspaces.js";

const CreateWorkspace = z.object({ turnstileToken: z.string().min(1).max(4096).nullable().optional() });

export async function startControlPlane(config: Config, db: BloomDatabase) {
  const agent = new AgentClient(config);
  const agentHealth = await agent.health();
  if (agentHealth.runtime !== config.runtime) throw new Error(`Runtime mismatch: control expects ${config.runtime}, node agent runs ${agentHealth.runtime}`);
  const workspaces = new WorkspaceService(db, config, agent);
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
  app.use((_request, response, next) => {
    response.set({
      "content-security-policy": "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss: https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
      "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    });
    next();
  });
  app.use("/api", express.json({ limit: "16kb" }));
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
  app.get("/api/session", (request, response, next) => {
    try {
      const { session } = context(request);
      response.json({
        authenticated: Boolean(session),
        ...(session ? { wallet: session.wallet, csrfToken: session.csrfToken, workspace: workspaces.current(session.wallet) } : {}),
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
      const workspace = workspaces.create(ctx.session.wallet, ctx.ipHash);
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

  const publicDir = resolve(process.cwd(), "dist/public");
  app.use(express.static(publicDir, { index: false, maxAge: config.publicMode ? "1h" : 0 }));
  app.get("/{*path}", (_request, response) => response.sendFile(resolve(publicDir, "index.html")));
  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    if (error instanceof z.ZodError) { response.status(400).json({ error: "Invalid request", issues: error.issues.map((issue) => issue.path.join(".")) }); return; }
    if (error instanceof AuthError) { response.status(401).json({ error: error.message }); return; }
    if (error instanceof WorkspaceError) { response.status(error.status).json({ error: error.message }); return; }
    console.error(error);
    response.status(500).json({ error: "Internal server error" });
  });

  const server = createServer(app);
  const browserSockets = new WebSocketServer({ noServer: true, maxPayload: 70 * 1024 });
  server.on("upgrade", (request, socket, head) => {
    try {
      if (!validBrowserOrigin(request.headers.origin, config.origin)) throw new Error("Invalid origin");
      const match = new URL(request.url ?? "/", config.origin).pathname.match(/^\/api\/workspaces\/([0-9a-f-]+)\/terminal$/i);
      if (!match?.[1]) throw new Error("Not found");
      const session = readSession(request as Request, db, config);
      if (!session || !workspaces.ownsRunning(session.wallet, match[1])) throw new Error("Unauthorized");
      browserSockets.handleUpgrade(request, socket, head, (browser) => {
        const upstream = agent.terminal(match[1]!);
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
      });
    } catch { socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n"); socket.destroy(); }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.port, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  const reconciler = setInterval(() => void workspaces.reconcile(), 2_000);
  reconciler.unref();
  const janitor = setInterval(maintenance, 60 * 60_000);
  janitor.unref();
  return {
    app,
    async close() {
      clearInterval(reconciler);
      clearInterval(janitor);
      browserSockets.clients.forEach((socket) => socket.close(1012, "server shutting down"));
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      db.close();
    },
  };
}
