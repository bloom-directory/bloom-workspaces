import { createServer, type IncomingMessage } from "node:http";
import { lstat, mkdir, unlink } from "node:fs/promises";
import { dirname } from "node:path";
import express from "express";
import { WebSocketServer, type WebSocket } from "ws";
import { z } from "zod";
import type { Config } from "../config.js";
import { safeEqual } from "../security.js";
import type { WorkspaceRuntime } from "./runtime.js";

const CreateBody = z.object({ id: z.string().uuid(), leaseExpiresAt: z.number().int().positive() });
const TerminalInput = z.discriminatedUnion("type", [
  z.object({ type: z.literal("input"), data: z.string().max(65_536) }),
  z.object({ type: z.literal("resize"), cols: z.number().int(), rows: z.number().int() }),
]);

export async function startAgent(config: Config, runtime: WorkspaceRuntime) {
  await prepareSocket(config.agentSocket);
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "16kb" }));
  app.use((request, response, next) => {
    const token = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
    if (!safeEqual(token, config.agentToken)) { response.status(401).json({ error: "Unauthorized" }); return; }
    next();
  });

  app.get("/v1/health", (_request, response) => response.json({ ok: true, runtime: config.runtime }));
  app.post("/v1/workspaces", async (request, response, next) => {
    try {
      const spec = CreateBody.parse(request.body);
      if (spec.leaseExpiresAt > Date.now() + config.maxLeaseMs + 60_000) throw new Error("Lease exceeds node maximum");
      await runtime.create(spec);
      response.status(201).json({ state: runtime.status(spec.id) });
    } catch (error) { next(error); }
  });
  app.get("/v1/workspaces/:id", (request, response) => response.json({ state: runtime.status(request.params.id ?? "") }));
  app.delete("/v1/workspaces/:id", async (request, response, next) => {
    try { await runtime.stop(request.params.id ?? "", "destroyed by owner"); response.status(204).end(); } catch (error) { next(error); }
  });
  app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
    const message = error instanceof Error ? error.message : "Node agent error";
    response.status(error instanceof z.ZodError ? 400 : 500).json({ error: message });
  });

  const server = createServer(app);
  const sockets = new WebSocketServer({ noServer: true, maxPayload: 70 * 1024 });
  server.on("upgrade", (request, socket, head) => {
    const token = request.headers.authorization?.replace(/^Bearer /, "") ?? "";
    const match = new URL(request.url ?? "/", "http://agent.local").pathname.match(/^\/v1\/workspaces\/([0-9a-f-]+)\/terminal$/i);
    if (!safeEqual(token, config.agentToken) || !match?.[1]) { socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n"); socket.destroy(); return; }
    const id = match[1];
    sockets.handleUpgrade(request, socket, head, (websocket) => attachTerminal(websocket, id, runtime));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.agentSocket, () => { server.off("error", reject); resolve(); });
  });
  await new Promise<void>((resolve, reject) => {
    import("node:fs").then(({ chmod }) => chmod(config.agentSocket, 0o660, (error) => error ? reject(error) : resolve()), reject);
  });
  const sweeper = setInterval(() => void runtime.sweep(), 1_000);
  sweeper.unref();

  return {
    async close() {
      clearInterval(sweeper);
      sockets.clients.forEach((socket) => socket.close(1012, "agent shutting down"));
      await runtime.close();
      await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      await unlink(config.agentSocket).catch(() => undefined);
    },
  };
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
