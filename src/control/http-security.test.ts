import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { ProcessRuntime } from "../agent/process-runtime.js";
import { startAgent } from "../agent/server.js";
import { loadConfig, type Config } from "../config.js";
import { openDatabase } from "../db.js";
import { tokenHash } from "../security.js";
import { startControlPlane } from "./server.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()?.(); });

async function setup() {
  const directory = await mkdtemp(join(tmpdir(), "bloom-http-sec-"));
  const config = testConfig(directory);
  const db = openDatabase(config.databasePath);
  const agent = await startAgent(config, new ProcessRuntime(config.dataDir));
  const control = await startControlPlane(config, db);
  cleanups.push(async () => { await control.close(); await agent.close(); await rm(directory, { recursive: true, force: true }); });

  const login = await request(control.app).post("/api/auth/dev").set("origin", config.origin).expect(200);
  const cookie = firstCookie(login.headers["set-cookie"]);
  const csrf = login.body.csrfToken as string;

  const created = await request(control.app).post("/api/workspaces")
    .set(headers(config.origin, cookie, csrf)).send({ storage: "disposable" }).expect(202);
  const workspaceId = created.body.workspace.id as string;
  await eventually(async () => (await get(control.app, cookie, "/api/workspaces/current")).body.workspace?.state === "running");

  return { control, config, db, cookie, csrf, workspaceId };
}

describe("HTTP security: outbox path traversal rejection", () => {
  it("rejects path traversal payloads in outbox confirm", async () => {
    const { control, config, cookie, csrf, workspaceId } = await setup();

    for (const payload of ["../../..", "..%2f..%2f", "foo/bar", "..", "a\\b"]) {
      const response = await request(control.app)
        .post(`/api/workspaces/${workspaceId}/outbox/confirm`)
        .set(headers(config.origin, cookie, csrf))
        .send({ id: payload, chain: "8453", wallet: "default", confirmText: "ok" });
      expect(response.status, `confirm id="${payload}"`).toBeGreaterThanOrEqual(400);
    }
  });

  it("rejects path traversal payloads in outbox cancel", async () => {
    const { control, config, cookie, csrf, workspaceId } = await setup();

    for (const payload of ["../../..", "..%2f..%2f", "foo/bar", "..", "a\\b"]) {
      const response = await request(control.app)
        .post(`/api/workspaces/${workspaceId}/outbox/cancel`)
        .set(headers(config.origin, cookie, csrf))
        .send({ id: payload, chain: "8453", wallet: "default" });
      expect(response.status, `cancel id="${payload}"`).toBeGreaterThanOrEqual(400);
    }
  });

  it("rejects path traversal in chain and wallet fields", async () => {
    const { control, config, cookie, csrf, workspaceId } = await setup();

    // chain traversal
    const chainResponse = await request(control.app)
      .post(`/api/workspaces/${workspaceId}/outbox/confirm`)
      .set(headers(config.origin, cookie, csrf))
      .send({ id: "tx-1", chain: "../../etc", wallet: "default", confirmText: "ok" });
    expect(chainResponse.status).toBeGreaterThanOrEqual(400);

    // wallet traversal
    const walletResponse = await request(control.app)
      .post(`/api/workspaces/${workspaceId}/outbox/cancel`)
      .set(headers(config.origin, cookie, csrf))
      .send({ id: "tx-1", chain: "8453", wallet: "../../secret" });
    expect(walletResponse.status).toBeGreaterThanOrEqual(400);
  });

  it("rejects requests without authentication", async () => {
    const { control, workspaceId } = await setup();

    const response = await request(control.app)
      .get(`/api/workspaces/${workspaceId}/outbox/pending`);
    expect(response.status).toBe(401);
  });

  it("rejects requests from other wallets (workspace not owned)", async () => {
    const { control, config, db, workspaceId } = await setup();
    const outsider = createTestSession(db, config, "wallet-b");

    const response = await request(control.app)
      .get(`/api/workspaces/${workspaceId}/outbox/pending`)
      .set("cookie", outsider.cookie);
    expect(response.status).toBe(404);
  });
});

describe("HTTP: metrics endpoint", () => {
  it("returns workspace counts and process stats", async () => {
    const { control } = await setup();

    const response = await request(control.app).get("/metricsz");
    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("workspaces");
    expect(response.body.workspaces).toHaveProperty("running");
    expect(response.body.workspaces).toHaveProperty("total");
    expect(response.body.workspaces.total).toBeGreaterThanOrEqual(1);
    expect(response.body).toHaveProperty("uptimeSeconds");
    expect(response.body).toHaveProperty("memoryUsage");
    expect(response.body.memoryUsage).toHaveProperty("rssBytes");
  });
});

describe("HTTP: healthz endpoint", () => {
  it("returns ok when agent is healthy", async () => {
    const { control } = await setup();
    const response = await request(control.app).get("/healthz");
    expect(response.status).toBe(200);
    expect(response.body.ok).toBe(true);
  });
});

function testConfig(directory: string): Config {
  return {
    ...loadConfig({
      BLOOM_ORIGIN: "http://127.0.0.1:8787",
      BLOOM_DATABASE: join(directory, "control.sqlite"),
      BLOOM_AGENT_SOCKET: join(directory, "agent.sock"),
      BLOOM_DATA_DIR: join(directory, "workspaces"),
      BLOOM_AGENT_TOKEN: randomBytes(32).toString("hex"),
      BLOOM_SESSION_SECRET: randomBytes(32).toString("hex"),
      BLOOM_RUNTIME: "process",
      BLOOM_DEV_AUTH: "1",
      BLOOM_DAILY_PER_WALLET: "20",
      BLOOM_DAILY_PER_IP: "20",
    }),
    port: 0,
  };
}

function headers(origin: string, cookie: string, csrf: string) {
  return { origin, cookie, "x-csrf-token": csrf };
}

function get(app: Parameters<typeof request>[0], cookie: string, path: string) {
  return request(app).get(path).set("cookie", cookie);
}

function firstCookie(value: string | string[] | undefined) {
  const cookie = Array.isArray(value) ? value[0] : value;
  if (!cookie) throw new Error("Session cookie was not returned");
  return cookie.split(";", 1)[0]!;
}

function createTestSession(db: ReturnType<typeof openDatabase>, config: Config, wallet: string) {
  const token = randomBytes(32).toString("base64url");
  const csrf = randomBytes(24).toString("base64url");
  const now = Date.now();
  db.prepare("INSERT INTO sessions (token_hash, wallet, csrf_token, ip_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(tokenHash(token, config.sessionSecret), wallet, csrf, "test-ip", now, now + 60_000);
  return { cookie: `bloom_session=${token}`, csrf };
}

async function eventually(predicate: () => Promise<boolean>) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("condition was not reached");
}
