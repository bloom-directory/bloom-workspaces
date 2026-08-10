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
  const directory = await mkdtemp(join(tmpdir(), "bloom-ceremony-relay-"));
  const config = testConfig(directory);
  const db = openDatabase(config.databasePath);
  const agent = await startAgent(config, new ProcessRuntime(config.dataDir, [], true));
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

function validAssertion() {
  return { assertion: {
    credentialId: randomBytes(16).toString("base64"),
    authenticatorData: randomBytes(37).toString("base64"),
    clientDataJSON: Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: "x", origin: "http://127.0.0.1:8787" })).toString("base64"),
    signature: randomBytes(64).toString("base64"),
  } };
}

describe("Ceremony relay (process runtime, mock guest)", () => {
  it("surfaces a pending request with a relay challenge", async () => {
    const { control, config, cookie, csrf, workspaceId } = await setup();
    const response = await request(control.app).get(`/api/workspaces/${workspaceId}/ceremony`).set(headers(config.origin, cookie, csrf));
    expect(response.status).toBe(200);
    expect(response.body.requests).toHaveLength(1);
    const pending = response.body.requests[0];
    expect(pending.id).toBe(`dev_mock_${workspaceId}`);
    expect(typeof pending.challenge).toBe("string");
    expect(pending.challenge.length).toBeGreaterThan(0);
  });

  it("approves a pending request via the relay and resolves it", async () => {
    const { control, config, cookie, csrf, workspaceId } = await setup();
    const txId = `dev_mock_${workspaceId}`;
    const approve = await request(control.app).post(`/api/workspaces/${workspaceId}/ceremony/${txId}/approve`)
      .set(headers(config.origin, cookie, csrf)).send(validAssertion());
    expect(approve.status).toBe(200);
    expect(approve.body.approved).toBe(true);
    const after = await request(control.app).get(`/api/workspaces/${workspaceId}/ceremony`).set(headers(config.origin, cookie, csrf));
    expect(after.body.requests).toHaveLength(0);
  });

  it("rejects approval without authentication", async () => {
    const { control, config, workspaceId } = await setup();
    const response = await request(control.app).post(`/api/workspaces/${workspaceId}/ceremony/tx_unknown/approve`)
      .set("origin", config.origin).send(validAssertion());
    expect(response.status).toBe(401);
  });

  it("rejects approval from a wallet that does not own the workspace", async () => {
    const { control, config, db, workspaceId } = await setup();
    const outsider = createTestSession(db, config, "wallet-b");
    const txId = `dev_mock_${workspaceId}`;
    const response = await request(control.app).post(`/api/workspaces/${workspaceId}/ceremony/${txId}/approve`)
      .set({ origin: config.origin, cookie: outsider.cookie, "x-csrf-token": outsider.csrf }).send(validAssertion());
    expect(response.status).toBe(404);
  });

  it("returns 404 for an unknown ceremony request", async () => {
    const { control, config, cookie, csrf, workspaceId } = await setup();
    const response = await request(control.app).post(`/api/workspaces/${workspaceId}/ceremony/tx_missing/approve`)
      .set(headers(config.origin, cookie, csrf)).send(validAssertion());
    expect(response.status).toBe(404);
  });

  it("rejects a malformed assertion body", async () => {
    const { control, config, cookie, csrf, workspaceId } = await setup();
    const txId = `dev_mock_${workspaceId}`;
    const response = await request(control.app).post(`/api/workspaces/${workspaceId}/ceremony/${txId}/approve`)
      .set(headers(config.origin, cookie, csrf)).send({ assertion: { credentialId: "not-base64!!!" } });
    expect(response.status).toBe(400);
  });
});

describe("Ceremony relay: public mode forbids the mock", () => {
  it("rejects BLOOM_DEV_MOCK_CEREMONY in public mode", () => {
    expect(() => loadConfig({
      BLOOM_ORIGIN: "https://workspaces.example.com",
      BLOOM_PUBLIC_MODE: "1",
      BLOOM_DEV_AUTH: "0",
      BLOOM_DEV_MOCK_CEREMONY: "1",
      BLOOM_RUNTIME: "qemu",
      BLOOM_TURNSTILE_SITE_KEY: "x",
      BLOOM_TURNSTILE_SECRET: "x",
      BLOOM_SESSION_SECRET: randomBytes(48).toString("hex"),
      BLOOM_AGENT_TOKEN: randomBytes(48).toString("hex"),
    })).toThrow(/BLOOM_DEV_MOCK_CEREMONY is forbidden/);
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
      BLOOM_DEV_MOCK_CEREMONY: "1",
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
