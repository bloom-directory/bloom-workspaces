import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { ProcessRuntime } from "../agent/process-runtime.js";
import { startAgent } from "../agent/server.js";
import { loadConfig, type Config } from "../config.js";
import { openDatabase } from "../db.js";
import { tokenHash } from "../security.js";
import type { AgentClient } from "./agent-client.js";
import { startControlPlane } from "./server.js";
import { WorkspaceError, WorkspaceService } from "./workspaces.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => { while (cleanups.length) await cleanups.pop()?.(); });

describe("authenticated workspace data API", () => {
  it("does not allocate a volume when the node reports persistence unsupported", () => {
    const db = openDatabase(":memory:");
    try {
      const config = loadConfig({ BLOOM_RUNTIME: "firecracker", BLOOM_FIRECRACKER_JAILED: "1" });
      const service = new WorkspaceService(db, config, {} as AgentClient, {
        persistence: false,
        persistenceReason: "Persistent data disks are unsupported with the Firecracker jailer",
        fileTransfer: false,
      });
      let failure: unknown;
      try { service.create("wallet-a", "ip-a", { storage: "persistent" }); }
      catch (error) { failure = error; }
      expect(failure).toBeInstanceOf(WorkspaceError);
      expect(failure).toMatchObject({ status: 501, message: "Persistent data disks are unsupported with the Firecracker jailer" });
      expect(db.prepare("SELECT COUNT(*) AS count FROM persistent_volumes").get()).toMatchObject({ count: 0 });
    } finally { db.close(); }
  });

  it("uploads, lists, downloads, deletes, retains, authorizes, audits, and explicitly destroys", async () => {
    const directory = await mkdtemp(join(tmpdir(), "bloom-data-api-"));
    const config = testConfig(directory);
    const db = openDatabase(config.databasePath);
    const agent = await startAgent(config, new ProcessRuntime(config.dataDir));
    const control = await startControlPlane(config, db);
    cleanups.push(async () => { await control.close(); await agent.close(); await rm(directory, { recursive: true, force: true }); });

    const login = await request(control.app).post("/api/auth/dev").set("origin", config.origin).expect(200);
    const ownerCookie = firstCookie(login.headers["set-cookie"]);
    const ownerCsrf = login.body.csrfToken as string;
    const created = await request(control.app).post("/api/workspaces")
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).send({ storage: "persistent" }).expect(202);
    expect(created.body.workspace.storage).toMatchObject({ mode: "persistent", quotaBytes: 512 * 1024 * 1024, retainedAfterStop: true });
    const firstId = created.body.workspace.id as string;
    await eventually(async () => (await ownerGet(control.app, ownerCookie, "/api/workspaces/current")).body.workspace?.state === "running");

    await request(control.app).put(`/api/workspaces/${firstId}/files?path=src%2Fkeep.txt`)
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).type("application/octet-stream").send(Buffer.from("durable-data")).expect(200);
    await request(control.app).put(`/api/workspaces/${firstId}/files?path=delete.txt`)
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).type("application/octet-stream").send(Buffer.from("temporary")).expect(200);

    await request(control.app).put(`/api/workspaces/${firstId}/files?path=..%2Fescape`)
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).type("application/octet-stream").send(Buffer.from("blocked")).expect(400);
    await request(control.app).put(`/api/workspaces/${firstId}/files?path=oversized`)
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).type("application/octet-stream").send(Buffer.alloc(8 * 1024 * 1024 + 1)).expect(413);
    await request(control.app).put(`/api/workspaces/${firstId}/files?path=no-csrf`)
      .set({ origin: config.origin, cookie: ownerCookie }).type("application/octet-stream").send(Buffer.from("blocked")).expect(403);
    await request(control.app).get(`/api/workspaces/${firstId}/files?path=`).expect(401);

    const activeVolume = db.prepare("SELECT volume_id FROM workspaces WHERE id = ?").get(firstId) as { volume_id: string };
    const outside = join(directory, "outside");
    await mkdir(outside);
    await writeFile(join(outside, "secret"), "host-secret");
    await symlink(outside, join(config.dataDir, "volumes", activeVolume.volume_id, "workspace", "escape"));
    await ownerGet(control.app, ownerCookie, `/api/workspaces/${firstId}/files/content?path=escape%2Fsecret`).then((response) => expect(response.status).toBe(400));

    const listed = await ownerGet(control.app, ownerCookie, `/api/workspaces/${firstId}/files?path=src`);
    expect(listed.status).toBe(200);
    expect(listed.body.files).toMatchObject([{ path: "src/keep.txt", type: "file", size: 12 }]);
    const downloaded = await ownerGet(control.app, ownerCookie, `/api/workspaces/${firstId}/files/content?path=src%2Fkeep.txt`);
    expect(downloaded.status).toBe(200);
    expect(Buffer.from(downloaded.body)).toEqual(Buffer.from("durable-data"));
    await request(control.app).delete(`/api/workspaces/${firstId}/files?path=delete.txt`)
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).expect(200);

    const outsider = createTestSession(db, config, "wallet-b");
    await request(control.app).get(`/api/workspaces/${firstId}/files?path=`).set("cookie", outsider.cookie).expect(404);
    await request(control.app).put(`/api/workspaces/${firstId}/files?path=src%2Fkeep.txt`)
      .set(ownerHeaders(config.origin, outsider.cookie, outsider.csrf)).type("application/octet-stream").send(Buffer.from("stolen")).expect(404);
    await request(control.app).delete("/api/workspace-volume").set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).expect(409);

    await request(control.app).delete("/api/workspaces/current").set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).expect(204);
    await ownerGet(control.app, ownerCookie, `/api/workspaces/${firstId}/files/content?path=src%2Fkeep.txt`).then((response) => expect(response.status).toBe(409));
    await request(control.app).delete("/api/workspace-volume").set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).expect(204);

    // A destroyed volume is never silently reattached. Recreate persistent,
    // write content, stop, then prove it survives a separate VM id.
    const second = await request(control.app).post("/api/workspaces")
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).send({ storage: "persistent" }).expect(202);
    const secondId = second.body.workspace.id as string;
    await eventually(async () => (await ownerGet(control.app, ownerCookie, "/api/workspaces/current")).body.workspace?.state === "running");
    await request(control.app).put(`/api/workspaces/${secondId}/files?path=retained.txt`)
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).type("application/octet-stream").send(Buffer.from("retained")).expect(200);
    await request(control.app).delete("/api/workspaces/current").set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).expect(204);

    const third = await request(control.app).post("/api/workspaces")
      .set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).send({ storage: "persistent" }).expect(202);
    const thirdId = third.body.workspace.id as string;
    expect(thirdId).not.toBe(secondId);
    await eventually(async () => (await ownerGet(control.app, ownerCookie, "/api/workspaces/current")).body.workspace?.state === "running");
    const retained = await ownerGet(control.app, ownerCookie, `/api/workspaces/${thirdId}/files/content?path=retained.txt`);
    expect(retained.status).toBe(200);
    expect(Buffer.from(retained.body)).toEqual(Buffer.from("retained"));

    await request(control.app).delete("/api/workspaces/current").set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).expect(204);
    await request(control.app).delete("/api/workspace-volume").set(ownerHeaders(config.origin, ownerCookie, ownerCsrf)).expect(204);
    const auditKinds = (db.prepare("SELECT kind FROM audit_events").all() as unknown as Array<{ kind: string }>).map((row) => row.kind);
    expect(auditKinds).toEqual(expect.arrayContaining([
      "workspace.volume_created", "workspace.file_uploaded", "workspace.file_listed", "workspace.file_downloaded",
      "workspace.file_deleted", "workspace.file_denied", "workspace.volume_destroyed",
    ]));
    expect(db.prepare("SELECT COUNT(*) AS count FROM persistent_volumes WHERE destroyed_at IS NULL").get()).toMatchObject({ count: 0 });
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

function ownerHeaders(origin: string, cookie: string, csrf: string) {
  return { origin, cookie, "x-csrf-token": csrf };
}

function ownerGet(app: Parameters<typeof request>[0], cookie: string, path: string) {
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
