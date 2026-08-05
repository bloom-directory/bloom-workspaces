import { randomUUID } from "node:crypto";
import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { GuestResponse } from "../guest-protocol.js";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const servicePath = join(repoRoot, "ops/guest-control/bloom-guest-control.py");
const helperPath = join(repoRoot, "ops/guest-control/bloom-workspace");
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => { while (cleanups.length) await cleanups.pop()?.(); });

describe("guest job, file, and Bloom control service", () => {
  it("serves bounded files and only public watch-only Bloom metadata", async () => {
    const harness = await GuestHarness.create();

    const hello = await harness.request({ operation: "hello" });
    expect(hello.ok && hello.result).toMatchObject({ protocolVersion: 1, limits: { activeJobs: 2, jobLogBytes: 1024 * 1024 } });

    const contents = Buffer.from("bounded workspace file");
    expect(await harness.request({ operation: "fs.write", path: "src/example.txt", offset: 0, truncate: true, data: contents.toString("base64") }))
      .toMatchObject({ ok: true, result: { size: contents.byteLength, nextOffset: contents.byteLength, usedBytes: contents.byteLength, quotaBytes: 16 * 1024 * 1024 } });
    const read = await harness.request({ operation: "fs.read", path: "src/example.txt", offset: 0, maxBytes: 256 * 1024 });
    expect(read.ok && Buffer.from((read.result as { data: string }).data, "base64")).toEqual(contents);
    expect(await harness.request({ operation: "fs.list", path: "src" })).toMatchObject({ ok: true, result: { files: [{ path: "src/example.txt", type: "file" }] } });
    const rootList = await harness.request({ operation: "fs.list", path: "." });
    expect(rootList.ok).toBe(true);
    expect(rootList.ok && (rootList.result as { files: unknown[] }).files).toEqual(expect.arrayContaining([expect.objectContaining({ path: "src", type: "directory" })]));
    expect(await harness.request({ operation: "fs.read", path: ".", offset: 0, maxBytes: 1 })).toMatchObject({ ok: false, error: { code: "invalid_request" } });
    expect(await harness.request({ operation: "fs.write", path: ".", offset: 0, truncate: true, data: "" })).toMatchObject({ ok: false, error: { code: "invalid_request" } });
    expect(await harness.request({ operation: "fs.delete", path: ".", recursive: false })).toMatchObject({ ok: false, error: { code: "invalid_request" } });
    expect(await harness.request({ operation: "fs.delete", path: "src/example.txt", recursive: false })).toMatchObject({
      ok: true,
      result: { deleted: true, usedBytes: 0, quotaBytes: 16 * 1024 * 1024 },
    });
    expect(await harness.request({ operation: "fs.write", path: "src/example.txt", offset: 0, truncate: true, data: contents.toString("base64") }))
      .toMatchObject({ ok: true, result: { usedBytes: contents.byteLength, quotaBytes: 16 * 1024 * 1024 } });

    const outside = await mkdtemp(join(tmpdir(), "bloom-guest-outside-"));
    cleanups.push(async () => rm(outside, { recursive: true, force: true }));
    await writeFile(join(outside, "secret"), "host-secret");
    await symlink(outside, join(harness.root, "src/escape"));
    expect(await harness.request({ operation: "fs.read", path: "src/escape/secret", offset: 0, maxBytes: 100 }))
      .toMatchObject({ ok: false, error: { code: "permission_denied" } });
    expect(await readFile(join(outside, "secret"), "utf8")).toBe("host-secret");

    await harness.provisionWatchWallet("0x1111111111111111111111111111111111111111");
    const bloom = await harness.request({ operation: "bloom.status" });
    expect(bloom).toMatchObject({
      ok: true,
      result: {
        identity: { kind: "watch", address: "0x1111111111111111111111111111111111111111" },
        mount: { path: "/bloom" },
        capabilities: { files: true, jobs: true, walletSigning: true, transactions: true },
      },
    });

    await writeFile(join(harness.root, ".bloom/keystore/workspace-login/private-key"), "must-not-leak");
    const contaminated = await harness.request({ operation: "bloom.status" });
    expect(contaminated).toMatchObject({ ok: true, result: { available: false, identity: null } });
    expect(JSON.stringify(bloom)).not.toContain("must-not-leak");
    expect(JSON.stringify(contaminated)).not.toContain("must-not-leak");
  });

  it("runs literal structured argv with an allowlisted environment as uid 1000 and no-new-privileges", async () => {
    const harness = await GuestHarness.create();
    const script = [
      "import json, os, pathlib, sys",
      "status = pathlib.Path('/proc/self/status').read_text()",
      "nnp = next(line.split()[1] for line in status.splitlines() if line.startswith('NoNewPrivs:'))",
      "print(json.dumps({'uid': os.getuid(), 'gid': os.getgid(), 'nnp': nnp, 'value': os.environ['APP_VALUE'], 'arg': sys.argv[1], 'cwd': os.getcwd(), 'has_loader': 'LD_PRELOAD' in os.environ}), flush=True)",
    ].join("\n");
    const jobId = randomUUID();
    const started = await harness.request({
      operation: "job.start",
      jobId,
      argv: ["python3", "-c", script, "; echo this-would-be-shell-injection"],
      cwd: ".",
      environment: { APP_VALUE: "hello" },
      timeoutMs: 10_000,
    });
    expect(started).toMatchObject({ ok: true, result: { jobId, state: "running" } });

    const completed = await harness.waitForTerminal(jobId);
    expect(completed).toMatchObject({ state: "succeeded", exitCode: 0 });
    const output = JSON.parse(Buffer.from(completed.logs.data, "base64").toString("utf8"));
    expect(output).toMatchObject({ uid: 1000, gid: 1000, nnp: "1", value: "hello", arg: "; echo this-would-be-shell-injection", has_loader: false });
    expect(output.cwd).toBe(harness.root);

    expect(await harness.request({
      operation: "job.start",
      jobId: randomUUID(),
      argv: ["true"],
      cwd: "src",
      environment: { LD_PRELOAD: "/workspace/evil.so" },
      timeoutMs: 1000,
    })).toMatchObject({ ok: false, error: { code: "permission_denied" } });
  });

  it("enforces active-job limits, timeouts, process-group cancellation, and bounded absolute-cursor logs", async () => {
    const harness = await GuestHarness.create();
    const cancellableId = randomUUID();
    const timeoutId = randomUUID();
    const childScript = "import signal,subprocess,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); p=subprocess.Popen(['sleep','30']); print(p.pid,flush=True); time.sleep(30)";
    expect(await harness.request({ operation: "job.start", jobId: cancellableId, argv: ["python3", "-c", childScript], cwd: "src", environment: {}, timeoutMs: 30_000 }))
      .toMatchObject({ ok: true, result: { state: "running" } });
    expect(await harness.request({ operation: "job.start", jobId: timeoutId, argv: ["sleep", "30"], cwd: "src", environment: {}, timeoutMs: 1000 }))
      .toMatchObject({ ok: true, result: { state: "running" } });
    expect(await harness.request({ operation: "job.start", jobId: randomUUID(), argv: ["true"], cwd: "src", environment: {}, timeoutMs: 1000 }))
      .toMatchObject({ ok: false, error: { code: "limit_exceeded" } });

    const withChild = await harness.waitForLog(cancellableId);
    const childOutput = Buffer.from(withChild.logs.data, "base64").toString("utf8").trim();
    expect(childOutput).toMatch(/^\d+$/);
    const childPid = Number(childOutput);
    expect(childPid).toBeGreaterThan(1);
    expect(await harness.request({ operation: "job.cancel", jobId: cancellableId })).toMatchObject({ ok: true });
    expect(await harness.waitForTerminal(cancellableId)).toMatchObject({ state: "cancelled" });
    await eventually(() => !processExists(childPid));
    expect(await harness.waitForTerminal(timeoutId)).toMatchObject({ state: "timed_out" });

    const largeId = randomUUID();
    expect(await harness.request({
      operation: "job.start",
      jobId: largeId,
      argv: ["python3", "-c", "import sys; sys.stdout.write('x' * (1200 * 1024)); sys.stdout.flush()"],
      cwd: "src",
      environment: {},
      timeoutMs: 10_000,
    })).toMatchObject({ ok: true });
    const large = await harness.waitForTerminal(largeId);
    expect(large.state).toBe("succeeded");
    expect(large.logs).toMatchObject({ truncatedBefore: true, endOffset: 1200 * 1024 });
    expect(large.logs.offset).toBe(1200 * 1024 - 1024 * 1024);
    expect(Buffer.from(large.logs.data, "base64").byteLength).toBe(256 * 1024);
    expect(await harness.request({ operation: "job.status", jobId: largeId, logOffset: large.logs.endOffset + 1, maxBytes: 1 }))
      .toMatchObject({ ok: false, error: { code: "invalid_request" } });
  });

  it("serves the guest-local helper over a private Unix socket and cleans up on termination", async () => {
    const root = await mkdtemp(join(tmpdir(), "bloom-guest-helper-"));
    const socketPath = join(root, "run/guest-control.sock");
    await mkdir(join(root, "src"));
    const child = spawn("python3", [
      servicePath,
      "--workspace", root,
      "--workspace-quota-bytes", String(1024 * 1024),
      "--job-uid", String(process.getuid?.() ?? 1000),
      "--job-gid", String(process.getgid?.() ?? 1000),
      "--unix-socket", socketPath,
    ], { stdio: "pipe" });
    cleanups.push(async () => {
      if (child.exitCode === null) child.kill("SIGKILL");
      await rm(root, { recursive: true, force: true });
    });
    await eventually(async () => {
      try { return (await stat(socketPath)).isSocket(); }
      catch { return false; }
    });
    const helper = spawnSync(helperPath, ["hello"], {
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", BLOOM_GUEST_CONTROL_SOCKET: socketPath },
    });
    expect(helper.status, helper.stderr).toBe(0);
    expect(JSON.parse(helper.stdout)).toMatchObject({ protocolVersion: 1, limits: { activeJobs: 2 } });
    child.kill("SIGTERM");
    await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    await expect(stat(socketPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("shares one job engine across stdio and the guest-local Unix socket", async () => {
    const harness = await GuestHarness.create(true);
    const jobId = randomUUID();
    expect(await harness.request({ operation: "job.start", jobId, argv: ["sleep", "30"], cwd: ".", environment: {}, timeoutMs: 30_000 }))
      .toMatchObject({ ok: true, result: { jobId, state: "running" } });

    const viaSocket = harness.runHelper(["jobs", "status", jobId]);
    expect(viaSocket.status, viaSocket.stderr).toBe(0);
    expect(JSON.parse(viaSocket.stdout)).toMatchObject({ jobId, state: "running" });
    const cancelled = harness.runHelper(["jobs", "cancel", jobId]);
    expect(cancelled.status, cancelled.stderr).toBe(0);
    expect(await harness.waitForTerminal(jobId)).toMatchObject({ state: "cancelled" });
  });
});

type RequestFields = { operation: string } & Record<string, unknown>;
type SuccessResponse = Extract<ReturnType<typeof GuestResponse.parse>, { ok: true }>;

class GuestHarness {
  private sequence = 0;
  private readonly pending: Array<(value: ReturnType<typeof GuestResponse.parse>) => void> = [];
  private stderr = "";

  private constructor(readonly root: string, private readonly child: ChildProcessWithoutNullStreams, private readonly socketPath?: string) {
    const lines = createInterface({ input: child.stdout });
    lines.on("line", (line) => this.pending.shift()?.(GuestResponse.parse(JSON.parse(line))));
    child.stderr.on("data", (chunk: Buffer) => { this.stderr = `${this.stderr}${chunk.toString("utf8")}`.slice(-16_384); });
  }

  static async create(withUnixSocket = false) {
    const root = await mkdtemp(join(tmpdir(), "bloom-guest-control-"));
    await mkdir(join(root, "src"), { recursive: true });
    const socketPath = withUnixSocket ? join(root, "guest-control.sock") : undefined;
    const argumentsList = [
      servicePath,
      "--stdio",
      "--workspace", root,
      "--workspace-quota-bytes", String(16 * 1024 * 1024),
      "--job-uid", String(process.getuid?.() ?? 1000),
      "--job-gid", String(process.getgid?.() ?? 1000),
    ];
    if (socketPath) argumentsList.push("--unix-socket", socketPath);
    const child = spawn("python3", argumentsList, { stdio: "pipe" });
    const harness = new GuestHarness(root, child, socketPath);
    cleanups.push(async () => harness.close());
    if (socketPath) {
      await eventually(async () => {
        try { return (await stat(socketPath)).isSocket(); }
        catch { return false; }
      });
    }
    return harness;
  }

  runHelper(args: string[]) {
    if (!this.socketPath) throw new Error("guest harness does not have a Unix socket");
    return spawnSync(helperPath, args, {
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", BLOOM_GUEST_CONTROL_SOCKET: this.socketPath },
    });
  }

  async provisionWatchWallet(address: string) {
    const directory = join(this.root, ".bloom/keystore/workspace-login");
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, "kind"), "watch\n");
    await writeFile(join(directory, "address"), `${address}\n`);
    await writeFile(join(directory, "pubkey"), "");
  }

  async request(fields: RequestFields) {
    const id = `test_${++this.sequence}`;
    const response = new Promise<ReturnType<typeof GuestResponse.parse>>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`guest request timed out; stderr=${this.stderr}`)), 10_000);
      this.pending.push((value) => { clearTimeout(timer); resolve(value); });
    });
    this.child.stdin.write(`${JSON.stringify({ version: 1, id, ...fields })}\n`);
    return response;
  }

  async waitForTerminal(jobId: string) {
    for (let attempt = 0; attempt < 300; attempt++) {
      const response = await this.request({ operation: "job.status", jobId, logOffset: 0, maxBytes: 256 * 1024 });
      if (!response.ok) throw new Error(response.error.message);
      const status = response.result as SuccessResponse["result"] & { state: string };
      if (["succeeded", "failed", "cancelled", "timed_out"].includes(status.state)) return status as JobStatusResult;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error("job did not reach a terminal state");
  }

  async waitForLog(jobId: string) {
    for (let attempt = 0; attempt < 300; attempt++) {
      const response = await this.request({ operation: "job.status", jobId, logOffset: 0, maxBytes: 256 * 1024 });
      if (!response.ok) throw new Error(response.error.message);
      const status = response.result as JobStatusResult;
      if (status.logs.endOffset > 0) return status;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error("job did not produce output");
  }

  async close() {
    if (this.child.exitCode !== null) {
      await rm(this.root, { recursive: true, force: true });
      return;
    }
    if (this.socketPath) this.child.kill("SIGTERM");
    else this.child.stdin.end();
    await Promise.race([
      new Promise<void>((resolve) => this.child.once("exit", () => resolve())),
      new Promise<void>((resolve) => setTimeout(() => { this.child.kill("SIGKILL"); resolve(); }, 2000)),
    ]);
    await rm(this.root, { recursive: true, force: true });
  }
}

type JobStatusResult = {
  state: string;
  exitCode: number | null;
  logs: { offset: number; nextOffset: number; endOffset: number; truncatedBefore: boolean; data: string };
};

function processExists(pid: number) {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code !== "ESRCH"; }
}

async function eventually(predicate: () => boolean | Promise<boolean>) {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("condition was not reached");
}
