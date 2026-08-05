import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { GuestRequest } from "../guest-protocol.js";
import { BloomGuestStatus } from "../guest/results.js";
import { GuestJobs } from "../jobs/client.js";
import { decodeJobLog, isAllowlistedJobEnvironmentName, isValidJobTransition, JobStatus, StructuredJobSpec } from "../jobs/model.js";

describe("structured job control model", () => {
  it("accepts structured argv while rejecting path, loader, proxy, and oversized inputs", () => {
    expect(StructuredJobSpec.parse({ argv: ["sh", "-c", "printf '%s' literal"], cwd: "src", environment: { APP_MODE: "test" }, timeoutMs: 1000 }))
      .toMatchObject({ argv: ["sh", "-c", "printf '%s' literal"], cwd: "src" });
    expect(StructuredJobSpec.parse({ argv: ["pwd"], cwd: ".", environment: {}, timeoutMs: 1000 })).toMatchObject({ cwd: "." });
    expect(StructuredJobSpec.safeParse({ argv: ["true"], cwd: "../escape", environment: {}, timeoutMs: 1000 }).success).toBe(false);
    expect(StructuredJobSpec.safeParse({ argv: ["true"], cwd: "src", environment: { LD_PRELOAD: "evil" }, timeoutMs: 1000 }).success).toBe(false);
    expect(StructuredJobSpec.safeParse({ argv: ["true"], cwd: "src", environment: { HTTPS_PROXY: "http://evil" }, timeoutMs: 1000 }).success).toBe(false);
    expect(StructuredJobSpec.safeParse({ argv: ["true"], cwd: "src", environment: { APP_DATA: "x".repeat(8193) }, timeoutMs: 1000 }).success).toBe(false);
    expect(isAllowlistedJobEnvironmentName("JOB_TOKEN")).toBe(true);
    expect(isAllowlistedJobEnvironmentName("BLOOM_AGENT_TOKEN")).toBe(false);
  });

  it("defines an irreversible terminal state machine", () => {
    expect(isValidJobTransition("queued", "running")).toBe(true);
    expect(isValidJobTransition("running", "timed_out")).toBe(true);
    expect(isValidJobTransition("cancelled", "running")).toBe(false);
    expect(isValidJobTransition("succeeded", "failed")).toBe(false);
  });

  it("emits only guest protocol requests and validates bounded log replies", async () => {
    const jobId = randomUUID();
    const calls: GuestRequest[] = [];
    const call = vi.fn(async (request: GuestRequest) => {
      calls.push(request);
      return validStatus(jobId, request.operation === "job.start" ? "running" : request.operation === "job.cancel" ? "cancelled" : "succeeded");
    });
    const jobs = new GuestJobs(call);
    await jobs.start({ argv: ["node", "script.js"], cwd: "src", environment: { NODE_ENV: "test" }, timeoutMs: 5000 }, jobId);
    await jobs.status(jobId, 0, 1024);
    await jobs.cancel(jobId);
    expect(calls.map((request) => request.operation)).toEqual(["job.start", "job.status", "job.cancel"]);
    expect(calls[0]).toMatchObject({ jobId, argv: ["node", "script.js"], cwd: "src", environment: { NODE_ENV: "test" } });
    expect(decodeJobLog(JobStatus.parse(validStatus(jobId, "succeeded")).logs).toString()).toBe("ok\n");
  });

  it("makes watch-only Bloom limitations machine-readable", () => {
    expect(BloomGuestStatus.parse({
      available: true,
      mount: { path: "/bloom", mounted: true },
      identity: { kind: "watch", address: "0x1111111111111111111111111111111111111111" },
      capabilities: { files: true, jobs: true, bloomRead: true, walletSigning: false, transactions: false },
      helper: { name: "bloom-workspace", protocolVersion: 1 },
    })).toMatchObject({ capabilities: { walletSigning: false, transactions: false } });
    expect(BloomGuestStatus.safeParse({
      available: true,
      mount: { path: "/bloom", mounted: false },
      identity: null,
      capabilities: { files: true, jobs: true, bloomRead: true, walletSigning: false, transactions: false },
      helper: { name: "bloom-workspace", protocolVersion: 1 },
    }).success).toBe(false);
  });
});

function validStatus(jobId: string, state: "running" | "succeeded" | "cancelled") {
  const terminal = state !== "running";
  return {
    jobId,
    state,
    createdAt: 1,
    startedAt: 2,
    finishedAt: terminal ? 3 : null,
    exitCode: state === "succeeded" ? 0 : null,
    signal: state === "cancelled" ? 15 : null,
    timeoutMs: 5000,
    logs: {
      offset: 0,
      nextOffset: 3,
      endOffset: 3,
      truncatedBefore: false,
      eof: terminal,
      encoding: "base64",
      data: Buffer.from("ok\n").toString("base64"),
    },
  } as const;
}
