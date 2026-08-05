import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  decodeGuestFrames,
  encodeGuestFrame,
  GuestRequest,
  isSafeWorkspacePath,
  MAX_FILE_CHUNK_BYTES,
} from "./guest-protocol.js";

const envelope = { version: 1 as const, id: "request_1" };

describe("guest control protocol", () => {
  it("accepts rooted relative paths and rejects traversal and ambiguous separators", () => {
    expect(isSafeWorkspacePath("src/index.ts")).toBe(true);
    for (const path of ["/etc/passwd", "../secret", "src/../../secret", "src//index.ts", "src\\index.ts", ".", "dir/"]) {
      expect(isSafeWorkspacePath(path), path).toBe(false);
    }
  });

  it("uses dot only as the workspace-root sentinel for directory operations", () => {
    expect(GuestRequest.safeParse({ ...envelope, operation: "fs.list", path: "." }).success).toBe(true);
    expect(GuestRequest.safeParse({ ...envelope, operation: "job.start", jobId: randomUUID(), argv: ["pwd"], cwd: ".", environment: {}, timeoutMs: 1_000 }).success).toBe(true);
    expect(GuestRequest.safeParse({ ...envelope, operation: "fs.read", path: ".", offset: 0, maxBytes: 1 }).success).toBe(false);
  });

  it("bounds file chunks after base64 decoding", () => {
    expect(GuestRequest.safeParse({ ...envelope, operation: "fs.write", path: "large.bin", offset: 0, truncate: true, data: Buffer.alloc(MAX_FILE_CHUNK_BYTES).toString("base64") }).success).toBe(true);
    expect(GuestRequest.safeParse({ ...envelope, operation: "fs.write", path: "large.bin", offset: 0, truncate: true, data: Buffer.alloc(MAX_FILE_CHUNK_BYTES + 1).toString("base64") }).success).toBe(false);
    expect(GuestRequest.safeParse({ ...envelope, operation: "fs.write", path: "bad.bin", offset: 0, truncate: true, data: "!!!!" }).success).toBe(false);
  });

  it("models jobs as argv and a bounded environment rather than a shell string", () => {
    const valid = GuestRequest.parse({
      ...envelope,
      operation: "job.start",
      jobId: randomUUID(),
      argv: ["npm", "test", "--", "a; touch /tmp/not-shell"],
      cwd: "project",
      environment: { CI: "1" },
      timeoutMs: 60_000,
    });
    expect(valid.operation).toBe("job.start");
    expect(GuestRequest.safeParse({ ...valid, argv: [] }).success).toBe(false);
    expect(GuestRequest.safeParse({ ...valid, environment: { "BAD-NAME": "1" } }).success).toBe(false);
  });

  it("accepts only a public Ed25519 CA for guest connection setup", () => {
    const request = { ...envelope, operation: "connections.configure", workspaceId: randomUUID(), wallet: "0x1111111111111111111111111111111111111111", caPublicKey: `ssh-ed25519 ${Buffer.alloc(32, 7).toString("base64")}`, nfs: false };
    expect(GuestRequest.safeParse(request).success).toBe(true);
    expect(GuestRequest.safeParse({ ...request, caPublicKey: "-----BEGIN OPENSSH PRIVATE KEY-----" }).success).toBe(false);
  });

  it("frames partial and multiple responses without unbounded buffering", () => {
    const first = encodeGuestFrame({ ...envelope, operation: "hello" });
    const second = encodeGuestFrame({ ...envelope, id: "request_2", operation: "bloom.status" });
    const split = first.byteLength - 2;
    const partial = decodeGuestFrames(first.subarray(0, split));
    expect(partial.frames).toEqual([]);
    const completed = decodeGuestFrames(Buffer.concat([partial.remainder, first.subarray(split), second]));
    expect(completed.frames).toHaveLength(2);
    expect(completed.remainder.byteLength).toBe(0);
  });
});
