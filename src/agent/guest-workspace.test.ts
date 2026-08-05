import { describe, expect, it, vi } from "vitest";
import type { GuestRequest } from "../guest-protocol.js";
import { waitForGuestControl } from "./guest-ready.js";
import { GuestWorkspace } from "./guest-workspace.js";

describe("VM guest workspace adapter", () => {
  it("assembles bounded reads and preserves the root directory sentinel", async () => {
    const contents = Buffer.alloc(600_000, 0x42);
    const call = vi.fn(async (request: GuestRequest) => {
      if (request.operation === "fs.list") return { files: [{ path: "large.bin", type: "file", size: contents.length, modifiedAt: 1 }] };
      if (request.operation !== "fs.read") throw new Error("unexpected operation");
      const chunk = contents.subarray(request.offset, request.offset + request.maxBytes);
      return { path: request.path, offset: request.offset, nextOffset: request.offset + chunk.length, size: contents.length, eof: request.offset + chunk.length === contents.length, data: chunk.toString("base64") };
    });
    const workspace = new GuestWorkspace(call);
    await expect(workspace.list(".")).resolves.toMatchObject([{ path: "large.bin" }]);
    await expect(workspace.read("large.bin")).resolves.toEqual(contents);
    expect(call.mock.calls.filter(([request]) => request.operation === "fs.read")).toHaveLength(3);
  });

  it("splits uploads without shell or path reinterpretation and returns quota accounting", async () => {
    const received: Buffer[] = [];
    const call = vi.fn(async (request: GuestRequest) => {
      if (request.operation === "fs.write") {
        const chunk = Buffer.from(request.data, "base64");
        received.push(chunk);
        const nextOffset = request.offset + chunk.length;
        return { path: request.path, size: nextOffset, nextOffset, usedBytes: nextOffset, quotaBytes: 128 * 1024 * 1024 };
      }
      if (request.operation === "fs.delete") return { path: request.path, deleted: true, usedBytes: 0, quotaBytes: 128 * 1024 * 1024 };
      throw new Error("unexpected operation");
    });
    const contents = Buffer.alloc(600_000, 0x24);
    const workspace = new GuestWorkspace(call);
    await expect(workspace.write("literal;name", contents)).resolves.toMatchObject({ size: contents.length, usedBytes: contents.length });
    expect(Buffer.concat(received)).toEqual(contents);
    expect(call.mock.calls.filter(([request]) => request.operation === "fs.write")).toHaveLength(3);
    await expect(workspace.delete("literal;name")).resolves.toMatchObject({ usedBytes: 0 });
  });

  it("rejects inconsistent guest framing", async () => {
    const workspace = new GuestWorkspace(async () => ({ path: "file", offset: 0, nextOffset: 2, size: 1, eof: true, data: "YQ==" }));
    await expect(workspace.read("file")).rejects.toMatchObject({ status: 501 });
  });
});

describe("guest readiness", () => {
  it("waits for a complete protocol-v1 operation set", async () => {
    let attempts = 0;
    const result = await waitForGuestControl(async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("booting");
      return { protocolVersion: 1, operations: ["fs.list", "fs.read", "fs.write", "fs.delete", "job.start", "job.status", "job.cancel", "bloom.status", "connections.configure"] };
    }, 2_000);
    expect(result.protocolVersion).toBe(1);
    expect(attempts).toBe(2);
  });
});
